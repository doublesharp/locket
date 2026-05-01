# Offline Release-Key Infrastructure (Design)

This document is the design plan for Locket's offline release-signing
infrastructure. It defines what the key signs, where it lives, who handles
it, and how downstream verifies. It does **not** ship key material. Key
generation and the first ceremony will be tracked separately once this design
is ratified.

The release key signs:

- Update manifests (`docs/specs/operations.md:51`).
- Public release artifacts: agent binaries, desktop app installers, VSIX
  ([`vscode-vsix-signing.md`](./vscode-vsix-signing.md)), and any future
  installer formats.
- Provenance attestations that downstream verifiers consume alongside SLSA
  build provenance from CI.

## Recommendation

**Use minisign-format Ed25519 release keys held on YubiKey 5 series tokens
(OpenPGP application, signature subkey), with M-of-N quorum at the
ceremony.** Justification: minisign signatures are tiny, non-controversial,
require no third-party transparency log, are trivially verifiable in air-gapped
or firewalled environments, and the Ed25519 key can live on a
hardware-attested token whose private half never leaves the device. Sigstore
keyless was considered and rejected: it depends on Fulcio + Rekor uptime and
on per-signer OIDC identity (a non-starter for environments that block
`fulcio.sigstore.dev`), and Locket's threat model already requires offline,
out-of-band key trust (`docs/specs/operations.md:51`).

The remainder of this document treats minisign-on-YubiKey as the chosen stack.

## 1. Threat model

The release key exists to defend against:

- **Compromised CI runner.** A poisoned hosted runner (or a compromised
  self-hosted runner reused across PRs and releases) injects malicious
  artifacts. CI never holds signing material; signatures are produced
  out-of-band on hardware the attacker cannot reach.
- **Supply-chain injection in the build pipeline.** A malicious dependency or
  build-step substitution swaps in a tampered binary before signing. The
  ceremony's SHA-256 reproduction step on the air-gapped host catches
  divergence between what CI built and what is being signed.
- **Repository or maintainer-account takeover.** An attacker with `git push`
  access cannot mint a valid release because the signing key is offline and
  guarded by hardware PIN + ceremony quorum.
- **Stolen laptop / lost token.** Any single hardware token can be revoked
  and replaced via the rotation path below; M-of-N quorum prevents any one
  token from minting a release on its own.
- **Coercion or insider threat.** Quorum + ceremony logs make a unilateral
  rogue release detectable after the fact even if not preventable in the
  moment.

Out of scope: cryptanalytic attacks on Ed25519, hardware-token firmware
exploits requiring physical possession, and end-user systems that disable
signature verification.

## 2. Key storage

- **Tokens.** YubiKey 5 series (5C NFC or 5 NFC). The OpenPGP application's
  signature subkey holds an Ed25519 private key generated on-token. Touch is
  required for every signing operation.
- **PIN.** 8+ digits, set during key generation, never written down. PIN
  retry counter set to 3; PUK held by a separate role.
- **Air-gapped signing host.** A laptop with the radios physically removed
  (or a Tails USB stick used only for ceremonies). It runs minisign +
  `gpg --card-edit` (for OpenPGP-on-card flows) and nothing else. No network
  hardware enabled.
- **Public-key distribution.** Verification keys are pinned in the agent
  binary, committed to `dist/keys/locket-release-<key-id>.pub` after each
  ceremony, and mirrored to `https://releases.locket.dev/keys/`. Pinning is
  the ground truth; the URL is a convenience mirror.
- **Backup.** Each subkey is generated on-token (not extractable), so there
  is **no private-key backup**. Recovery from loss is via rotation. The
  public key, fingerprint, and ceremony logs are stored in the company
  password vault and on paper in two physical safes.

## 3. Key-generation ceremony

- **Quorum.** 3-of-5 quorum: five tokens are generated at the ceremony, three
  are required to sign any future release. The fourth and fifth are held in
  geographically separated safes as recovery tokens.
- **Attendees.** Minimum three role-holders (see Roles below) present
  in-person; one independent witness who is not a role-holder; one notarised
  observer for the first ceremony only.
- **Hardware verification.** Each YubiKey is checked against
  `ykman info --check-fips` and the Yubico attestation chain. Tokens are
  unboxed in front of the witness; tamper-evident packaging is photographed
  before opening.
- **Generation steps.**
  1. Boot the air-gapped host from verified read-only media; confirm
     `ip link` shows no enabled interfaces.
  2. For each token: generate the Ed25519 subkey on-card
     (`gpg --card-edit` → `admin` → `key-attr` → `generate`). Set PIN, Admin
     PIN, and force-touch policy. Export and record the public key
     fingerprint.
  3. Convert each OpenPGP public key to minisign format using a deterministic
     conversion documented in `tools/openpgp-to-minisign.md` (committed
     separately).
  4. Sign a "ceremony manifest" document (containing date, attendees,
     fingerprints, hardware serials) with all five tokens to prove they all
     work end-to-end before leaving the room.
- **Log retention.** Ceremony manifest is signed, photographed, printed, and
  stored in two safes. Digital copies are committed to a private archival
  repository accessible only to the security lead.

## 4. Signing flow (CI → offline signer → release)

1. CI on an isolated runner (see [`release-ci-runners.md`](./release-ci-runners.md))
   builds the artifact, computes its SHA-256, and uploads the artifact and
   digest to a staging bucket. CI also uploads the SLSA provenance JSON
   produced for the build.
2. The release signer fetches the artifact, digest, and provenance via
   one-way media (USB written from a connected machine, mounted read-only on
   the air-gapped host).
3. The signer recomputes the SHA-256 on the air-gapped host and confirms it
   matches CI's digest. They run
   `scripts/slsa-provenance-policy.pl --require-signature --require-build-l3`
   on the provenance to validate builder identity and source repo before
   signing anything.
4. The signer collects 3-of-5 token signatures using minisign (each signer
   provides a touch + PIN). The output is a single concatenated minisign
   signature file plus per-token detached signatures for audit.
5. Signed artifact + signatures + ceremony log are written back to one-way
   media and carried to the release machine, which uploads them and
   publishes the release.

## 5. Verification

Downstream clients verify in this order:

1. **Pinned-key check.** The agent binary contains the active release public
   keys. `minisign -V -p <pinned-pub> -m <artifact>` succeeds for at least
   one pinned key.
2. **Quorum check.** For artifacts requiring quorum (update manifests,
   binary releases), the verifier confirms ≥3 distinct token signatures over
   the same payload. The agent's verification helper enforces this.
3. **Provenance check.** SLSA provenance is verified with
   `scripts/slsa-provenance-policy.pl` against pinned builder identity and
   workflow.
4. **Digest check.** Published `*.sha256` matches the artifact bytes.

The user-facing verification command is `locket verify <artifact>` which
wraps minisign + provenance + digest in one step.

## 6. Key rotation

- **Routine rotation.** Every 24 months, or sooner if a token is suspected
  compromised. Each rotation is a fresh ceremony; the new public keys are
  added to the pinned set in the next agent release.
- **Dual-signed handover.** During a rotation window, the next release is
  signed by both the old quorum (3-of-old-5) and the new quorum
  (3-of-new-5), so clients pinned to either key set verify successfully.
  Mirrors the manifest-rotation policy in `docs/specs/operations.md:51`.
- **Revocation path.** A compromised token is revoked by:
  1. Publishing a minisign-signed revocation statement (signed by the
     remaining quorum) to `https://releases.locket.dev/revocations/`.
  2. Shipping an agent update that drops the revoked public key from the
     pinned set and refuses signatures from it.
  3. Physically destroying the revoked token if recoverable, or marking the
     serial as revoked in the ceremony archive if not.
- **Quorum reduction.** Falling below 3 active tokens (e.g., two losses)
  triggers an emergency ceremony to regenerate the missing tokens before
  any further releases.

## 7. Roles

- **Security lead.** Owns the ceremony archive, holds one signing token,
  signs ceremony logs, gates rotation timing.
- **Release engineer.** Owns CI release pipeline, holds one signing token,
  drives the per-release signing flow.
- **Maintainer-at-large (rotating).** Holds one signing token; rotates among
  designated senior maintainers each quarter.
- **Recovery custodian (×2).** Each holds one of the two recovery tokens in
  geographically separated safes. Recovery custodians never sign routine
  releases; their tokens come out only during rotation or revocation
  ceremonies.
- **Independent witness.** Not a role-holder; signs ceremony logs as a
  third-party attestation that the ceremony followed this document.

Each role's identity, contact info, and token serial number are recorded in
the ceremony archive (private). Public release notes never identify which
specific token signed a release, only that quorum was met.
