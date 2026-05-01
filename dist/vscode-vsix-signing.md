# Signed VSIX Direct-Download Distribution

This document describes how Locket distributes its VS Code extension as a
**signed VSIX direct download**, why that path exists alongside (or instead of)
a Marketplace listing, and the operational signing flow.

The companion offline release-key infrastructure is documented in
[`release-key-offline.md`](./release-key-offline.md). The same offline key —
or a sibling key in the same ceremony — is used to sign VSIX artifacts.

## 1. Marketplace VSIX vs. directly-downloaded VSIX

VS Code can install extensions from two sources:

1. **Visual Studio Marketplace.** `vsce publish` pushes a VSIX to the
   Marketplace. VS Code clients trust the Marketplace transport and the
   publisher identity declared in `package.json` (`publisher: "locket"`).
   Microsoft's Marketplace re-signs / counter-signs the artifact for clients
   that enforce the new VSIX signature scheme.

2. **Direct download VSIX (`code --install-extension locket-<version>.vsix`).**
   The same `vsce package` output, distributed from `releases.locket.dev` or a
   GitHub Release. There is no Marketplace counter-signature, so the trust
   anchor must be provided by Locket's own offline release key.

Locket's primary distribution path per `docs/specs/operations.md:53` is the
**signed direct-download VSIX**. The Marketplace listing is *optional* and may
be added later for discovery, but the canonical install path does not depend
on it.

## 2. Why a signed direct download matters

Many target deployments — regulated enterprises, government, air-gapped or
firewalled networks, secrets-management workflows — cannot or will not reach
the VS Code Marketplace:

- Outbound traffic to `marketplace.visualstudio.com` is blocked by policy.
- Internal mirrors only accept artifacts whose publisher signature can be
  verified against an offline-pinned key.
- Some orgs forbid arbitrary Marketplace extensions and only allow VSIX files
  on a vetted allow-list.
- Extensions handling secrets must offer a verifiable supply chain
  independent of any third-party redistribution layer.

A directly-downloaded VSIX without a verifiable signature is a trust hole.
Locket signs every released VSIX and publishes the verification key alongside
the agent binary signature material so a single offline release-key trust
anchor covers the agent, the desktop app, and the editor extension.

## 3. Signing flow

### Who signs

Releases are signed by a designated **release signer** during the offline
signing ceremony described in [`release-key-offline.md`](./release-key-offline.md).
CI never has access to the signing key. The release signer runs the ceremony
on the air-gapped signing host using the YubiKey-resident Ed25519 key.

### Key storage

- Signing key: Ed25519 private key resident on a hardware token (YubiKey 5
  series, OpenPGP slot or PIV slot). The private key never leaves the token.
- Public key: pinned in the agent binary, published at
  `https://releases.locket.dev/keys/locket-release-<key-id>.pub`, and committed
  to this repository as `dist/keys/locket-release-<key-id>.pub` once the
  ceremony is complete.

### Ceremony

1. CI (on an isolated runner — see `release-ci-runners.md`) builds an
   *unsigned* VSIX with `scripts/package-vscode-extension.sh` and publishes it
   plus its SHA-256 to a staging bucket. The unsigned artifact filename is
   `locket-<version>.vsix`.
2. The release signer fetches the unsigned VSIX and its digest onto the
   air-gapped signing host via one-way media (USB, write-once optical).
3. The signer recomputes the SHA-256 and confirms it matches the digest
   published by CI before any signing operation.
4. The signer runs:

   ```
   scripts/package-vscode-extension.sh --sign <key-id>
   ```

   on a re-built tree, *or* signs the staged VSIX in place by invoking the
   same hook script the package step would invoke
   (`tools/vsix-sign.sh <input-vsix> <output-vsix> <key-id>`). The script
   produces `locket-<version>.signed.vsix` plus a detached
   `locket-<version>.signed.vsix.sig` file.
5. The signed artifact and signature travel back over one-way media to the
   release machine, which uploads both alongside the SHA-256 to the public
   release location.

### Verification

Downstream verification is documented in
[`release-key-offline.md`](./release-key-offline.md#verification). For VSIX
specifically, the recommended user-facing check is:

```
minisign -V -p locket-release-<key-id>.pub \
         -m locket-<version>.signed.vsix
```

The agent binary additionally verifies VSIX signatures internally when the
desktop app installs the extension on the user's behalf.

## 4. `--sign` flag in `scripts/package-vscode-extension.sh`

`scripts/package-vscode-extension.sh` supports an optional `--sign <key-id>`
flag:

| Mode      | Output filename                         | Signature file                              |
|-----------|------------------------------------------|---------------------------------------------|
| unsigned  | `locket-<version>.vsix`                  | none                                        |
| `--sign`  | `locket-<version>.signed.vsix`           | `locket-<version>.signed.vsix.sig` (detached) |

When `--sign` is passed, the script runs the standard `vsce package` step into
a temporary path, then invokes `tools/vsix-sign.sh` (a thin wrapper around the
ceremony's signing tool — minisign by default, see `release-key-offline.md`).
The signing tool may also call `vsce`'s built-in signature insertion when
distributing through the Marketplace path; the direct-download path uses the
detached `.sig` file.

When `--sign` is omitted the script behaves exactly as before: it produces an
unsigned `locket-<version>.vsix` plus its `.sha256` digest and exits.

## 5. Operational notes

- The signing host has no network and no shell history that survives a
  ceremony.
- `tools/vsix-sign.sh` is intentionally not committed yet; it is provisioned
  on the signing host during the ceremony described in `release-key-offline.md`.
  CI must never invoke it.
- When the release key rotates, both the old and new keys sign the next VSIX
  release so clients pinned to either key continue to verify successfully
  (mirrors the dual-signed update-manifest rotation policy from
  `docs/specs/operations.md:51`).
