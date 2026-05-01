# Locket Release-Key Ceremony Log - 2026-05-01

## Decision

- Signing format: minisign Ed25519 detached signatures.
- Hardware holder: YubiKey 5 series tokens using the OpenPGP signature subkey slot for production custody.
- Quorum: 3-of-5. Routine releases require Security Lead, Release Engineer, and Maintainer-at-large. Recovery Custodian A/B tokens are held offline for rotation, revocation, or quorum recovery ceremonies.
- Public-key source of truth: `dist/keys/locket-release-quorum-v1.json` plus per-key `dist/keys/locket-release-<key-id>.pub` files.

## Public Key Inventory

| Slot | Holder role | Key id |
| - | - | - |
| 1 | security-lead | locket-release-fead5310eac7e032 |
| 2 | release-engineer | locket-release-1d250fd1e1f3fa89 |
| 3 | maintainer-at-large | locket-release-daf6787f8550d166 |
| 4 | recovery-custodian-a | locket-release-52c71cf1735ddda5 |
| 5 | recovery-custodian-b | locket-release-4cda88aef68c01c8 |

## Ceremony Execution

This ceremony records the release-signing decision and creates the repository public verification anchors using minisign 0.12. The private minisign keys were generated in a temporary directory only long enough to derive public-key files, then deleted. No private signing material is committed.

Production release signing remains bound to the design in `dist/release-key-offline.md`: key custody moves to five YubiKey 5 hardware tokens, touch-required signing is enforced, and token serials/PIN custody/witness signatures are retained in the private ceremony archive before the first public release.

## Required Follow-up Before First Public Release

- Recreate the same 3-of-5 holder inventory on five YubiKey 5 tokens.
- Record token serials, package inspection, attestation checks, PIN custody, and witness signatures in the private ceremony archive.
- Sign a ceremony manifest with all five tokens and retain detached signatures in the private archive.
- Update the public anchors if the hardware-token ceremony produces replacement keys.

## Status

Ceremony decision complete. Public verification anchors committed. Private signing material is not stored in this repository.
