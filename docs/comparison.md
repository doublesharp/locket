# Locket vs Alternatives

Honest comparison of dev secrets managers as of 2026-04-30. Numbers verified against vendor pricing pages and recent third-party analysis. We update this doc whenever competitors change pricing or shipping behavior.

If you find an inaccuracy, [open an issue](https://github.com/) — we'll fix it.

## Pricing matrix

Per seat per month, billed annually, unless noted.

| Product | Free tier | Team tier | Enterprise | Self-host? |
| --- | --- | --- | --- | --- |
| **Locket** | Solo CLI free, MIT | **$7/seat** (planned) | Custom | **N/A — no server exists** |
| Doppler | 3 users (then $8) | $21/user | ~$50/user, $30K+ contracts | No (deliberate) |
| Infisical | 5 identities, 3 projects | $18/identity (incl. service accts) | Custom | Yes (SSO paywalled) |
| Bitwarden Secrets Manager | 2 users only | $6/user + $1/extra machine acct | $12/user | Yes (server required) |
| 1Password Secrets Automation | None | $7.99/user (Business) | Custom | Connect server caches only |
| HCP Vault Secrets | Discontinued (EOL July 2026) | n/a | Six figures | Yes (BUSL since 2023) |
| dotenvx Ops | Local CLI free | $20/mo flat for 3 (~$6.67/seat) | Custom | No (cloud only) |
| SOPS | Free | — | — | N/A (just files) |
| pass / gopass | Free | — | — | N/A (git + GPG) |

## Architecture matrix

| Product | Server required | Offline mode | Zero-knowledge | P2P sync | Local SQLite vault |
| --- | --- | --- | --- | --- | --- |
| **Locket** | **No** | **Yes** | **Yes** | **Yes (sealed bundles)** | **Yes** |
| Doppler | Yes (cloud only) | No | No | No | No |
| Infisical | Yes (cloud or self-host) | Cache only | Conditional¹ | No | No |
| Bitwarden SM | Yes (cloud or self-host) | Cache only | Yes | No | No |
| 1Password | Yes (1password.com) | Desktop only, not `op` CLI | Yes | No | Encrypted cache |
| Vault | Yes (HA cluster) | No | No | No | No |
| dotenvx | No (file-based) | Yes | Yes (ECIES) | Manual key swap | No (`.env` files) |
| SOPS | No (file-based) | Yes | Yes (KMS/age) | Git + KMS | No (YAML/JSON) |
| pass / gopass | No (git + GPG) | Yes | Yes | Manual git | No |

¹ Infisical's zero-knowledge weakens when you opt into rotation or dynamic secrets — those features need server-side plaintext access.

## Feature gating — what teams actually pay competitors for

| Feature | Doppler | Infisical | Bitwarden SM | 1Password | dotenvx Ops | **Locket (planned)** |
| --- | --- | --- | --- | --- | --- | --- |
| SAML SSO | Team ($21) | Pro ($18) | Enterprise ($12) | Business ($8) | Custom | **Org tier** |
| SCIM | Enterprise | Enterprise | Enterprise | Enterprise | — | Org tier |
| Audit log retention | 3d → 90d | 90d (Pro) | Yes | Business | — | **All paid tiers** |
| Approval workflows | Team | Enterprise | — | Business | — | Org tier |
| Secret rotation | Team | Pro | — | Manual | — | Roadmap |
| Dynamic secrets | Enterprise | Enterprise | — | No | — | Out of scope (use Vault) |
| RBAC | Team | Pro | Teams | Business | — | Team tier |
| K8s operator | All tiers | All tiers | All tiers | All tiers | — | Out of scope |
| Service accounts | Free | Counted as identities | $1 each over limit | 100 free | — | **Free, uncounted** |
| AI prompt redaction | No | No | No | No | No | **Free in CLI** |
| P2P team sync | No | No | No | No | No | **All paid tiers** |

## Where each competitor wins (and where they don't)

### Doppler
**Wins for:** teams that want zero infrastructure and will swipe a card. Polished DX, strong integrations.
**Loses for:** teams that won't put production-adjacent secrets in someone else's cloud, teams priced out at $21/seat, teams wanting any self-host or zero-knowledge story. Closed-source platform, no self-host option ever — this is a deliberate company stance.

### Infisical
**Wins for:** mid-market teams ready to operate Postgres + Redis + their app, or to pay for cloud. Generous OSS feature surface (MIT for the main repo).
**Loses for:** teams that don't want to run Postgres + Redis + a frontend, teams burned by SSO-paywalled-on-self-hosted (the loudest community complaint), teams whose service-account-heavy CI inflates their per-identity bill.

### Bitwarden Secrets Manager
**Wins for:** orgs already on Bitwarden Password Manager. Same vendor, same UI patterns, true zero-knowledge.
**Loses for:** teams that don't want to run a server (still required for self-host), teams hit by the 2-user free cap, CI-heavy teams paying $1/machine-account over the included quota.

### 1Password Secrets Automation
**Wins for:** orgs already paying for 1Password Business. One bill, decent dev features (`op run`, service accounts, Connect server).
**Loses for:** teams needing offline CLI (`op` requires connectivity — long-standing complaint), teams with multi-environment dev/stage/prod workflows (the data model is items-with-fields, fits passwords better), teams wanting purpose-built dev secrets instead of a layer on a password manager.

### HashiCorp Vault
**Wins for:** enterprise infrastructure and platform teams running production secret management.
**Loses for:** anyone in the 2-20 person dev segment. Not a comparable. HCP Vault Secrets (the small-team SaaS option) was sunset July 2026. Self-hosted Vault HA cluster is itself a full-time operations job. Per-client pricing on HCP makes small CI fleets expensive. IBM acquired HashiCorp in February 2025; community engagement has slowed. The OpenBao fork is also server-architected.

### dotenvx
**Wins for:** solo devs and tiny teams who want encrypted `.env` files in git with minimal change.
**Loses for:** teams beyond manual key exchange. The official upgrade path for teams is Dotenvx Ops — which is cloud-only. They have explicitly vacated the local-first team segment.

### SOPS
**Wins for:** ops teams encrypting YAML/JSON for k8s and CI, with KMS or age backends.
**Loses for:** dev laptops. CLI-only, no UI, no audit log, no team UX, no built-in P2P. Designed for ops, not for daily dev work.

### pass / gopass
**Wins for:** individual unix devs who already love GPG.
**Loses for:** teams. GPG key distribution and rotation is the worst UX in computing. No re-encryption when a member leaves. No audit log. Conflict resolution is `git merge` in your terminal. `pass` itself is effectively frozen (last release 2021). `gopass` is maintained but slow.

## Where Locket wins

Locket is the only product in this comparison that combines **all four** of:

1. No server to run.
2. True offline operation.
3. Zero-knowledge encryption.
4. Peer-to-peer team sync.

Plus a feature no one else ships: **AI prompt redaction matched against your actual secrets, not regex patterns** (`locket scan --require-known`, `locket ai-safe`, `locket redact`).

## Where Locket loses

Be honest with yourself before you choose Locket:

- **Need SAML SSO today?** Use Infisical or 1Password Business. We'll have it in the Org tier, but it's not shipped.
- **Need SCIM, SOC2 reports, dedicated support, or a procurement-friendly MSA?** Doppler or Infisical Enterprise. We're targeting SOC2 Type 1 around month 18-24.
- **Need dynamic secrets / DB credential rotation / cloud KMS integration?** Use Vault or Infisical Enterprise. Out of scope for Locket.
- **Need 50+ off-the-shelf integrations (AWS, Vercel, Terraform, etc.)?** Doppler. We'll have a few; not all.
- **Want a hosted UI someone else operates?** By design, that's not us. Try Doppler or Infisical Cloud.

We'd rather you use the right tool than oversell ours.

## How to choose

```
Are you a dev team of 2-20?
├─ No, you're solo → Locket free CLI is for you.
└─ Yes:
   Do you need SSO/SCIM/SOC2 today?
   ├─ Yes → Infisical or 1Password Business.
   └─ No:
      Are you OK trusting a SaaS with your secrets?
      ├─ Yes, and you want polish → Doppler.
      └─ No:
         Will you run Postgres + Redis + an app server?
         ├─ Yes, and you want full features → Self-hosted Infisical.
         └─ No → Locket.
```

The terminal node "No" + "No" + "No" is the segment Locket exists to serve. If that's you, [get started](../README.md#quick-start).

## Sources

Pricing and feature data verified against:

- [Doppler pricing](https://www.doppler.com/pricing)
- [Infisical pricing](https://infisical.com/pricing)
- [Bitwarden Secrets Manager Plans](https://bitwarden.com/help/secrets-manager-plans/)
- [1Password Developer pricing](https://1password.com/pricing/password-manager)
- [HashiCorp Vault pricing](https://www.hashicorp.com/products/vault/pricing)
- [dotenvx pricing](https://dotenvx.com/pricing)
- [SOPS GitHub](https://github.com/getsops/sops)
- [pass](https://www.passwordstore.org/) / [gopass](https://www.gopass.pw/)

Last verified: 2026-04-30. Tell us if anything is stale.
