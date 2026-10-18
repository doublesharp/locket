# Choosing Locket

Locket is being built for developers who want development variables encrypted on their own machines, explicit command access, and offline local execution. Its case should rest on that workflow being easy and reliable.

## Compare the workflow

| Question | Current Locket behavior |
| --- | --- |
| Where do values live? | An encrypted local SQLite vault; shareable project metadata stays in locket.toml. |
| How does an application receive values? | A saved command declares permitted names; Locket injects values into that process. |
| Does routine execution require a hosted service? | No. Local keys, project configuration, and values must be available. |
| How are teammates updated? | Explicit encrypted export/import. This is not automatic synchronization. |
| What is shared by default? | Current shared values. Personal/machine values and history require opt-in. |
| Are imported commands trusted? | No. Approve their access locally. Version 1 bundles do not authenticate their issuer. |
| Is fresh-machine invite onboarding complete? | No. Invite acceptance still requires a local pending trust record. |
| What works in the desktop? | Project connection, unlock, import, durable command editing, and terminal launch. CLI-backed import/edit require OS-keychain access; passphrase-only vaults use the terminal. |
| Is this a production secret-management service? | No. Use infrastructure designed for your production and CI requirements. |

## Claims to avoid

Offline execution is not unique to Locket. Doppler documents encrypted fallback snapshots and a fallback-only mode for offline access. [Doppler fallback documentation](https://docs.doppler.com/docs/automatic-fallbacks).

Actual-value redaction is not unique either. Dotenvx documents redaction of loaded values with its run command, as well as encrypted env files. [Dotenvx official CLI documentation](https://github.com/dotenvx/dotenvx).

Locket's scanners and redaction are explicit tools for preparing files or output. They do not intercept AI requests or make arbitrary code safe. A process receiving a variable can disclose it.

Do not market unfinished SSO, compliance programs, hosted tiers, automatic team sync, or future pricing as shipped features. Vendor prices and plan limits change; check their primary pricing pages when evaluating a purchase rather than relying on an old matrix.

The remaining adoption test is practical: can an unfamiliar developer import and run their app without coaching, then help a teammate do the same without losing data or sharing extra values? The [product plan](superpowers/plans/2026-10-18-developer-experience-product-plan.md) records those release gates.

External claims checked against the linked primary documentation on 2026-10-18. Product behavior is based on this repository; live multi-device usability has not been measured.
