# Locket Marketing Brief

Internal working doc. The single source of truth for how we describe Locket — to devs, to investors, in the README, on social, in conference talks. Last updated 2026-04-30.

If marketing copy somewhere conflicts with this doc, this doc wins. If this doc is wrong, fix it here first.

---

## The one-line pitch

> **Locket is the secrets manager for dev teams who don't want to run a server or trust a SaaS.**

Memorize this. Don't deviate. Don't add adjectives. The 14 words are load-bearing:

- "secrets manager" — known category, no education required
- "dev teams" — not enterprises, not solo (paid tier opens at 2 seats)
- "don't want to run a server" — anti-Vault, anti-self-hosted-Infisical
- "or trust a SaaS" — anti-Doppler, anti-Infisical-cloud

## The 30-second pitch

> Locket is the secrets manager for dev teams who don't want to run a server or trust a SaaS. Encrypted local vault on each developer's machine, peer-to-peer sealed sync between teammates, AI-prompt redaction so your secrets never leak to Claude or Cursor. Free CLI for solo devs, $7 per seat for teams. Open source, MIT.

Five sentences. Every word earns its place. If you can't repeat it after one read, it's still too long — cut it down.

## The 2-minute pitch

> Every dev team has the same problem: they need to share secrets — database URLs, API tokens, third-party credentials — across their environments. Today they pick one of three bad options.
>
> Option one: `.env` files in `.gitignore`, copy-pasted in Slack. Leaks happen. Drift happens. There's no audit trail. And now those values get pasted into Claude prompts and Cursor context.
>
> Option two: Doppler or Infisical. Polished, cloud-hosted, and $18-21 per seat. Fine, except your production-adjacent secrets now live in someone else's infrastructure, you have a vendor dependency, and pricing scales fast.
>
> Option three: self-host Vault or Infisical. Now you're operating Postgres, Redis, an app server, SSO, and audit retention — all to manage maybe 50 secrets for 5 developers. The medicine is worse than the disease.
>
> Locket is the fourth option. An encrypted SQLite vault on each developer's machine. Peer-to-peer sealed-bundle sync between teammates. No server to run, no SaaS to trust, no `.env` in Slack. Plus a feature no one else ships: AI-prompt redaction that matches against your *actual* secrets, not regex patterns — so when you pipe a log into Claude, your real credentials get scrubbed automatically.
>
> Open-source, MIT-licensed. Solo CLI is free forever. Team tier is $7 per seat per month, no per-machine-account taxes, no SSO paywall below 25 seats. We exist for the long tail of teams that procurement-driven SaaS players can't or won't serve.

## Audience-specific framings

Same product, different opening line depending on who's reading.

### For devs frustrated by `.env` workflow
> Stop pasting `.env` files in Slack. Locket is an encrypted local vault with peer-to-peer team sync — no server, no SaaS, no GPG nightmare.

### For ops/platform engineers who refuse to run Vault
> The secrets layer for teams that don't want to operate Postgres, Redis, and an app server just to manage 50 dev secrets. Local-first, MIT, $7/seat for teams.

### For sovereignty-conscious / regulated teams
> Your secrets, on your machines, encrypted at rest, never on someone else's infrastructure. Zero-knowledge by design. SOC2 Type 1 on the roadmap.

### For AI-tooling-aware devs
> Your `.env` ends up in Claude's context window. Locket scans, redacts, and gates on your actual vault — not regex patterns. `locket ai-safe -- claude` keeps real credentials out of model prompts.

### For investors
> The secrets management market is $200-300M ARR for dev secrets specifically, growing 25-30% annually. SaaS players (Doppler, Infisical) own the cloud-comfortable mid-market; Vault owns enterprise infra. We own the underserved local-first 2-20 person team segment, with a roadmap to expand into agent credential brokering — the credential layer the AI agent stack doesn't have yet.

### For the local-first community
> We're the encrypted secrets primitive Martin Kleppmann's local-first manifesto needs. CRDT-friendly metadata, age-encrypted device-addressed bundles, zero coordination plane. MIT.

## What we never say

These are red flags that pull us back into a worse positioning. If you catch them in copy, rewrite.

- ❌ "Local-first secrets control plane" — architecture jargon, no buyer wakes up wanting this
- ❌ "Zero-trust secret broker" — buzzword salad, means nothing
- ❌ "Replace your `.env` with an encrypted control plane" — same problem, abstract
- ❌ "Enterprise-grade encryption" — every vendor says this, signal-free
- ❌ "Best-in-class developer experience" — generic, no claim
- ❌ "Built with Rust for performance" — devs care that it's fast, not what it's written in
- ❌ "Secure by default" — every security tool says this; we have to *show*

What we say instead:

- ✅ "No server to run, no SaaS to trust"
- ✅ "Cold start under 50ms" (a measured number, not an adjective)
- ✅ "Your secrets live on your machine. Period."
- ✅ "Free for solo devs, $7/seat for teams"
- ✅ "AI-prompt redaction matched against your actual vault"

## Brand voice

- **Direct.** No hedging. No "we believe" or "we think." State it.
- **Honest about limits.** We do not have SSO yet. We say so. We tell people to use Infisical if they need it today. Trust compounds.
- **Anti-marketing-speak.** Devs can smell it. Write the way an engineer talks to another engineer at a bar.
- **Specific over abstract.** "$7/seat" beats "affordable." "50ms cold start" beats "fast." "Encrypted SQLite on disk" beats "secure storage."
- **Confident, not aggressive.** We don't trash competitors. We say where they win and where they lose. The matrix does the talking.

## The comparison page is marketing

[`docs/comparison.md`](comparison.md) is not documentation — it's the most important marketing artifact we have. Every dev evaluating secrets tools eventually builds this matrix in their head. We build it for them, on our terms, and host it where Google can find it.

Maintain it ruthlessly. Update within 7 days of any competitor pricing change. If we're wrong about a competitor, fix it — we'd rather be trusted on the matrix than win one bullet.

## Channels — the only three that matter in year one

We have one founder and limited time. We pick three channels and ignore the rest.

### 1. HN Show launch (one shot, do it right)

**Format:** `Show HN: Locket — open-source local-first secrets manager for dev teams (Rust)`

The phrase "open-source alternative to X" or "local-first alternative to X" over-indexes on HN. The repo URL is the link target, not a marketing landing page.

**Timing:** Tuesday, Wednesday, or Thursday, 8-10am Pacific. Avoid Monday morning, Friday afternoon, and any week with a major industry event.

**Body template:**
```
Hi HN,

I built Locket because I got tired of three things:
1. .env files in Slack
2. Paying $21/seat for Doppler
3. The thought of running Vault for 50 secrets across 5 devs

Locket is an encrypted SQLite vault on each developer's machine, with peer-to-peer
sealed-bundle sync for teams. No server. No SaaS. MIT license.

It also ships AI-prompt redaction — `locket scan --require-known` matches against
your actual vault, not regex patterns, so piping a log into Claude doesn't leak
real credentials.

Status: CLI vault, scanner, redactor, command policies, audit chain are usable
today. Team sync (sealed bundles), tray, and VS Code extension are next.

Repo: [link]
Comparison vs Doppler/Infisical/Bitwarden/dotenvx/etc: [link to docs/comparison.md]

Built in Rust. Cold start under 50ms. Honest feedback wanted.
```

**Within 5 minutes of posting:** pin a top-level comment with technical depth — "happy to answer questions about the threat model, sealed bundle format, or the agent design." This signals to mods and HN regulars that the founder is present.

**For 4 hours after posting:** respond to every comment. Do not get defensive on critical comments — engage technically, concede the point if it's right, explain the tradeoff if it's a tradeoff.

### 2. Reddit (3 specific subs, not generic devops listicles)

- **r/selfhosted** — the anti-SaaS, sovereignty-conscious crowd. Lead with ops-pain framing.
- **r/devops** — pragmatic. Lead with the "stop paying $21/seat" framing.
- **r/programming** — the broad reach play. Lead with the AI-redaction angle, it's the most novel.

Don't post the same copy in all three. Tailor the opening sentence to the sub's culture.

### 3. Founder-led blog (one sharp post per month)

Not "10 reasons to use Locket." Concrete, specific, evergreen posts:

- *"We benchmarked 8 secrets managers' cold-start latency"* — comparative data, table at top
- *"Why your team's `.env` ends up in Claude's training data"* — fear-driving, recent
- *"The case against running Postgres for 5 secrets"* — opinion, contrarian, links to comparison
- *"How we built peer-to-peer secret sync without a server"* — engineering deep-dive
- *"What dotenvx Ops, Doppler, and Infisical have in common — and why it disqualifies them for some teams"* — comparison framing

Each post earns links and exists for SEO years later. Cross-post to Lobste.rs and HN as relevant. Submit to programming.dev, [r/rust](https://reddit.com/r/rust), and dev.to (just as syndication, not original).

### What we skip

- Paid ads to developers (CAC > LTV until Org tier exists)
- Conference sponsorships year one (booth at $25K+ doesn't pay back below $1M ARR)
- Twitter/X main feed engagement (high noise, low convert; we use it for replies and broadcasting blog posts only)
- dev.to listicles, Medium hype posts, podcast tours
- "AI for X" announcements when AI isn't the headline feature

## Free tier design

The free tier is marketing infrastructure, not just a generous gesture. It has to convert.

**Wall on scale, not capability:**

- Solo (1 user): full CLI, full vault, full scanner, full redactor, full audit chain, single-user only.
- Team ($7/seat, 2+ users): everything in solo + sealed-bundle sync + tray + audit aggregation.
- Org ($14/seat, 25+ or SSO required): + SSO/SCIM, 1yr audit retention, approval workflows, SLA.

We never paywall the security primitives (encryption, scanner, audit chain). We paywall coordination — the moment a second human is involved.

**Time-to-first-value target: under 5 minutes.** Install, init, set, get, run. No signup, no email gate, no telemetry handshake. The CLI works air-gapped on day one.

**Charge from customer #1.** Even $7. Free pilots train customers that the product is free.

## Pricing rationale (one paragraph for skeptics)

$7/seat is $1 above Bitwarden Secrets Manager ($6) and $1 below 1Password Business ($8). Well under Doppler ($21) and Infisical ($18). Matches dotenvx Ops blended ($6.67/seat at the 3-seat tier). Within the "small team will swipe a card without a procurement review" range. Service accounts free and uncounted — explicit anti-Infisical move, since per-identity pricing including CI runners is their loudest community complaint. SSO at the Org tier ($14) — explicit anti-Infisical move on the SSO-paywall complaint. We do not gate audit log retention by tier (Doppler shrinks free to 3 days; we don't); we gate by retention length, not by access.

## Distribution growth flywheel

```
Solo dev installs → uses on personal projects → introduces at work →
team needs sync → upgrades to Team tier → company hits 25 seats →
needs SSO → upgrades to Org tier → procurement contact → Enterprise.
```

Every step has to feel natural. The friction points to engineer:

- **Solo → Team:** When the user invites a teammate, the upgrade is the next step. CLI prompt: "Locket is free for solo use. Inviting a teammate moves you to Team tier ($7/seat/mo). Continue?"
- **Team → Org:** When the user adds a 25th seat or runs `locket policy require sso`, surface Org tier.
- **Org → Enterprise:** Procurement contact triggers — "annual contract", "MSA", "SOC2 letter" requests.

Bottom-up adoption, founder-led conversion, no top-down sales until $1M ARR.

## Visual identity (placeholder — to be designed)

- **Wordmark:** lowercase `locket`, monospace or near-monospace.
- **Color:** dark slate primary, warm amber accent (locket = something private + warm).
- **Logo:** literal locket icon, simple line. Avoid generic "lock" iconography (overused).
- **Code blocks in marketing:** dark theme, real Locket commands, syntax-highlighted, copyable.

Until we hire a designer, use the wordmark and the amber accent consistently across README, comparison page, blog, and slides.

## Customer-discovery questions

For the first 30 conversations with prospective users, ask these in order. Don't pitch. Listen. The answers shape every word above.

1. How does your team currently share secrets across local dev environments?
2. What's the worst part of that workflow?
3. Have you tried Doppler / Infisical / 1Password / Vault? What happened?
4. If you could change one thing about how secrets work on your team, what would it be?
5. (After demo) On a scale of 1-10, how likely are you to use this within 30 days?
6. (If <7) What would have to be true for that to be a 9?
7. What would you pay per developer per month for Locket if it had [the features they listed in #4]?

If 7+ of 10 give a pain that Locket solves and a number ≥ $5/seat, the marketing copy is right. If not, the product is what's wrong, not the words. Fix the product, then come back to this doc.

## Update cadence

- README + comparison page: review monthly, update on any competitor pricing change within 7 days
- This brief: review quarterly, rewrite when product positioning shifts (target: every 18-24 months)
- Blog post cadence: 1 sharp post per month for first 12 months, ratchet to 2/month after Series A

## Owners

- README, comparison, marketing brief: founder until $1M ARR
- Blog posts: founder writes, technical reviewer (eng team) checks accuracy
- Social/HN/Reddit launch: founder only
- Customer discovery calls: founder only until first 30 done

The founder owns the voice. Don't delegate the words until you've written 50 of them yourself.
