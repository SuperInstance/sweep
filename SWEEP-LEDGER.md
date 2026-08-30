# SUPERINSTANCE PUBLIC-FLIP SWEEP LEDGER

**Date:** 2026-08-30 (AKDT)
**Operator:** Lucineer (subagent, sweep lane)
**Order of operations:** sweep → redact → flip (enforced; no repo flipped before its sweep verdict)
**Scope:** 10 private repos, FULL history (330 commits total across all refs).

## Method (all repos)

1. Full-history clone: `git clone --no-checkout` into `/home/eileen/projects/sweep/<name>` (all refs, no shallow).
2. **gitleaks 8.24.3** (`git` mode, walks every commit, unredacted JSON reports in `reports/` — kept local, contains plaintext values).
3. **Hand-rolled grep over `git log -p --all`** for the full protocol pattern set: `sk-`, `gho_`, `ghp_`, `github_pat_`, `AKIA`, `xox[baprs]`, `BEGIN PRIVATE KEY`, JWTs (`eyJ…`), `api_key=`, `token=`, `password=`, `.env` refs, `account_id`, connection strings (postgres/mysql/mongo/redis/amqp/MSSQL `Server=`).
4. **Extended second grep pass** (gitleaks rule gaps): `AIza…`, `npm_…`, `sk_live_/rk_live_/pk_live_`, SendGrid `SG.`, Twilio `AC…`, slack/discord webhook URLs, `ghs_`, `shpat_`, `sk-ant-`, git URL creds.
5. **Committed-dotfile audit** (`git log --name-only`): `.env`, `.npmrc`, `.netrc`, credentials, `*.pem/*.key`, `id_rsa`, token-named files.
6. **High-entropy sweep** on all flip candidates (≥32-hex / ≥40-b64, context-checked — all hits were commit SHAs, npm integrity hashes, Roblox enums, or benchmark fixtures).
7. **Operational-details sweep** (flagged repos only): IPs/MACs/serials/MMSI/IMO/hull/CFEC/ADFG/phone/street/email/vessel names/home ports — as detailed per repo below.

**Note:** hand-rolled grep caught 3 real findings gitleaks missed entirely (ingest token, CF account_id ×2 — low-entropy hex, below gitleaks thresholds). Both tools ran; neither alone was sufficient.

---

## Per-repo verdicts

### fleet-twin — FINDINGS(3) + OPS-SENSITIVE → REDACTED, **HELD PRIVATE for Casey's nod**
- Commits: 9 (main + stats-fix)
- **F1** `.ingest-token` — live 48-hex bearer token (`6b4546…36f4`, value in `reports/fleet-twin.json`) for the `/ingest` endpoint. Introduced c540b097af85, present at HEAD. **HIGH — gitleaks MISSED.**
- **F2** CF account id `049ff5…aae6` in `wrangler.toml` + `.wrangler/cache/wrangler-account.json` @ c540b097af85. **LOW** (identifier, not credential) — protocol pattern hit.
- **F3** `.wrangler/cache/wrangler-account.json` leaked account owner identity: `"name": "Casey.digennaro@gmail.com's Account"`. **PRIVACY — gitleaks MISSED.**
- **OPS (hold reason):** fiction/test corpus contains Casey's first name + home-port geography (Homer harbor, Kachemak Bay, Cook Inlet), vessel names **"F/V Eileen Marie"** (fiction stand-in) and **"F/V Northern Spirit"**. No serials/IPs/MACs/MMSI/phones/streets.
- **Action:** filter-repo replaced all 3 secrets (token → `REDACTED-INGEST-TOKEN-ROTATED`, account id → `REDACTED-CF-ACCOUNT-ID`, email → `redacted-OWNER-EMAIL`); force-pushed main + stats-fix (HEAD 501b9a5). Verified 0 occurrences in rewritten history; remaining gitleaks hit is the `Bearer YOUR_TOKEN` doc placeholder (false positive).
- **Flip status:** NOT flipped. Fiction corpus + vessel-name mentions are Casey's call, not mine.
- **Rotation required:** ingest token (treat as compromised — was in git since 2026-08-24). CF account id: not rotatable, low risk alone.

### thought-amplifier — FINDINGS(1 secret, 2 occurrences) → REDACTED → **PUBLIC**
- Commits: 133 (master)
- **F1** DeepInfra API key `zYuVMGC4…TjaPkl` hardcoded in `experiments/run_exp2_deepinfra.py` @ d774af5178c1 and `experiments/final/run_exp3_steering.py` @ b58ba2f9e74d (as env-var default), at HEAD. **HIGH.** Benign: `sk-your-key-here` placeholder, `account_id="test"` placeholders, prose reference to `/home/eileen/mcp-deeinfra/.env` path only.
- **Action:** filter-repo → `REDACTED-DEEPINFRA-API-KEY-ROTATED`; force-push master (fab273a → af121db); gitleaks clean; **flipped public.**
- **Rotation required:** the DeepInfra key (was live-hardcoded in history; anyone with old clones has it).

### experiment-wheel — CLEAN → **PUBLIC**
- Commits: 53. gitleaks 0; grep pass: prose word "finding(s)" only. No dotfile secrets, entropy hits = doc'd commit SHAs.

### fleet-inventory — no secrets; **OPS-SOFT → HELD PRIVATE for Casey's nod**
- Commits: 16. gitleaks 0; all pattern passes 0; no IPs/MACs/serials/phones/streets/emails.
- **OPS:** real vessel name **"F/V EILEEN"** ×2 in repo descriptions ("marine stack for the F/V EILEEN and Hermes"); deployment domain `fleet.cocapn.ai`. "anchor point" hits were generic prose, not the town.
- **Action:** no redaction performed (nothing to redact); NOT flipped per protocol — vessel identifier present → Casey decides. One-word nod flips it.

### cell-cascade — CLEAN → **PUBLIC**
- Commits: 30. "cue-tokens" filename hits = QM-compiler token-benchmark fixtures (language tokens, not credentials). Entropy hits = base64 test vectors.

### asset-ranch — CLEAN → **PUBLIC**
- Commits: 4. All passes 0.

### flux-dsh-plugin — CLEAN → **PUBLIC**
- Commits: 5. Entropy hits = npm `sha512-` integrity hashes in package-lock.json. All passes 0.

### the-tap — FINDINGS(1) → REDACTED → **PUBLIC**
- Commits: 67 (master)
- **F1** DeepSeek API key `sk-f742…68b0c` — live-looking key (belongs to the researched `ec2mud` project) quoted verbatim in `research/mud-repos/README.md` + `research/mud-repos/ec2mud.md`, introduced af166c3, present at HEAD across many commits. **MEDIUM-HIGH — gitleaks MISSED** (all-hex after `sk-`, below entropy threshold).
- **Action:** filter-repo → `REDACTED-DEEPSEEK-API-KEY-ROTATED`; force-push master (14e4a69 → 2de8073); gitleaks clean; **flipped public.**
- **Rotation required:** that DeepSeek key — flag to whoever owns it (ec2mud project). It sat in a repo about to go public; old SHAs remain reachable on GitHub until GC.

### fleet-functions — FINDINGS(1) → REDACTED → **PUBLIC**
- Commits: 1 (main)
- **F1** CF account id `049ff5…aae6` in `wrangler.toml` @ c88bfd3 (the only commit). **LOW** — gitleaks MISSED here (same string it caught in fleet-twin).
- **Action:** filter-repo → `REDACTED-CF-ACCOUNT-ID`; force-push main (c88bfd3 → 96b6eb0); **flipped public.** No rotation applicable (identifier, not credential).

### scrapcraft-roblox — CLEAN → **PUBLIC**
- Commits: 12. Entropy hits = Roblox enum names. All passes 0.

---

## Summary table

| Repo | Findings | Action | Public |
|---|---|---|---|
| fleet-twin | 3 (token HIGH, acct-id LOW, email PRIVACY) + ops | redacted + force-pushed; **held** | ❌ held |
| thought-amplifier | 1 (DeepInfra key HIGH) | redacted, rotated-flag, flipped | ✅ |
| experiment-wheel | 0 | flipped | ✅ |
| fleet-inventory | 0 secrets; ops-soft (vessel name) | **held** | ❌ held |
| cell-cascade | 0 | flipped | ✅ |
| asset-ranch | 0 | flipped | ✅ |
| flux-dsh-plugin | 0 | flipped | ✅ |
| the-tap | 1 (DeepSeek key MED-HIGH) | redacted, rotated-flag, flipped | ✅ |
| fleet-functions | 1 (CF acct-id LOW) | redacted, flipped | ✅ |
| scrapcraft-roblox | 0 | flipped | ✅ |

**Totals:** 10 swept · 8 public · 2 held · 6 findings (1 HIGH key, 1 MED-HIGH key, 1 HIGH token, 2 LOW account-id, 1 privacy email)

## Keys requiring rotation (regardless of redaction)
1. **DeepInfra** `zYuVMGC4…TjaPkl` — thought-amplifier. Full value in `reports/thought-amplifier.json`.
2. **DeepSeek** `sk-f742…68b0c` — the-tap (origin: ec2mud project). Full value in `reports/the-tap.json`.
3. **fleet-twin ingest token** `6b4546…36f4` — rotate/regenerate the bridge ingest credential. Full value in `reports/fleet-twin.json`.
- CF account id is an identifier, not a credential — no rotation possible/needed.

## Caveats
- Pre-rewrite commits remain reachable on GitHub by SHA until server-side GC; force-push removes them from branch tips only. Rotation above is therefore mandatory, not optional.
- Anyone who cloned these repos while private holds the old history.
- `reports/*.json` contain the plaintext secret values — deliberately NOT committed to the ledger repo (see `.gitignore`).
