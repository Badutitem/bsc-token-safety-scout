# BSC Token-Safety Scout

An autonomous screening agent for BNB Smart Chain (BSC, chain 56) tokens.
Give it a token contract address and it returns a structured safety report
with a **GO / CAUTION / BLOCK** verdict and the concrete evidence behind it.

Built for the **Agent Games by zkVerify — Wildcard track** (Security /
Research category). Pure Python 3 standard library: no dependencies, no
API keys, runs anywhere Python 3 runs.

## Why this exists

A free-mint / airdrop hunter screens dozens of BSC tokens every week, and
the same questions decide every call: *Is the contract verified? Can this
actually be sold — is there a real pool? Can the owner mint, pause, or
blacklist? Is it a honeypot?* This agent automates exactly that checklist,
cross-checking every claim against at least two independent sources, and
refusing to call anything safe on evidence it could not actually verify.

## The checks

For a token address, the scout runs five checks (all free public APIs):

1. **Sourcify verification** — is the contract source verified
   (exact / partial match) or unverified? When verified, the source is
   scanned for owner-privilege functions. (Handles Sourcify's 404 =
   "unverified" answer and its legacy `match` value.)
2. **Pool reality check, twice** — DexScreener **and** GeckoTerminal:
   pool existence, total liquidity (USD), 24h volume. A token's price
   claim only counts if a pool actually exists on at least one source.
3. **On-chain reads** via a BSC public RPC (`eth_call`): name, symbol,
   decimals, total supply, `owner()`, plus an EIP-1967 proxy-slot probe.
4. **Danger-signal scan** — verified source: regex scan for mint / pause /
   blacklist / settable fee-tax / upgrade functions and owner gating.
   Unverified: the deployed bytecode is scanned for the exact 4-byte
   selectors of dangerous functions (selectors derived with a built-in
   pure-Python Keccak-256 — the stdlib has no Keccak).
5. **GoPlus token security** (bonus source): honeypot flag, buy/sell tax,
   holder count, top-holder concentration, mintable / pausable /
   take-back-ownership flags. If GoPlus is unreachable, the scan continues
   and the check is reported as *not verified* — never silently passed.

## Verdict rules

- **BLOCK** — GoPlus flags a honeypot; or the contract is unverified AND
  has no pool AND its bytecode carries dangerous owner functions; or one
  holder controls > 50% of supply while the owner can still mint.
- **CAUTION** — unverified source; no pool; thin liquidity (< $10,000);
  buy/sell tax > 5%; mintable supply; pausable transfers; hidden owner;
  take-back ownership; live owner with privilege functions; EIP-1967
  proxy; or any core check could not be performed.
- **GO** — only when *every* core check ran and passed: verified source,
  pool with ≥ $10,000 liquidity and real 24h volume, no honeypot, no
  dangerous owner powers found.

Every report lists the evidence per check, and any check that could not
be performed appears in a `not_verified` list. A check that failed is
never treated as a pass.

## Run it

CLI:

```bash
python3 scout.py 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c          # text
python3 scout.py 0x7468aAA418869760b8488b45d59AfB624781435b --json   # JSON
```

HTTP endpoint:

```bash
PORT=8787 python3 server.py
curl http://localhost:8787/health
curl -X POST http://localhost:8787/scan \
  -H 'Content-Type: application/json' \
  -d '{"address": "0x7468aAA418869760b8488b45d59AfB624781435b"}'
# or: curl "http://localhost:8787/scan?address=0x7468..."
```

Deploy: any free Python host or a small VPS — it is two files
(`scout.py`, `server.py`), stdlib only, nothing to install. A
`Dockerfile` is included for container hosting.

## Real demo runs (16 Nov 2026, saved in `demo/`)

**WBNB** `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` → **GO**
Verified (exact match), $157M liquidity / $272M 24h volume across
DexScreener + GeckoTerminal, no honeypot, no danger signals.

**AEQ** `0x7468aAA418869760b8488b45d59AfB624781435b` → **CAUTION**
Verified (exact match) and not a honeypot, but the pool has thinned to
~$2,909 liquidity with ~$0.90 of 24h volume — exit risk. Honest CAUTION,
not a rubber-stamped GO.

**Unaffiliated 'Agent ID' meme token**
`0xae545bfea9a1b3b8f749c6480bc83d8fe1017777` → **CAUTION**
Source is **not verified** on Sourcify, so the code cannot be audited —
flagged even though a ~$29k pool exists and ownership is renounced.

Full text + JSON outputs of all three runs, plus a live server test
(`GET /health`, `POST /scan`), are in the `demo/` folder.

## Files

- `scout.py` — the agent (all checks, verdict logic, CLI).
- `server.py` — HTTP endpoint (`/health`, `/scan`).
- `Dockerfile` — container image for hosting the endpoint on any host.
- `demo/` — real saved outputs of the demo runs and the server test.
- `SUBMISSION_DRAFT.md` — the competition submission text.

## Limits

- BSC only (chain 56). Public RPCs and free APIs are rate-limited; the
  scout retries once and degrades to "not verified" instead of guessing.
- Selector/source scans find *known* danger patterns; a clean scan is
  evidence, not a proof of safety. The verdict is a screening aid, not
  financial advice.
