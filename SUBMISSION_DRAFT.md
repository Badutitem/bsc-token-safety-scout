# Agent Games by zkVerify — Wildcard submission draft

**Name:** BSC Token-Safety Scout

**Category:** Security / Research

**One-line pitch:** An autonomous agent that screens any BSC token in
seconds — verified source? real pool? owner powers? honeypot? — and
answers GO, CAUTION, or BLOCK with the evidence attached.

## Use case

Free-mint and airdrop hunters, small BSC traders, and community mods
screen dozens of tokens a week, most of them brand-new contracts pushed
through Telegram and X posts. The losses rarely come from bad luck; they
come from skipping the boring checks: the contract was never verified,
there is no pool to sell into, the owner can mint or pause transfers, or
the token is an outright honeypot.

This scout is that checklist, automated. It is the exact screening
routine a working BSC hunter runs by hand — contract verification,
two-source pool verification, owner-privilege scan, holder concentration,
tax and honeypot flags — packaged as an agent anyone can call.

## How it works

Input: one BSC (chain 56) token contract address.
Output: a JSON + human-readable report and a GO / CAUTION / BLOCK
verdict, with a reason for every call.

1. **Sourcify** — verification status (exact / partial / unverified);
   when verified, the source is scanned for mint, pause, blacklist,
   fee-setting, and upgrade functions.
2. **DexScreener + GeckoTerminal** — pool existence, liquidity, and 24h
   volume, cross-checked on two independent sources. No pool, no price
   claim.
3. **BSC public RPC** — name, symbol, decimals, total supply, owner(),
   and an EIP-1967 proxy-slot probe, read straight from the chain.
4. **Bytecode selector scan** — for unverified contracts, the deployed
   bytecode is scanned for the exact selectors of dangerous functions
   (selectors computed with a built-in pure-Python Keccak-256).
5. **GoPlus** — honeypot flag, buy/sell tax, holder count, top-holder
   concentration, mintable / pausable / take-back-ownership flags.

Verdict rules are conservative by design: BLOCK on honeypots and on
unverified + pool-less + dangerous-bytecode combinations; CAUTION on
anything unverified, thin, taxable, or owner-controlled; GO only when
every core check actually ran and passed. Any check that could not be
performed is listed as "not verified" — the agent never treats a failed
check as a pass.

Tech: Python 3 standard library only. No dependencies, no API keys, two
files (`scout.py`, `server.py`).

## How judges can try it

Clone the repo and run it — Python 3 standard library only, nothing to
install, no API keys:

```bash
git clone https://github.com/Badutitem/bsc-token-safety-scout
cd bsc-token-safety-scout
python3 scout.py 0x7468aAA418869760b8488b45d59AfB624781435b        # text report
python3 scout.py 0x7468aAA418869760b8488b45d59AfB624781435b --json # machine-readable
```

Or run it as an HTTP endpoint:

```bash
python3 server.py            # listens on $PORT, default 8787
curl -X POST http://localhost:8787/scan \
  -H 'Content-Type: application/json' \
  -d '{"address": "0x7468aAA418869760b8488b45d59AfB624781435b"}'
curl http://localhost:8787/health   # liveness check
```

This submission ships as a repo rather than a hosted service; a hosted
endpoint can be stood up in minutes from the included `Dockerfile` on
any host.

Example addresses on BSC:

- `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c` (WBNB) → **GO** —
  verified, $157M liquidity, no danger signals.
- `0x7468aAA418869760b8488b45d59AfB624781435b` (AEQ) → **CAUTION** —
  verified and clean, but pool liquidity has thinned to ~$2.9k.
- `0xae545bfea9a1b3b8f749c6480bc83d8fe1017777` (unaffiliated 'Agent ID'
  meme token) → **CAUTION** — source unverified on Sourcify, code
  cannot be audited.

Full saved outputs of these runs are in the repo's `demo/` folder.

## Why Wildcard

The scout is a working, useful agent today — not a mock-up: every demo
output in the repo is a real run against live chain data. zkVerify
integration is optional in this track; the roadmap is to anchor each
scan report (address + verdict + evidence hash) as a verifiable proof,
so a screening result can be shown to a third party without trusting
the scout's operator.
