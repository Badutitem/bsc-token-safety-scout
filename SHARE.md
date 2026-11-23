# Share package — BSC Token-Safety Scout

Draft launch thread (for the builder to post from his own X account —
not posted automatically).

---

**1/**
I built a BSC Token-Safety Scout for the Agent Games by @zkVerify —
Wildcard track.

Paste any BSC token address, get a GO / CAUTION / BLOCK verdict with
the evidence attached. Live now, no install:

https://bsc-token-safety-scout.vercel.app/scan?address=0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c

**2/**
What it checks, every time, across independent sources:

• Sourcify — is the contract source verified?
• DexScreener + GeckoTerminal — is there a real pool, or just a price claim?
• On-chain reads — owner, supply, proxy slot
• Bytecode selector scan — mint / pause / blacklist powers
• GoPlus — honeypot, taxes, holder concentration

**3/**
The rule that matters: a check that couldn't run is reported as
"not verified" — never silently passed.

GO means every core check actually ran and passed. That's it.

**4/**
Two real examples:

WBNB → GO. Verified source, ~$132M liquidity.
AEQ → CAUTION. Clean contract, but the pool thinned to ~$2.7K — exit risk.

Same code, same rules, opposite answers — because the evidence differs.

**5/**
Every report carries a Keccak-256 receipt over its own contents, so
anyone can verify a report wasn't altered after the scan:

python3 scout.py --verify report.json

Pure Python stdlib. No dependencies, no API keys.
Repo: https://github.com/Badutitem/bsc-token-safety-scout
