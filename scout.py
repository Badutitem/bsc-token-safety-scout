#!/usr/bin/env python3
"""BSC Token-Safety Scout.

Input : a BSC (chain 56) token contract address.
Output: a structured safety report + a GO / CAUTION / BLOCK verdict.

Checks (all free public sources, no API keys):
  1. Sourcify contract verification status (+ source, when verified)
  2. Pool existence / liquidity / 24h volume on DexScreener AND GeckoTerminal
  3. On-chain reads via a BSC public RPC (name, symbol, decimals, supply, owner)
  4. Danger-signal scan: source scan when verified, bytecode selector scan
     when unverified; EIP-1967 proxy slot probe
  5. GoPlus token security API (bonus source; failures are reported, not fatal)

Standard library only. Deterministic: same input -> same report shape.
"""

import json
import re
import sys
import time
import urllib.error
import urllib.request

CHAIN_ID = 56
RPC_URL = "https://bsc-dataseed.bnbchain.org"
SOURCIFY_URL = "https://sourcify.dev/server/v2/contract/56/{addr}"
DEXSCREENER_URL = "https://api.dexscreener.com/latest/dex/tokens/{addr}"
GECKOTERMINAL_URL = (
    "https://api.geckoterminal.com/api/v2/networks/bsc/tokens/{addr}/pools"
)
GOPLUS_URL = (
    "https://api.gopluslabs.io/api/v1/token_security/56"
    "?contract_addresses={addr}"
)

HTTP_TIMEOUT = 20
USER_AGENT = "bsc-token-safety-scout/1.0 (+agent-games-zkverify wildcard)"

# Verdict thresholds (documented in README.md)
REAL_LIQUIDITY_USD = 10_000.0      # at/above this, liquidity counts as "real"
HIGH_TAX = 0.05                    # buy or sell tax above 5% is a caution flag
EXTREME_TOP_HOLDER = 0.50          # one holder above 50% of supply

ZERO_ADDRESS = "0x" + "0" * 40
# EIP-1967 implementation storage slot
EIP1967_IMPL_SLOT = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)

# ---------------------------------------------------------------------------
# Pure-Python Keccak-256 (stdlib hashlib only offers NIST SHA3, not Keccak).
# Needed to derive exact 4-byte function selectors for the bytecode scan.
# ---------------------------------------------------------------------------

_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_KECCAK_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_MASK64 = (1 << 64) - 1


def _rotl64(x, n):
    if n == 0:
        return x & _MASK64
    return ((x << n) | (x >> (64 - n))) & _MASK64


def _keccak_f1600(state):
    for rc in _KECCAK_RC:
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15]
             ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(
                    state[x + 5 * y], _KECCAK_ROT[x][y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = (
                    b[x + 5 * y]
                    ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
                ) & _MASK64
        state[0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136  # 1088-bit rate for 256-bit output
    padded = bytearray(data)
    padded.append(0x01)  # Keccak (pre-NIST) domain separator
    while len(padded) % rate != rate - 1:
        padded.append(0x00)
    padded.append(0x80)
    state = [0] * 25
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:(i + 1) * 8], "little")
            state[i] ^= lane
        _keccak_f1600(state)
    out = bytearray()
    for i in range(4):
        out += state[i].to_bytes(8, "little")
    return bytes(out[:32])


def selector(signature: str) -> str:
    """4-byte function selector as 8 lowercase hex chars."""
    return keccak256(signature.encode()).hex()[:8]


# ---------------------------------------------------------------------------
# HTTP + RPC helpers (retry once, spaced, fail soft with None)
# ---------------------------------------------------------------------------

def http_get_json(url, retries=1):
    """GET JSON. Returns parsed object or None on any failure."""
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": USER_AGENT,
                              "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except Exception:
            if attempt < retries:
                time.sleep(1.5)
    return None


def rpc_call(method, params, retries=1):
    """One JSON-RPC call to the BSC public RPC. Returns result or None."""
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(
                RPC_URL, data=payload,
                headers={"Content-Type": "application/json",
                         "User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            if isinstance(data, dict) and "result" in data:
                return data["result"]
            return None  # RPC-level error (e.g. execution reverted)
        except Exception:
            if attempt < retries:
                time.sleep(1.5)
    return None


def eth_call(address, data_hex):
    return rpc_call("eth_call", [{"to": address, "data": data_hex}, "latest"])


# ---------------------------------------------------------------------------
# ABI decoding helpers (only the simple types this scout reads)
# ---------------------------------------------------------------------------

def decode_string(hexdata):
    if not hexdata or hexdata == "0x":
        return None
    raw = bytes.fromhex(hexdata[2:])
    try:
        if len(raw) >= 64:  # dynamic string: offset + length + data
            length = int.from_bytes(raw[32:64], "big")
            return raw[64:64 + length].decode("utf-8", "replace")
        return raw.rstrip(b"\x00").decode("utf-8", "replace")  # bytes32 style
    except Exception:
        return None


def decode_uint(hexdata):
    if not hexdata or hexdata == "0x":
        return None
    try:
        return int(hexdata, 16)
    except Exception:
        return None


def decode_address(hexdata):
    if not hexdata or len(hexdata) < 42:
        return None
    return "0x" + hexdata[-40:].lower()


# ---------------------------------------------------------------------------
# Check 1: Sourcify verification (+ source when available)
# ---------------------------------------------------------------------------

def check_sourcify(address):
    """Returns dict with status: exact_match | partial_match | unverified |
    not_verified, plus the concatenated source text when verified.

    Note: Sourcify answers HTTP 404 with a JSON body {"match": null} for
    contracts it has not verified — that is a valid 'unverified' answer,
    not an API failure."""
    url = SOURCIFY_URL.format(addr=address) + "?fields=sources"
    data = None
    for attempt in range(2):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": USER_AGENT,
                              "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            break
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                try:
                    data = json.loads(
                        exc.read().decode("utf-8", "replace"))
                except Exception:
                    data = {"match": None}
                break
            if attempt == 0:
                time.sleep(1.5)
        except Exception:
            if attempt == 0:
                time.sleep(1.5)
    if data is None:
        return {"status": "not_verified", "match": None, "source": None}
    match = data.get("match")  # "exact_match" | "partial_match" | null
    if not match:
        return {"status": "unverified", "match": None, "source": None}
    # Legacy Sourcify entries report a full match as plain "match".
    status = "exact_match" if match == "match" else match
    sources = data.get("sources") or {}
    text = "\n".join(
        (v or {}).get("content", "") for v in sources.values())
    return {
        "status": status,
        "match": match,
        "source": text or None,
        "verified_at": data.get("verifiedAt"),
    }


# ---------------------------------------------------------------------------
# Check 2: pools on DexScreener AND GeckoTerminal
# ---------------------------------------------------------------------------

def check_pools(address):
    out = {"dexscreener": None, "geckoterminal": None}

    ds = http_get_json(DEXSCREENER_URL.format(addr=address))
    if ds is not None:
        pairs = [p for p in (ds.get("pairs") or [])
                 if (p.get("chainId") == "bsc")]
        liq = sum(float((p.get("liquidity") or {}).get("usd") or 0)
                  for p in pairs)
        vol = sum(float((p.get("volume") or {}).get("h24") or 0)
                  for p in pairs)
        best = None
        if pairs:
            top = max(pairs,
                      key=lambda p: float((p.get("liquidity") or {})
                                          .get("usd") or 0))
            best = {
                "pair": top.get("pairAddress"),
                "dex": top.get("dexId"),
                "liquidity_usd": float((top.get("liquidity") or {})
                                       .get("usd") or 0),
                "volume_24h_usd": float((top.get("volume") or {})
                                        .get("h24") or 0),
            }
        out["dexscreener"] = {
            "pairs_found": len(pairs),
            "total_liquidity_usd": round(liq, 2),
            "total_volume_24h_usd": round(vol, 2),
            "best_pair": best,
        }

    gt = http_get_json(GECKOTERMINAL_URL.format(addr=address))
    if gt is not None:
        pools = gt.get("data") or []
        liq = 0.0
        vol = 0.0
        for p in pools:
            attrs = p.get("attributes") or {}
            try:
                liq += float(attrs.get("reserve_in_usd") or 0)
            except (TypeError, ValueError):
                pass
            try:
                vol += float((attrs.get("volume_usd") or {}).get("h24") or 0)
            except (TypeError, ValueError):
                pass
        out["geckoterminal"] = {
            "pairs_found": len(pools),
            "total_liquidity_usd": round(liq, 2),
            "total_volume_24h_usd": round(vol, 2),
        }

    sources = [s for s in (out["dexscreener"], out["geckoterminal"]) if s]
    out["checked"] = len(sources) > 0
    out["exists"] = any(s["pairs_found"] > 0 for s in sources)
    # Cross-source totals: take the max per metric (sources overlap heavily;
    # summing would double-count the same pools).
    out["liquidity_usd"] = max(
        (s["total_liquidity_usd"] for s in sources), default=0.0)
    out["volume_24h_usd"] = max(
        (s["total_volume_24h_usd"] for s in sources), default=0.0)
    return out


# ---------------------------------------------------------------------------
# Check 3: basic on-chain reads
# ---------------------------------------------------------------------------

SEL = {
    "name": "0x06fdde03",
    "symbol": "0x95d89b41",
    "decimals": "0x313ce567",
    "totalSupply": "0x18160ddd",
    "owner": "0x8da5cb5b",
}


def check_onchain(address):
    out = {"checked": False}
    code = rpc_call("eth_getCode", [address, "latest"])
    out["has_code"] = bool(code and code != "0x")
    out["bytecode"] = code if out["has_code"] else None

    name = eth_call(address, SEL["name"])
    if name is not None:
        out["checked"] = True
    out["name"] = decode_string(name)
    out["symbol"] = decode_string(eth_call(address, SEL["symbol"]))
    out["decimals"] = decode_uint(eth_call(address, SEL["decimals"]))
    supply = decode_uint(eth_call(address, SEL["totalSupply"]))
    out["total_supply_raw"] = supply
    if supply is not None and out["decimals"] is not None:
        out["total_supply"] = supply / (10 ** out["decimals"])
    else:
        out["total_supply"] = None
    owner_raw = eth_call(address, SEL["owner"])
    out["owner"] = decode_address(owner_raw) if owner_raw else None
    out["owner_function_present"] = owner_raw is not None

    impl = rpc_call("eth_getStorageAt",
                    [address, EIP1967_IMPL_SLOT, "latest"])
    impl_addr = decode_address(impl) if impl else None
    out["eip1967_implementation"] = (
        impl_addr if impl_addr and impl_addr != ZERO_ADDRESS else None)
    return out


# ---------------------------------------------------------------------------
# Check 4: danger signals (source scan or bytecode selector scan)
# ---------------------------------------------------------------------------

DANGER_SIGNATURES = {
    "mint(address,uint256)": "owner can mint new tokens",
    "mint(uint256)": "owner can mint new tokens",
    "mint(address)": "owner can mint new tokens",
    "pause()": "transfers can be paused",
    "unpause()": "transfers can be paused/unpaused",
    "blacklist(address)": "addresses can be blacklisted",
    "blackList(address)": "addresses can be blacklisted",
    "setBlacklist(address,bool)": "addresses can be blacklisted",
    "addBlacklist(address)": "addresses can be blacklisted",
    "setFee(uint256)": "owner can change fees",
    "setFees(uint256,uint256)": "owner can change fees",
    "setTax(uint256)": "owner can change taxes",
    "setBuyFee(uint256)": "owner can change fees",
    "setSellFee(uint256)": "owner can change fees",
    "upgradeTo(address)": "contract is upgradeable (proxy)",
    "upgradeToAndCall(address,bytes)": "contract is upgradeable (proxy)",
    "setWhitelist(address,bool)": "whitelist gating present",
    "addWhitelist(address)": "whitelist gating present",
}

SOURCE_PATTERNS = [
    (r"function\s+mint\s*\(", "mint function in source"),
    (r"function\s+pause\s*\(", "pause function in source"),
    (r"function\s+unpause\s*\(", "unpause function in source"),
    (r"blacklist|blackList|_isBlacklisted|isBlacklisted",
     "blacklist logic in source"),
    (r"function\s+set\w*(Fee|Tax)\w*\s*\(", "owner-settable fee/tax in source"),
    (r"function\s+upgradeTo\w*\s*\(", "upgrade function in source"),
    (r"onlyOwner", "owner-gated functions in source"),
]


def check_danger(sourcify, onchain):
    """Returns list of {signal, severity, evidence}."""
    signals = []
    if sourcify.get("source"):
        src = sourcify["source"]
        for pattern, label in SOURCE_PATTERNS:
            if re.search(pattern, src):
                sev = "info" if label.startswith("owner-gated") else "warn"
                signals.append({"signal": label, "severity": sev,
                                "evidence": "verified source scan"})
        return signals
    code = onchain.get("bytecode")
    if code:
        hexcode = code[2:].lower()
        for sig, label in DANGER_SIGNATURES.items():
            if selector(sig) in hexcode:
                signals.append({
                    "signal": label,
                    "severity": "warn",
                    "evidence": f"bytecode contains selector for {sig}",
                })
    return signals


# ---------------------------------------------------------------------------
# Check 5: GoPlus token security (bonus source)
# ---------------------------------------------------------------------------

def _f(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def check_goplus(address):
    data = http_get_json(GOPLUS_URL.format(addr=address))
    if not data or data.get("code") != 1:
        return None
    result = (data.get("result") or {}).get(address.lower())
    if not result:
        return None
    holders = result.get("holders") or []
    top = []
    for h in holders[:10]:
        pct = _f(h.get("percent"))
        if pct is not None:
            top.append({"address": h.get("address"), "percent": pct})
    top.sort(key=lambda x: x["percent"], reverse=True)
    dex = result.get("dex") or []
    return {
        "is_honeypot": result.get("is_honeypot") == "1",
        "honeypot_unknown": result.get("is_honeypot") in (None, ""),
        "buy_tax": _f(result.get("buy_tax")),
        "sell_tax": _f(result.get("sell_tax")),
        "holder_count": result.get("holder_count"),
        "top_holders": top,
        "top1_percent": top[0]["percent"] if top else None,
        "top10_percent": (round(sum(h["percent"] for h in top), 6)
                          if top else None),
        "is_mintable": result.get("is_mintable") == "1",
        "is_proxy": result.get("is_proxy") == "1",
        "can_take_back_ownership":
            result.get("can_take_back_ownership") == "1",
        "hidden_owner": result.get("hidden_owner") == "1",
        "transfer_pausable": result.get("transfer_pausable") == "1",
        "owner_address": result.get("owner_address"),
        "pool_liquidity_usd": (max((_f(d.get("liquidity")) or 0)
                                   for d in dex) if dex else None),
    }


# ---------------------------------------------------------------------------
# Verdict logic
# ---------------------------------------------------------------------------

def build_verdict(sourcify, pools, onchain, danger, goplus):
    """Returns (verdict, reasons, not_verified)."""
    reasons = []
    not_verified = []
    block = False
    caution = False

    verified = sourcify["status"] in ("exact_match", "partial_match")
    if sourcify["status"] == "not_verified":
        not_verified.append("Sourcify verification status (API unreachable)")
    if not onchain["checked"]:
        not_verified.append("On-chain token reads (RPC unreachable)")
    if not pools["checked"]:
        not_verified.append("Pool data (DexScreener + GeckoTerminal "
                            "unreachable)")
    if goplus is None:
        not_verified.append("GoPlus token security (API unreachable or "
                            "token not indexed)")

    # --- hard blocks -------------------------------------------------------
    if goplus and goplus["is_honeypot"]:
        block = True
        reasons.append("BLOCK: GoPlus flags this token as a honeypot "
                       "(buying works, selling is blocked).")
    warn_signals = [s for s in danger if s["severity"] == "warn"]
    if (not verified and sourcify["status"] == "unverified"
            and pools["checked"] and not pools["exists"] and warn_signals):
        block = True
        reasons.append(
            "BLOCK: contract is unverified, no pool exists on DexScreener "
            "or GeckoTerminal, and the bytecode carries dangerous owner "
            "functions (" +
            "; ".join(sorted({s["signal"] for s in warn_signals})) + ").")
    if (goplus and goplus["top1_percent"] is not None
            and goplus["top1_percent"] > EXTREME_TOP_HOLDER
            and goplus["is_mintable"]):
        block = True
        reasons.append(
            f"BLOCK: one holder controls {goplus['top1_percent']:.1%} of "
            "supply and the owner can still mint — extreme concentration "
            "with mint power.")

    # --- cautions ----------------------------------------------------------
    if sourcify["status"] == "unverified":
        caution = True
        reasons.append("CAUTION: contract source is NOT verified on "
                       "Sourcify — code cannot be audited.")
    if pools["checked"] and not pools["exists"]:
        caution = True
        reasons.append("CAUTION: no pool found on DexScreener or "
                       "GeckoTerminal — the token cannot be sold on a DEX "
                       "and any price claim is unverifiable.")
    elif pools["exists"] and pools["liquidity_usd"] < REAL_LIQUIDITY_USD:
        caution = True
        reasons.append(
            f"CAUTION: liquidity is thin (${pools['liquidity_usd']:,.0f} "
            f"< ${REAL_LIQUIDITY_USD:,.0f}) — high slippage / exit risk.")
    if goplus:
        for side in ("buy_tax", "sell_tax"):
            tax = goplus[side]
            if tax is not None and tax > HIGH_TAX:
                caution = True
                reasons.append(
                    f"CAUTION: {side.replace('_', ' ')} is {tax:.1%} "
                    f"(> {HIGH_TAX:.0%} threshold).")
        if goplus["is_mintable"]:
            caution = True
            reasons.append("CAUTION: supply is mintable — owner can "
                           "inflate the supply.")
        if goplus["can_take_back_ownership"]:
            caution = True
            reasons.append("CAUTION: ownership can be taken back by the "
                           "deployer (can_take_back_ownership).")
        if goplus["hidden_owner"]:
            caution = True
            reasons.append("CAUTION: hidden owner detected by GoPlus.")
        if goplus["transfer_pausable"]:
            caution = True
            reasons.append("CAUTION: transfers are pausable by the owner.")
    if onchain.get("eip1967_implementation"):
        caution = True
        reasons.append(
            "CAUTION: EIP-1967 proxy — implementation at "
            f"{onchain['eip1967_implementation']} can be upgraded by the "
            "proxy admin.")
    owner = onchain.get("owner")
    if owner and owner != ZERO_ADDRESS and warn_signals:
        caution = True
        reasons.append(
            f"CAUTION: contract has a live owner ({owner}) and "
            "owner-privilege functions are present.")

    # --- positives (for the GO case and for the record) --------------------
    positives = []
    if verified:
        positives.append(
            f"Contract verified on Sourcify ({sourcify['status']}).")
    if pools["exists"] and pools["liquidity_usd"] >= REAL_LIQUIDITY_USD:
        positives.append(
            f"Pool liquidity ${pools['liquidity_usd']:,.0f} with "
            f"${pools['volume_24h_usd']:,.0f} traded in 24h.")
    if goplus and not goplus["is_honeypot"]:
        positives.append("GoPlus: not flagged as honeypot.")
    if owner == ZERO_ADDRESS:
        positives.append("Ownership renounced (owner() = zero address).")

    if block:
        verdict = "BLOCK"
    elif caution:
        verdict = "CAUTION"
    else:
        # GO only when every core check actually ran and came back clean.
        core_ok = (verified and pools["checked"] and pools["exists"]
                   and pools["liquidity_usd"] >= REAL_LIQUIDITY_USD
                   and pools["volume_24h_usd"] > 0
                   and onchain["checked"] and goplus is not None
                   and not goplus["is_honeypot"] and not warn_signals)
        if core_ok:
            verdict = "GO"
            reasons = positives + reasons
        else:
            verdict = "CAUTION"
            reasons.append(
                "CAUTION: not enough verified evidence for GO (one or "
                "more core checks missing or inconclusive — see "
                "'not verified' list).")
            reasons = positives + reasons
    return verdict, reasons, not_verified


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def scan(address):
    if not ADDRESS_RE.match(address or ""):
        raise ValueError("invalid address format (expected 0x + 40 hex)")
    address = address.lower()

    sourcify = check_sourcify(address)
    pools = check_pools(address)
    onchain = check_onchain(address)
    danger = check_danger(sourcify, onchain)
    goplus = check_goplus(address)
    verdict, reasons, not_verified = build_verdict(
        sourcify, pools, onchain, danger, goplus)

    report = {
        "address": address,
        "chain": CHAIN_ID,
        "chain_name": "BSC (BNB Smart Chain)",
        "token": {
            "name": onchain.get("name"),
            "symbol": onchain.get("symbol"),
            "decimals": onchain.get("decimals"),
            "total_supply": onchain.get("total_supply"),
            "owner": onchain.get("owner"),
            "is_contract": onchain.get("has_code"),
        },
        "verification": {
            "source": "Sourcify",
            "status": sourcify["status"],
            "verified_at": sourcify.get("verified_at"),
        },
        "pools": {
            "exists": pools["exists"],
            "liquidity_usd": pools["liquidity_usd"],
            "volume_24h_usd": pools["volume_24h_usd"],
            "dexscreener": pools["dexscreener"],
            "geckoterminal": pools["geckoterminal"],
        },
        "danger_signals": danger,
        "proxy": {
            "eip1967_implementation":
                onchain.get("eip1967_implementation"),
            "goplus_is_proxy": (goplus or {}).get("is_proxy"),
        },
        "goplus": goplus,
        "not_verified": not_verified,
        "verdict": verdict,
        "reasons": reasons,
    }
    report["receipt"] = make_receipt(report)
    return report


# ---------------------------------------------------------------------------
# Verifiable receipt
# ---------------------------------------------------------------------------
# Every report carries a Keccak-256 receipt over its own canonical form, so
# anyone holding the report can prove it was not altered after the scan and
# can re-derive the exact verdict inputs. Canonical form: the report WITHOUT
# the "receipt" field, JSON with sorted keys and compact separators, UTF-8.
# Verify with:  python3 scout.py --verify report.json

def canonical_report_bytes(report):
    core = {k: v for k, v in report.items() if k != "receipt"}
    return json.dumps(core, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def make_receipt(report):
    digest = keccak256(canonical_report_bytes(report)).hex()
    return {
        "algorithm": "keccak-256",
        "report_hash": "0x" + digest,
        "canonicalization": ("report JSON without the 'receipt' field, "
                             "sorted keys, compact separators, UTF-8"),
        "verify_with": "python3 scout.py --verify <report.json>",
    }


def verify_receipt(report):
    receipt = report.get("receipt") or {}
    claimed = (receipt.get("report_hash") or "").lower()
    if not claimed:
        return False, "report has no receipt.report_hash"
    actual = "0x" + keccak256(canonical_report_bytes(report)).hex()
    return (actual == claimed), actual


def render_text(r):
    lines = []
    t = r["token"]
    lines.append("=" * 68)
    lines.append(f"BSC TOKEN SAFETY REPORT — {r['address']}")
    lines.append("=" * 68)
    lines.append(f"Token        : {t['name']} ({t['symbol']}), "
                 f"decimals {t['decimals']}, supply {t['total_supply']}")
    lines.append(f"Owner        : {t['owner']}")
    v = r["verification"]
    lines.append(f"Sourcify     : {v['status']}"
                 + (f" (verified {v['verified_at']})"
                    if v.get("verified_at") else ""))
    p = r["pools"]
    lines.append(f"Pools        : exists={p['exists']}  "
                 f"liquidity=${p['liquidity_usd']:,.2f}  "
                 f"24h volume=${p['volume_24h_usd']:,.2f}")
    for name in ("dexscreener", "geckoterminal"):
        s = p[name]
        if s is None:
            lines.append(f"  {name:<14}: NOT VERIFIED (API unreachable)")
        else:
            lines.append(f"  {name:<14}: {s['pairs_found']} pair(s), "
                         f"liquidity ${s['total_liquidity_usd']:,.2f}, "
                         f"24h vol ${s['total_volume_24h_usd']:,.2f}")
    g = r["goplus"]
    if g is None:
        lines.append("GoPlus       : NOT VERIFIED (API unreachable / "
                     "not indexed)")
    else:
        lines.append(
            f"GoPlus       : honeypot={g['is_honeypot']}  "
            f"buy tax={g['buy_tax']}  sell tax={g['sell_tax']}  "
            f"holders={g['holder_count']}  "
            f"top1={('%0.2f%%' % (g['top1_percent'] * 100))
                    if g['top1_percent'] is not None else 'n/a'}  "
            f"mintable={g['is_mintable']}  "
            f"take-back-ownership={g['can_take_back_ownership']}")
    if r["danger_signals"]:
        lines.append("Danger signals:")
        for s in r["danger_signals"]:
            lines.append(f"  [{s['severity']}] {s['signal']} "
                         f"({s['evidence']})")
    else:
        lines.append("Danger signals: none found")
    if r["not_verified"]:
        lines.append("NOT VERIFIED (checks that could not be performed):")
        for n in r["not_verified"]:
            lines.append(f"  - {n}")
    lines.append("-" * 68)
    lines.append(f"VERDICT: {r['verdict']}")
    for reason in r["reasons"]:
        lines.append(f"  * {reason}")
    receipt = r.get("receipt") or {}
    if receipt.get("report_hash"):
        lines.append(f"Receipt (keccak-256): {receipt['report_hash']}")
        lines.append("Verify: python3 scout.py --verify <report.json>")
    lines.append("=" * 68)
    return "\n".join(lines)


def main(argv):
    if "--verify" in argv:
        files = [a for a in argv[1:]
                 if not a.startswith("--") and a != "--verify"]
        if len(files) != 1:
            print("usage: python3 scout.py --verify <report.json>",
                  file=sys.stderr)
            return 2
        try:
            with open(files[0], encoding="utf-8") as fh:
                saved = json.load(fh)
        except Exception as exc:
            print(f"error: cannot read report: {exc}", file=sys.stderr)
            return 2
        ok, detail = verify_receipt(saved)
        if ok:
            print(f"RECEIPT MATCH — report is unaltered "
                  f"(hash {detail})")
            return 0
        print(f"RECEIPT MISMATCH — recomputed {detail}")
        return 1
    args = [a for a in argv[1:] if not a.startswith("--")]
    as_json = "--json" in argv
    if len(args) != 1:
        print("usage: python3 scout.py <address> [--json]",
              file=sys.stderr)
        return 2
    try:
        report = scan(args[0])
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if as_json:
        print(json.dumps(report, indent=2))
    else:
        print(render_text(report))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
