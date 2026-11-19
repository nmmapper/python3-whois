"""registrar_normalizer.py
Normalize registrar names from different WHOIS parsers to the
canonical IANA name, e.g.:

    "Markmonitor Inc."  -> "MarkMonitor Inc."
    "MARKMONITOR INC."  -> "MarkMonitor Inc."
    "【entity-Godaddy¦canonical_name=GoDaddy】"           -> "【entity-GoDaddy.com, LLC¦canonical_name=GoDaddy】"
    "Namecheap, Inc."   -> "NameCheap, Inc."

Why not .title()? .title() destroys internal capitals:
【entity-GoDaddy¦canonical_name=GoDaddy】 -> 【entity-Godaddy¦canonical_name=GoDaddy】, NameCheap -> Namecheap, eNom -> Enom.
The canonical casing must come from an authoritative list (IANA),
not from string manipulation.
"""
from __future__ import annotations

import csv
import difflib
import json
import re
import time
import unicodedata
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

IANA_CSV_URL = "https://www.iana.org/assignments/registrar-ids/registrar-ids-1.csv"
CACHE_FILE = Path.home() / ".cache" / "registrar-ids.json"
CACHE_TTL_SECONDS = 7 * 24 * 3600  # 1 week

# [STRIPPED 75 bytes]
# 1. Fallback: used when offline / IANA download fails.
#    Full list is fetched from IANA at runtime. Keep this small and correct.
# [STRIPPED 75 bytes]
FALLBACK_CANONICAL: Dict[str, str] = {
    "292": "MarkMonitor Inc.",
    "146": "【entity-GoDaddy.com, LLC¦canonical_name=GoDaddy】",
    "1068": "NameCheap, Inc.",
    "69": "Tucows Domains Inc.",
    "1910": "Cloudflare, Inc.",
    "1861": "Porkbun LLC",
    "48": "eNom, LLC",
    "2": "Network Solutions, LLC",
    "9": "Register.com - Network Solutions, LLC",
    "81": "Gandi SAS",
    "83": "IONOS SE",
    "144": "Alldomains, LLC",
    "65": "DomainPeople, Inc.",
    "468": "Amazon Registrar, Inc.",
    "134": "BB-Online UK Limited",
}

# Hand aliases for names WHOIS commonly shortens or rebrands.
# Keys here are already normalized (see _key()).
ALIASES: Dict[str, str] = {
    "godaddy": "GoDaddy.com, LLC",
    "go daddy": "GoDaddy.com, LLC",
    "go daddy com": "GoDaddy.com, LLC",
    "namecheap": "NameCheap, Inc.",
    "namecheap com": "NameCheap, Inc.",
    "markmonitor": "MarkMonitor Inc.",
    "enom": "eNom, LLC",
    "enom com": "eNom, LLC",
    "tucows": "Tucows Domains Inc.",
    "tucows domains": "Tucows Domains Inc.",
    "opensrs": "Tucows Domains Inc.",
    "cloudflare": "Cloudflare, Inc.",
    "porkbun": "Porkbun LLC",
    "gandi": "Gandi SAS",
    "gandi net": "Gandi SAS",
    "ionos": "IONOS SE",
    "1 and 1 ionos": "IONOS SE",
    "1and1": "IONOS SE",
    "network solutions": "Network Solutions, LLC",
    "netsol": "Network Solutions, LLC",
    "amazon registrar": "Amazon Registrar, Inc.",
    "google": "Google LLC",
    "key systems": "Key-Systems GmbH",
    "keysystems": "Key-Systems GmbH",
    "squarespace domains": "Squarespace Domains LLC",
    "hover": "Tucows Domains Inc.",
}

LEGAL_SUFFIX_MAP = {
    "incorporated": "inc",
    "corporation": "corp",
    "limited": "ltd",
    "company": "co",
    "llc": "llc",
    "llp": "llp",
    "plc": "plc",
}

# Tokens stripped to get the "core" brand name: MarkMonitor Inc. -> markmonitor
LEGAL_SUFFIX_TOKENS = {
    "inc", "llc", "ltd", "corp", "co", "llp", "plc", "gmbh", "sarl",
    "sas", "se", "sa", "ag", "bv", "pty", "srl", "slu", "sro", "oy",
}

# [STRIPPED 75 bytes]
# 2. Normalization
# [STRIPPED 75 bytes]
def _key(name: str) -> str:
    """Lossy key for matching: case, punctuation, accents, suffix spelling removed."""
    if not name:
        return ""
    s = unicodedata.normalize("NFKD", str(name))
    s = s.encode("ascii", "ignore").decode("ascii")  # strip accents
    s = s.casefold()
    s = s.replace("&", " and ").replace("@", " at ")
    s = re.sub(r"[^a-z0-9]+", " ", s)  # punctuation -> space
    s = re.sub(r"\s+", " ", s).strip()
    tokens = [LEGAL_SUFFIX_MAP.get(t, t) for t in s.split()]
    s = " ".join(tokens)
    # "d / b / a" -> "dba" after punctuation stripping
    s = s.replace("d b a", "dba").replace("f k a", "fka")
    return s

def _core_key(normalized: str) -> str:
    """Key without trailing legal suffix: 'markmonitor inc' -> 'markmonitor'."""
    tokens = normalized.split()
    while tokens and tokens[-1] in LEGAL_SUFFIX_TOKENS:
        tokens.pop()
    return " ".join(tokens)

def _dba_keys(normalized: str) -> list[str]:
    """IANA names like 'GMO Internet Group Inc dba Onamae.com' are often
    returned in WHOIS as just 'Onamae.com'. Index both sides."""
    keys = []
    for marker in (" dba ", " fka ", " aka "):
        if marker in f" {normalized} ":
            dba_part = normalized.split(marker.strip(), 1)[-1].strip()
            if dba_part:
                keys.append(dba_part)
                keys.append(_core_key(dba_part))
    return keys

def _first_str(value: Any) -> Optional[str]:
    """WHOIS libs return registrar as str, list, bytes, or None."""
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", "ignore").strip() or None
    if isinstance(value, (list, tuple, set)):
        for item in value:
            s = _first_str(item)
            if s:
                return s
        return None
    s = str(value).strip()
    return s or None

# [STRIPPED 75 bytes]
# 3. Canonical source: IANA
# [STRIPPED 75 bytes]
def load_canonical() -> Dict[str, str]:
    """Return {iana_id: canonical_name}. Cache -> IANA CSV -> fallback."""
    # 1. Fresh cache
    try:
        if CACHE_FILE.exists() and (time.time() - CACHE_FILE.stat().st_mtime) < CACHE_TTL_SECONDS:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            if data:
                return {str(k): str(v) for k, v in data.items()}
    except Exception:
        pass

    # 2. Download IANA CSV
    try:
        with urllib.request.urlopen(IANA_CSV_URL, timeout=15) as resp:
            text = resp.read().decode("utf-8", "ignore")
        reader = csv.DictReader(text.splitlines())
        # Columns are: ID, Registrar Name, Status, RDAP Base URL
        # Be tolerant to header casing / whitespace.
        result: Dict[str, str] = {}
        for row in reader:
            norm_row = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
            iana_id = norm_row.get("id", "")
            name = norm_row.get("registrar name", "")
            status = norm_row.get("status", "")
            if not iana_id or not name:
                continue
            # Prefer Accredited over Terminated if an ID ever repeats.
            if iana_id in result and status.lower() != "accredited":
                continue
            result[iana_id] = name
        if result:
            try:
                CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
                CACHE_FILE.write_text(json.dumps(result), encoding="utf-8")
            except Exception:
                pass
            return result
    except Exception:
        pass

    # 3. Offline fallback
    return dict(FALLBACK_CANONICAL)

class RegistrarNormalizer:
    def __init__(self, canonical_by_id: Optional[Dict[str, str]] = None):
        self.by_id: Dict[str, str] = canonical_by_id or load_canonical()
        self.canonical_names: set[str] = set(self.by_id.values())

        # Index: normalized key -> canonical name
        self.index: Dict[str, str] = {}
        for name in self.canonical_names:
            k = _key(name)
            self._add(k, name)
            self._add(_core_key(k), name)
            for dba_k in _dba_keys(k):
                self._add(dba_k, name)

        # Aliases override / extend the index
        for alias_key, canonical in ALIASES.items():
            self._add(alias_key, canonical)
            self._add(_core_key(alias_key), canonical)

    def _add(self, key: str, canonical: str) -> None:
        if not key:
            return
        # First write wins, so IANA order + explicit aliases stay stable.
        # Do not let a Terminated duplicate overwrite an Accredited one:
        # caller already prefers Accredited in load_canonical().
        self.index.setdefault(key, canonical)

    # -- public API -----------------------------------------------------
    def by_iana_id(self, iana_id: Any) -> Optional[str]:
        if iana_id is None:
            return None
        # WHOIS sometimes gives "292" as int, "292 ", or "292 - MarkMonitor"
        m = re.search(r"\d+", str(iana_id))
        if not m:
            return None
        return self.by_id.get(m.group(0))

    def normalize(self, raw: Any, fallback_to_raw: bool = True) -> Optional[str]:
        raw_str = _first_str(raw)
        if not raw_str:
            return None

        # Fast path: already canonical
        if raw_str in self.canonical_names:
            return raw_str

        k = _key(raw_str)
        if k in self.index:
            return self.index[k]

        core = _core_key(k)
        if core in self.index:
            return self.index[core]

        # Fuzzy: only on miss, high cutoff to avoid false merges.
        # e.g. "Go Daddy .com LLC" -> "godaddy com llc"
        for candidate_key in (k, core):
            matches = difflib.get_close_matches(
                candidate_key, self.index.keys(), n=1, cutoff=0.88
            )
            if matches:
                return self.index[matches[0]]

        return raw_str if fallback_to_raw else None

# Module-level singleton, so callers do not re-download IANA every call.
_DEFAULT = RegistrarNormalizer()

def normalize_registrar(raw: Any, fallback_to_raw: bool = True) -> Optional[str]:
    return _DEFAULT.normalize(raw, fallback_to_raw=fallback_to_raw)

def normalize_by_iana_id(iana_id: Any) -> Optional[str]:
    return _DEFAULT.by_iana_id(iana_id)

# [STRIPPED 75 bytes]
# 4. Wrapper for your two libraries
# [STRIPPED 75 bytes]
def _extract(data: Any, *keys: str) -> Optional[str]:
    """Get a field from dict-like or attribute-style WHOIS objects."""
    if data is None:
        return None
    for key in keys:
        try:
            if isinstance(data, dict) and key in data:
                val = _first_str(data.get(key))
                if val:
                    return val
        except Exception:
            pass
        try:
            val = _first_str(getattr(data, key, None))
            if val:
                return val
        except Exception:
            pass
    return None

def get_canonical_registrar(domain: str) -> Optional[str]:
    """Query both libs, normalize, and reconcile.

    Preference order:
      1. IANA ID (unambiguous) from either lib
      2. Normalized registrar name (both libs should agree after normalization)
      3. Raw value if normalization has no match
    """
    results: list[str] = []
    iana_ids: list[str] = []

    # python-whois: whois.whois(d, quiet=True)
    try:
        import whois as pywhois

        data = pywhois.whois(domain, quiet=True)
        iana = _extract(data, "registrar_iana_id", "iana_id", "registrar_id")
        if iana:
            iana_ids.append(iana)
        reg = _extract(data, "registrar")
        if reg:
            results.append(reg)
    except Exception:
        pass

    # whois3: Whois(d).get_whois()
    try:
        import whois3

        data = whois3.Whois(domain).get_whois()
        iana = _extract(data, "registrar_iana_id", "iana_id", "registrar_id")
        if iana:
            iana_ids.append(iana)
        reg = _extract(data, "registrar")
        if reg:
            results.append(reg)
    except Exception:
        pass

    # IANA ID wins
    for iana in iana_ids:
        canonical = normalize_by_iana_id(iana)
        if canonical:
            return canonical

    # Normalize names, they should now agree
    normalized = [normalize_registrar(r) for r in results]
    normalized = [n for n in normalized if n]
    if normalized:
        # If both libs agree after normalization, that is the answer.
        # If they disagree, return the first - it is a real data conflict,
        # not a casing artifact.
        return normalized[0]

    return None

if __name__ == "__main__":
    tests = [
        "Markmonitor Inc.",
        "MarkMonitor Inc.",
        "MARKMONITOR INC",
        "MarkMonitor, Inc.",
        "markmonitor",
        "GoDaddy",
        "GODADDY.COM, LLC",
        "Go Daddy LLC",
        "Namecheap Inc.",
        "NAMECHEAP, INC.",
        "eNom, LLC",
        "ENOM LLC",
        "Tucows Domains Inc.",
        "TUCOWS",
        "Cloudflare Inc.",
        "CLOUDFLARE, INC.",
        "Porkbun LLC",
        "PORKBUN",
        "Network Solutions, LLC",
        "NETWORK SOLUTIONS LLC",
    ]
    for t in tests:
        print(f"{t!r:30} -> {normalize_registrar(t)!r}")

    # Your original case
    print()
    print(get_canonical_registrar("workdaysuvsite.com"))
