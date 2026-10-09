#!/usr/bin/env python3
"""Compile ad/tracker blocklists into the compact ADBK binary the ESP32-S3
AdBlock firmware loads into PSRAM.

Format (little-endian):
    magic[4] = b"ADBK"
    version  = 1 (u8)
    hashBits = 40 (u8)
    reserved = 0 (u16)
    count    = u32
    count * 5-byte little-endian FNV-1a/40 hashes, sorted ascending

The 40-bit FNV-1a hash here MUST match fnv40() in src/blocklist.cpp.

Supported source formats (auto-detected per line):
    - hosts files:   "0.0.0.0 example.com"  /  "127.0.0.1 example.com"
    - plain domains: "example.com"
    - Adblock/AdGuard basic rules: "||example.com^"  (block)
                                   "@@||example.com^" (allow / exception)
Lines it cannot express as a bare-domain hash (regex, wildcards, element
hiding "##", options after "$") are skipped and counted.

Usage:
    python build_blocklist.py -o blocklist.bin [SOURCE ...]
SOURCE may be a URL (http/https) or a local file. With no sources, a sensible
default set (StevenBlack hosts + Hagezi light) is used.
"""
import argparse
import re
import struct
import sys

try:
    import requests
except ImportError:
    requests = None

FNV64_OFFSET = 0xCBF29CE484222325
FNV64_PRIME = 0x100000001B3
MASK40 = (1 << 40) - 1

DEFAULT_SOURCES = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
]

# A valid DNS domain (letters/digits/hyphen labels, 2+ labels).
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,}$")


def fnv40(domain: str) -> int:
    h = FNV64_OFFSET
    for b in domain.lower().encode("utf-8", "ignore"):
        h ^= b
        h = (h * FNV64_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h & MASK40


def clean_domain(d: str) -> str:
    d = d.strip().lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    return d


def parse_line(line: str, block: set, allow: set) -> bool:
    """Add any domain found on `line` to block/allow. Return False if skipped."""
    line = line.strip()
    if not line or line[0] in "#!":
        return True  # comment / blank, not a skip

    # Adblock / AdGuard exception: @@||domain^
    if line.startswith("@@"):
        m = re.match(r"^@@\|\|([a-z0-9_.-]+)\^?", line, re.I)
        if m and "*" not in m.group(1):
            d = clean_domain(m.group(1))
            if DOMAIN_RE.match(d):
                allow.add(d)
                return True
        return False

    # Adblock / AdGuard block: ||domain^  (reject anything with options/wildcards)
    if line.startswith("||"):
        if "$" in line or "*" in line:
            return False
        m = re.match(r"^\|\|([a-z0-9_.-]+)\^?$", line, re.I)
        if m:
            d = clean_domain(m.group(1))
            if DOMAIN_RE.match(d):
                block.add(d)
                return True
        return False

    # Cosmetic / element-hiding rules and other unsupported syntax.
    if "##" in line or "#@#" in line or "/" in line or "*" in line:
        return False

    # hosts file:  "0.0.0.0 domain"  or  "127.0.0.1 domain [domain2 ...]"
    parts = line.split()
    if len(parts) >= 2 and (parts[0] in ("0.0.0.0", "127.0.0.1", "::") or
                            re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0])):
        added = False
        for tok in parts[1:]:
            d = clean_domain(tok)
            if DOMAIN_RE.match(d):
                block.add(d)
                added = True
        return added

    # plain domain, one per line
    d = clean_domain(parts[0]) if parts else ""
    if DOMAIN_RE.match(d):
        block.add(d)
        return True
    return False


def load_source(src: str) -> str:
    if src.startswith(("http://", "https://")):
        if requests is None:
            sys.exit("requests not installed: pip install -r tools/requirements.txt")
        print(f"  fetching {src}")
        r = requests.get(src, timeout=60)
        r.raise_for_status()
        return r.text
    print(f"  reading {src}")
    with open(src, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def main() -> None:
    ap = argparse.ArgumentParser(description="Compile blocklists into ADBK .bin")
    ap.add_argument("-o", "--output", default="data/blocklist.bin")
    ap.add_argument("sources", nargs="*", help="URLs or files (default: StevenBlack + Hagezi light)")
    ap.add_argument("--allow-missing", action="store_true",
                    help="continue if a source fails to download")
    args = ap.parse_args()

    sources = args.sources or DEFAULT_SOURCES
    block: set = set()
    allow: set = set()
    skipped = 0

    print("Sources:")
    for src in sources:
        try:
            text = load_source(src)
        except Exception as e:  # noqa: BLE001
            if args.allow_missing:
                print(f"  !! skipping {src}: {e}")
                continue
            sys.exit(f"failed to load {src}: {e} (use --allow-missing to ignore)")
        for line in text.splitlines():
            if not parse_line(line, block, allow):
                skipped += 1

    domains = block - allow
    print(f"\nParsed: {len(block):,} block, {len(allow):,} allow, "
          f"{skipped:,} unsupported/skipped lines")
    print(f"Final:  {len(domains):,} domains after applying exceptions")

    hashes = sorted({fnv40(d) for d in domains})
    collisions = len(domains) - len(hashes)
    if collisions:
        print(f"Note:   {collisions} hash collision(s) at 40 bits (acceptable)")

    out = args.output
    import os
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "wb") as f:
        f.write(b"ADBK")
        f.write(struct.pack("<BBH", 1, 40, 0))
        f.write(struct.pack("<I", len(hashes)))
        for h in hashes:
            f.write(h.to_bytes(5, "little"))

    size = 12 + len(hashes) * 5
    print(f"\nWrote {out}: {len(hashes):,} hashes, {size:,} bytes "
          f"({size/1024/1024:.2f} MB)")


if __name__ == "__main__":
    main()
