#!/usr/bin/env python3
"""Veille mempool / chaîne : détecte une dépense #71–#74 et extraie la pubkey."""
from __future__ import annotations

import json
import os
import time
import urllib.request
from datetime import datetime, timezone

WATCH_PATH = "/workspace/src/data/pubkey_watch.json"
TARGETS_ALL = [
    {"id": 71, "bits": 71, "address": "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU",
     "min_hex": "0x400000000000000000", "max_hex": "0x7fffffffffffffffff"},
    {"id": 72, "bits": 72, "address": "1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR",
     "min_hex": "0x800000000000000000", "max_hex": "0xffffffffffffffffff"},
    {"id": 73, "bits": 73, "address": "12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4",
     "min_hex": "0x1000000000000000000", "max_hex": "0x1ffffffffffffffffff"},
    {"id": 74, "bits": 74, "address": "1FWGcVDK3JGzCC3WtkYetULPszMaK2Jksv",
     "min_hex": "0x2000000000000000000", "max_hex": "0x3ffffffffffffffffff"},
]
# FOCUS71=1 → uniquement #71 (chemin optimal kangaroo dès pub)
TARGETS = (
    [t for t in TARGETS_ALL if t["id"] == 71]
    if os.environ.get("FOCUS71", "").strip() in ("1", "true", "yes")
    else TARGETS_ALL
)
UA = {"User-Agent": "puzzle-pubkey-watch/1.0"}


def http_json(url: str):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=18) as resp:
        return json.loads(resp.read().decode())


def extract_p2pkh_pubkey(vin: dict, address: str) -> str | None:
    prev = vin.get("prevout") or {}
    if prev.get("scriptpubkey_address") != address:
        return None
    asm = vin.get("scriptsig_asm") or ""
    for part in asm.split():
        if len(part) == 66 and part[:2] in ("02", "03"):
            return part
        if len(part) == 130 and part.startswith("04"):
            return part
    witness = vin.get("witness") or []
    for item in witness:
        if len(item) == 66 and item[:2] in ("02", "03"):
            return item
    return None


def scan_target(t: dict) -> dict:
    addr = t["address"]
    row = {
        "id": t["id"],
        "bits": t["bits"],
        "address": addr,
        "spent": 0,
        "leaked": False,
        "pubkey": None,
        "txid": None,
        "in_mempool": False,
        "error": None,
    }
    try:
        info = http_json(f"https://mempool.space/api/address/{addr}")
        row["spent"] = (
            info["chain_stats"]["spent_txo_count"]
            + info["mempool_stats"]["spent_txo_count"]
        )
        txs = http_json(f"https://mempool.space/api/address/{addr}/txs")
        try:
            mem = http_json(f"https://mempool.space/api/address/{addr}/txs/mempool")
        except Exception:
            mem = []
        for tx in list(mem) + list(txs):
            in_mem = not (tx.get("status") or {}).get("confirmed", False)
            for vin in tx.get("vin") or []:
                pub = extract_p2pkh_pubkey(vin, addr)
                if pub:
                    row["leaked"] = True
                    row["pubkey"] = pub
                    row["txid"] = tx.get("txid")
                    row["in_mempool"] = in_mem
                    return row
    except Exception as exc:
        row["error"] = str(exc)
    return row


def write_status(payload: dict) -> None:
    os.makedirs(os.path.dirname(WATCH_PATH), exist_ok=True)
    tmp = WATCH_PATH + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(payload, fh)
    os.replace(tmp, WATCH_PATH)


def launch_kangaroo(target: dict) -> None:
    pub = target.get("pubkey")
    if not pub:
        return
    cmd = (
        f"python3 /workspace/scripts/kangaroo_interval.py "
        f"--puzzle {target['id']} --pubkey {pub} "
        f">> /tmp/kangaroo_{target['id']}.log 2>&1 &"
    )
    os.system(cmd)


def main() -> None:
    launched = set()
    focus = os.environ.get("FOCUS71", "").strip() in ("1", "true", "yes")
    label = "#71 ONLY" if focus else "#71–#74"
    print(f"Veille pubkey {label} — mempool.space, 15s", flush=True)
    while True:
        rows = []
        leaked = []
        for t in TARGETS:
            row = scan_target(t)
            rows.append(row)
            if row["leaked"]:
                leaked.append(row)
            time.sleep(0.35)
        payload = {
            "running": True,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "leaked_count": len(leaked),
            "targets": rows,
        }
        write_status(payload)
        for row in leaked:
            key = (row["id"], row["pubkey"])
            if key not in launched:
                launched.add(key)
                print(f"FUITE #{row['id']} pubkey={row['pubkey']} tx={row['txid']}", flush=True)
                launch_kangaroo(row)
        time.sleep(15)


if __name__ == "__main__":
    main()
