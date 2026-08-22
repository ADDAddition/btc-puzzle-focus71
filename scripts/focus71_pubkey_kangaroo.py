#!/usr/bin/env python3
"""Focus optimal exclusif Puzzle #71.

Sans pubkey : veille mempool/chaîne ultra-serrée sur #71 uniquement.
Dès qu'une pubkey apparaît : lance kangaroo C (engine auto) sur
[2^70, 2^71-1] → log /tmp/kangaroo_71.log

Usage:
  python3 -u scripts/focus71_pubkey_kangaroo.py
  FOCUS71_PUBKEY=03... python3 -u scripts/focus71_pubkey_kangaroo.py   # si tu as déjà la pub
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
DATA = ROOT / "src" / "data"
STATUS = DATA / "focus71_status.json"
WATCH = DATA / "pubkey_watch.json"
PUB_OUT = DATA / "puzzle71_pubkey.json"

PUZZLE = {
    "id": 71,
    "bits": 71,
    "address": "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU",
    "lo": "400000000000000000",
    "hi": "7fffffffffffffffff",
    "lo_hex": "0x400000000000000000",
    "hi_hex": "0x7fffffffffffffffff",
}
SWEEP_DEST = "bc1qnd2f0ute9galrwc99up937p8nnm6exjalfcyrk"
MEMPOOL = "https://mempool.space/api"
UA = {"User-Agent": "focus71/1.0"}
POLL_SEC = 8


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def http_json(url: str):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode())


def atomic_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2))
    os.replace(tmp, path)


def extract_pubkey(vin: dict, address: str) -> str | None:
    prev = vin.get("prevout") or {}
    if prev.get("scriptpubkey_address") != address:
        return None
    asm = vin.get("scriptsig_asm") or ""
    for part in asm.split():
        if len(part) == 66 and part[:2] in ("02", "03"):
            return part
        if len(part) == 130 and part.startswith("04"):
            return part
    for item in vin.get("witness") or []:
        if len(item) == 66 and item[:2] in ("02", "03"):
            return item
        if len(item) == 130 and item.startswith("04"):
            return item
    return None


def scan_pubkey() -> dict:
    addr = PUZZLE["address"]
    row = {
        "id": 71,
        "address": addr,
        "spent": 0,
        "leaked": False,
        "pubkey": None,
        "txid": None,
        "in_mempool": False,
        "error": None,
        "checked_at": utc(),
    }
    try:
        info = http_json(f"{MEMPOOL}/address/{addr}")
        row["spent"] = (
            info["chain_stats"]["spent_txo_count"]
            + info["mempool_stats"]["spent_txo_count"]
        )
        txs = http_json(f"{MEMPOOL}/address/{addr}/txs")
        try:
            mem = http_json(f"{MEMPOOL}/address/{addr}/txs/mempool")
        except Exception:
            mem = []
        for tx in list(mem) + list(txs):
            in_mem = not (tx.get("status") or {}).get("confirmed", False)
            for vin in tx.get("vin") or []:
                pub = extract_pubkey(vin, addr)
                if pub:
                    row.update(
                        leaked=True,
                        pubkey=pub,
                        txid=tx.get("txid"),
                        in_mempool=in_mem,
                    )
                    return row
    except Exception as e:
        row["error"] = str(e)
    return row


def launch_kangaroo(pubkey: str) -> subprocess.Popen:
    log = Path("/tmp/kangaroo_71.log")
    cmd = [
        sys.executable,
        str(SCRIPTS / "kangaroo_interval.py"),
        "--puzzle",
        "71",
        "--pubkey",
        pubkey,
        "--engine",
        "auto",
    ]
    # Prefer C binary directly if present (fastest path)
    cbin = SCRIPTS / "kangaroo"
    if cbin.exists() and os.access(cbin, os.X_OK):
        cmd = [
            str(cbin),
            "--pubkey",
            pubkey,
            "--lo",
            PUZZLE["lo"],
            "--hi",
            PUZZLE["hi"],
        ]
    print(f"LAUNCH kangaroo #71 → {' '.join(cmd)}", flush=True)
    fh = open(log, "a", buffering=1)
    fh.write(f"\n===== start {utc()} =====\n")
    return subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT, cwd=str(ROOT))


def write_focus_status(extra: dict) -> None:
    payload = {
        "mode": "FOCUS71_ONLY",
        "optimal": "watch→kangaroo_C (pas de hash160 brute, pas de #140)",
        "puzzle": PUZZLE,
        "sweep_dest_prepare_only": SWEEP_DEST,
        "broadcast": False,
        "updated_at": utc(),
        **extra,
    }
    atomic_write(STATUS, payload)
    # keep pubkey_watch.json compatible (single target)
    atomic_write(
        WATCH,
        {
            "running": True,
            "focus": 71,
            "checked_at": utc(),
            "leaked_count": 1 if extra.get("pubkey") else 0,
            "targets": [
                {
                    "id": 71,
                    "bits": 71,
                    "address": PUZZLE["address"],
                    "spent": extra.get("spent", 0),
                    "leaked": bool(extra.get("pubkey")),
                    "pubkey": extra.get("pubkey"),
                    "txid": extra.get("txid"),
                    "in_mempool": extra.get("in_mempool", False),
                    "error": extra.get("error"),
                }
            ],
        },
    )


def main() -> None:
    env_pub = os.environ.get("FOCUS71_PUBKEY", "").strip() or None
    print("=== FOCUS #71 ONLY (optimal: pubkey → kangaroo C) ===", flush=True)
    print(f"address={PUZZLE['address']}", flush=True)
    print(f"range=[{PUZZLE['lo_hex']}, {PUZZLE['hi_hex']}]", flush=True)
    if env_pub:
        print(f"pubkey from env: {env_pub[:24]}…", flush=True)

    kangaroo_proc: subprocess.Popen | None = None
    launched_pub: str | None = None

    while True:
        if env_pub:
            row = {
                "leaked": True,
                "pubkey": env_pub,
                "txid": "env",
                "spent": -1,
                "in_mempool": False,
                "error": None,
            }
        else:
            row = scan_pubkey()

        pub = row.get("pubkey")
        write_focus_status(
            {
                "pubkey": pub,
                "txid": row.get("txid"),
                "spent": row.get("spent"),
                "in_mempool": row.get("in_mempool"),
                "error": row.get("error"),
                "kangaroo_pid": kangaroo_proc.pid if kangaroo_proc else None,
                "kangaroo_running": bool(
                    kangaroo_proc and kangaroo_proc.poll() is None
                ),
                "phase": "kangaroo" if pub else "waiting_pubkey",
            }
        )

        if pub and pub != launched_pub:
            atomic_write(
                PUB_OUT,
                {
                    "puzzle": 71,
                    "address": PUZZLE["address"],
                    "pubkey": pub,
                    "txid": row.get("txid"),
                    "range": {"lo": PUZZLE["lo_hex"], "hi": PUZZLE["hi_hex"]},
                    "KANGAROO_READY": True,
                    "found_at": utc(),
                    "sweep_dest_prepare_only": SWEEP_DEST,
                },
            )
            kangaroo_proc = launch_kangaroo(pub)
            launched_pub = pub
            print(f"FUITE/READY pubkey={pub} kangaroo pid={kangaroo_proc.pid}", flush=True)
            if env_pub:
                # env mode: wait on kangaroo then exit
                kangaroo_proc.wait()
                print(f"kangaroo exit={kangaroo_proc.returncode}", flush=True)
                return

        if not pub:
            print(f"[{utc()}] wait pubkey #71 spent={row.get('spent')}", flush=True)

        time.sleep(POLL_SEC)


if __name__ == "__main__":
    main()
