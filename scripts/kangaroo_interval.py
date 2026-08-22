#!/usr/bin/env python3
"""Pollard Kangaroo borné. Préfère binaire C, sinon coincurve, sinon Python pur.

Prouvé sur ~24 bits ; prêt si une pubkey #71–#74 fuit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)
STATUS = "/workspace/src/data/kangaroo_status.json"
SCRIPTS = Path(__file__).resolve().parent
C_BIN = SCRIPTS / "kangaroo"
LOCK_DIR = Path("/tmp/kangaroo_locks")


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2:
        return None
    if x1 == x2:
        lam = (3 * x1 * x1 * pow(2 * y1, P - 2, P)) % P
    else:
        lam = ((y2 - y1) * pow(x2 - x1, P - 2, P)) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def point_mul(k, point=G):
    result = None
    addend = point
    kk = k % N
    while kk:
        if kk & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        kk >>= 1
    return result


def parse_pubkey(hex_str: str):
    raw = bytes.fromhex(hex_str)
    if raw[0] == 4 and len(raw) == 65:
        return (int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:], "big"))
    if raw[0] not in (2, 3) or len(raw) != 33:
        raise ValueError("pubkey invalide")
    x = int.from_bytes(raw[1:], "big")
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if (y % 2 == 0) != (raw[0] == 2):
        y = (-y) % P
    return (x, y)


def build_jump_table(max_log: int):
    table = [G]
    for _ in range(1, max_log):
        table.append(point_add(table[-1], table[-1]))
    return table


def jump_from(pt, table):
    h = hashlib.sha256(pt[0].to_bytes(32, "big")).digest()
    idx = h[0] % len(table)
    return point_add(pt, table[idx]), 1 << idx


def is_distinguished(pt, bits: int) -> bool:
    return (pt[0] & ((1 << bits) - 1)) == 0


def write_status(payload: dict) -> None:
    tmp = STATUS + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(payload, fh)
    os.replace(tmp, STATUS)


def _try_coincurve():
    try:
        from coincurve import PrivateKey, PublicKey

        return PrivateKey, PublicKey
    except ImportError:
        return None, None


def kangaroo_coincurve(pubkey_hex: str, lo: int, hi: int, limit: int = 5_000_000) -> dict:
    PrivateKey, PublicKey = _try_coincurve()
    if PrivateKey is None:
        raise RuntimeError("coincurve unavailable")

    target = PublicKey(bytes.fromhex(pubkey_hex))
    width = hi - lo + 1
    mean_log = max(8, min(32, width.bit_length() // 2))
    dp_bits = max(4, mean_log // 5)
    table_pubs = [PrivateKey.from_int(1 << i).public_key for i in range(mean_log)]
    tame: dict[bytes, int] = {}
    t_pt = PrivateKey.from_int(hi).public_key
    t_dist = 0
    w_pt = target
    w_dist = 0
    t0 = time.time()
    steps = 0
    found = None

    def jump(pt):
        x = pt.point()[0].to_bytes(32, "big")
        idx = hashlib.sha256(x).digest()[0] % len(table_pubs)
        return PublicKey.combine_keys([pt, table_pubs[idx]]), 1 << idx

    def is_dp(pt) -> bool:
        return (pt.point()[0] & ((1 << dp_bits) - 1)) == 0

    while steps < limit and found is None:
        t_pt, j = jump(t_pt)
        t_dist += j
        if is_dp(t_pt):
            tame[t_pt.format(compressed=True)] = t_dist
        w_pt, j = jump(w_pt)
        w_dist += j
        if is_dp(w_pt):
            key = w_pt.format(compressed=True)
            if key in tame:
                k = (hi + tame[key] - w_dist) % N
                if lo <= k <= hi:
                    cand = PrivateKey.from_int(k).public_key
                    if cand.format(compressed=True) == target.format(compressed=True):
                        found = k
        steps += 2
        if steps % 20000 == 0:
            el = time.time() - t0
            write_status({
                "running": True,
                "steps": steps,
                "elapsed": round(el, 2),
                "found": False,
                "dp_tame": len(tame),
                "ops_per_s": round(steps / el) if el > 0 else 0,
                "engine": "coincurve",
            })

    el = time.time() - t0
    payload = {
        "running": False,
        "steps": steps,
        "elapsed": round(el, 2),
        "found": found is not None,
        "key_hex": hex(found) if found is not None else None,
        "dp_tame": len(tame),
        "ops_per_s": round(steps / el) if el > 0 else 0,
        "engine": "coincurve",
    }
    write_status(payload)
    return payload


def kangaroo_pure(pubkey_hex: str, lo: int, hi: int, limit: int = 5_000_000) -> dict:
    target = parse_pubkey(pubkey_hex)
    width = hi - lo + 1
    mean_log = max(8, min(32, width.bit_length() // 2))
    dp_bits = max(4, mean_log // 5)
    table = build_jump_table(mean_log)
    tame: dict[int, int] = {}
    t_pt = point_mul(hi)
    t_dist = 0
    w_pt = target
    w_dist = 0
    t0 = time.time()
    steps = 0
    found = None
    while steps < limit and found is None:
        t_pt, j = jump_from(t_pt, table)
        t_dist += j
        if is_distinguished(t_pt, dp_bits):
            tame[t_pt[0]] = t_dist
        w_pt, j = jump_from(w_pt, table)
        w_dist += j
        if is_distinguished(w_pt, dp_bits) and w_pt[0] in tame:
            k = (hi + tame[w_pt[0]] - w_dist) % N
            if lo <= k <= hi and point_mul(k) == target:
                found = k
        steps += 2
        if steps % 20000 == 0:
            el = time.time() - t0
            write_status({
                "running": True,
                "steps": steps,
                "elapsed": round(el, 2),
                "found": found is not None,
                "dp_tame": len(tame),
                "ops_per_s": round(steps / el) if el > 0 else 0,
                "engine": "python_pure",
            })
    el = time.time() - t0
    payload = {
        "running": False,
        "steps": steps,
        "elapsed": round(el, 2),
        "found": found is not None,
        "key_hex": hex(found) if found is not None else None,
        "dp_tame": len(tame),
        "ops_per_s": round(steps / el) if el > 0 else 0,
        "engine": "python_pure",
    }
    write_status(payload)
    return payload


def ensure_c_binary() -> Path | None:
    if C_BIN.is_file() and os.access(C_BIN, os.X_OK):
        return C_BIN
    src = SCRIPTS / "kangaroo_c.c"
    if not src.is_file():
        return None
    try:
        subprocess.run(
            ["gcc", "-O3", "-march=native", "-o", str(C_BIN), str(src)],
            check=True,
            capture_output=True,
            timeout=120,
        )
        return C_BIN if C_BIN.is_file() else None
    except (subprocess.SubprocessError, OSError):
        return None


def kangaroo_c(pubkey_hex: str, lo: int, hi: int, limit: int = 5_000_000) -> dict:
    binary = ensure_c_binary()
    if binary is None:
        raise RuntimeError("kangaroo C binary unavailable")
    cmd = [
        str(binary),
        "--pubkey",
        pubkey_hex,
        "--lo",
        hex(lo),
        "--hi",
        hex(hi),
        "--limit",
        str(limit),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=None)
    if Path(STATUS).is_file():
        with open(STATUS) as fh:
            try:
                return json.load(fh)
            except json.JSONDecodeError:
                pass
    line = (proc.stdout or "").strip().splitlines()
    if line:
        try:
            return json.loads(line[-1])
        except json.JSONDecodeError:
            pass
    raise RuntimeError(f"kangaroo C failed: {proc.stderr or proc.stdout}")


def kangaroo(pubkey_hex: str, lo: int, hi: int, limit: int = 5_000_000, engine: str = "auto") -> dict:
    width = hi - lo + 1
    bits = width.bit_length() - 1
    engines = []
    if engine == "auto":
        if ensure_c_binary():
            engines.append("c")
        if _try_coincurve()[0] is not None:
            engines.append("coincurve")
        engines.append("python_pure")
    else:
        engines = [engine]

    # Full #71 width is fine for C/coincurve launch (no artificial 2^40 block).
    # Pure Python still discouraged above 40 bits.
    last_err = None
    for eng in engines:
        if eng == "python_pure" and bits > 40:
            last_err = f"python_pure bloqué pour width 2^{bits}"
            continue
        try:
            if eng == "c":
                return kangaroo_c(pubkey_hex, lo, hi, limit)
            if eng == "coincurve":
                return kangaroo_coincurve(pubkey_hex, lo, hi, limit)
            return kangaroo_pure(pubkey_hex, lo, hi, limit)
        except Exception as exc:  # noqa: BLE001 — try next engine
            last_err = str(exc)
            continue
    write_status({
        "running": False,
        "blocked": True,
        "reason": last_err or "no engine",
        "pubkey": pubkey_hex,
        "found": False,
    })
    return {"found": False, "blocked": True, "reason": last_err}


def acquire_launch_lock(puzzle_id: int, pubkey: str) -> bool:
    """True if this process owns the launch (dedup watchers / sweep_continue)."""
    LOCK_DIR.mkdir(parents=True, exist_ok=True)
    path = LOCK_DIR / f"puzzle_{puzzle_id}.lock"
    payload = f"{pubkey}\n{os.getpid()}\n{time.time()}\n"
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        with os.fdopen(fd, "w") as fh:
            fh.write(payload)
        return True
    except FileExistsError:
        try:
            existing = path.read_text().splitlines()
            if existing and existing[0].strip() == pubkey:
                return False
            # Different pub (re-leak?) — allow replace if old pid dead
            old_pid = int(existing[1]) if len(existing) > 1 else 0
            if old_pid and Path(f"/proc/{old_pid}").exists():
                return False
            path.write_text(payload)
            return True
        except (OSError, ValueError):
            return False


def bench_engines() -> dict:
    results = {}
    # Pure python add rate
    pt = G
    t0 = time.time()
    n = 3000
    for _ in range(n):
        pt = point_add(pt, G)
    el = time.time() - t0
    results["python_pure_add_ops_s"] = round(n / el) if el > 0 else 0

    PrivateKey, PublicKey = _try_coincurve()
    if PrivateKey is not None:
        pts = [PrivateKey.from_int(i).public_key for i in range(1, 33)]
        a = pts[0]
        t0 = time.time()
        n = 50000
        for i in range(n):
            a = PublicKey.combine_keys([a, pts[i % 32]])
        el = time.time() - t0
        results["coincurve_add_ops_s"] = round(n / el) if el > 0 else 0

    binary = ensure_c_binary()
    if binary is not None:
        proc = subprocess.run([str(binary), "--bench"], capture_output=True, text=True, timeout=60)
        try:
            results["kangaroo_c"] = json.loads(proc.stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            results["kangaroo_c_raw"] = proc.stdout

    # Toy solve with preferred engine
    secret = 0x10000A5CD68
    lo, hi = 0x10000000000, 0x10000FFFFFF
    pub = point_mul(secret)
    prefix = b"\x02" if pub[1] % 2 == 0 else b"\x03"
    pub_hex = (prefix + pub[0].to_bytes(32, "big")).hex()
    toy = kangaroo(pub_hex, lo, hi, limit=400000, engine="auto")
    results["toy"] = toy
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--puzzle", type=int, default=0)
    parser.add_argument("--pubkey", default="")
    parser.add_argument("--lo", default="")
    parser.add_argument("--hi", default="")
    parser.add_argument("--toy", action="store_true")
    parser.add_argument("--bench", action="store_true")
    parser.add_argument("--limit", type=int, default=400000)
    parser.add_argument("--engine", default="auto", choices=["auto", "c", "coincurve", "python_pure"])
    args = parser.parse_args()

    if args.bench:
        print(json.dumps(bench_engines(), indent=2))
        return

    if args.toy:
        secret = 0x10000A5CD68
        lo, hi = 0x10000000000, 0x10000FFFFFF
        pub = point_mul(secret)
        prefix = b"\x02" if pub[1] % 2 == 0 else b"\x03"
        pub_hex = (prefix + pub[0].to_bytes(32, "big")).hex()
        print(f"TOY secret={hex(secret)} range=2^24")
        result = kangaroo(pub_hex, lo, hi, limit=args.limit, engine=args.engine)
        print(json.dumps(result, indent=2))
        return

    if not args.pubkey:
        print("Aucune pubkey — Kangaroo en attente d'une fuite mempool.")
        write_status({"running": False, "waiting_leak": True, "found": False})
        return

    if args.puzzle:
        with open("/workspace/src/data/unsolved_targets.json") as fh:
            targets = json.load(fh)
        t = next(x for x in targets if x["id"] == args.puzzle)
        lo = int(t["min_hex"], 16)
        hi = int(t["max_hex"], 16)
        if not acquire_launch_lock(args.puzzle, args.pubkey):
            print(f"Kangaroo déjà lancé pour puzzle=#{args.puzzle} (lock)")
            write_status({
                "running": False,
                "dedup_skip": True,
                "puzzle": args.puzzle,
                "pubkey": args.pubkey,
                "found": False,
            })
            return
    else:
        lo = int(args.lo, 16)
        hi = int(args.hi, 16)

    width = hi - lo + 1
    print(
        f"Kangaroo puzzle=#{args.puzzle} width=2^{width.bit_length()-1} "
        f"pubkey={args.pubkey[:18]}... engine={args.engine}"
    )
    result = kangaroo(args.pubkey, lo, hi, limit=args.limit, engine=args.engine)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
