from __future__ import annotations
import argparse
import json
import sys
from .engine import LOAD_FAILURE_CODES, admit_object, inspect_object
from .load import load_json, load_store, save_store

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m certpin")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_ins = sub.add_parser("inspect")
    p_ins.add_argument("--input", required=True)

    p_ad = sub.add_parser("admit")
    p_ad.add_argument("--input", required=True)
    p_ad.add_argument("--keys", required=True)
    p_ad.add_argument("--policy", required=True)
    p_ad.add_argument("--store", required=True)
    p_ad.add_argument("--now", default=None)
    p_ad.add_argument("--report", required=True)

    args = ap.parse_args(argv)
    if args.cmd == "inspect":
        try:
            obj = load_json(args.input)
        except (OSError, ValueError) as e:
            print(f"load failure: {e}", file=sys.stderr)
            return 2
        print(json.dumps(inspect_object(obj), ensure_ascii=False, indent=2))
        return 0

    try:
        obj = load_json(args.input)
        keys = load_json(args.keys)
        policy = load_json(args.policy)
        store = load_store(args.store)
    except (OSError, ValueError) as e:
        print(f"load failure: {e}", file=sys.stderr)
        return 2
    now = None
    if args.now:
        try:
            now = int(args.now)
        except ValueError:
            from datetime import datetime
            try:
                now = int(datetime.fromisoformat(args.now.replace("Z", "+00:00")).timestamp())
            except ValueError as e:
                print(f"load failure: invalid --now: {e}", file=sys.stderr)
                return 2
    try:
        report = admit_object(obj, keys, policy, store, now)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2
    from pathlib import Path as _P
    _P(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if report.get("decision") == "allow":
        save_store(args.store, store)
        return 0
    if report.get("decision") == "deny":
        if any(code in LOAD_FAILURE_CODES for code in report.get("reason_codes") or []):
            return 2
        return 1
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
