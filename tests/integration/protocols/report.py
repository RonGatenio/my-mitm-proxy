#!/usr/bin/env python3
"""Render the protocol-coverage matrix from manifest.tsv (expected) + results.tsv (actual).

Exit 0 iff every case's actual (Fwd, Dump[, level, srcip]) matches its expected
verdict. SKIP rows (missing tool) are reported but never counted as pass and do
not fail the run.
"""
import argparse, json, sys

SYMB = {"ok": "✓", "degrade": "~", "fail": "✗", "na": "n/a",
        "skip": "SKIP", "err": "ERR", "": "?"}

MANIFEST_COLS = ["name", "kind", "group", "class", "exp_fwd", "exp_dump", "exp_level", "note"]
RESULT_COLS = ["name", "act_fwd", "act_dump", "act_level", "srcip"]


def read_tsv(path, cols):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            rows.append(dict(zip(cols, parts + [""] * (len(cols) - len(parts)))))
    return rows


def status_for(exp, act):
    if act.get("act_fwd") == "skip":
        return "SKIP"
    if act.get("act_fwd") == "err" or act.get("act_dump") == "err":
        return "ERROR"
    ok = (act.get("act_fwd") == exp["exp_fwd"] and act.get("act_dump") == exp["exp_dump"])
    if ok and exp["exp_dump"] == "ok":
        try:
            ok = int(act.get("act_level") or 0) >= int(exp["exp_level"] or 0)
        except ValueError:
            ok = False
    if act.get("srcip") not in (None, "", "ok", "na"):
        ok = False
    return "PASS" if ok else "FAIL"


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")   # robust on non-UTF-8 consoles
    except Exception:
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--results", required=True)
    ap.add_argument("--json-out")
    ap.add_argument("--mode", default="")
    args = ap.parse_args()

    manifest = {r["name"]: r for r in read_tsv(args.manifest, MANIFEST_COLS)}
    results = {r["name"]: r for r in read_tsv(args.results, RESULT_COLS)}

    rows, npass, nfail, nskip = [], 0, 0, 0
    print(f"\n=== mymitmproxy protocol coverage - P0 (mode={args.mode or '?'}) ===\n")
    hdr = f"{'CASE':<14}{'GRP':<4}{'CLASS':<10}{'FWD':<5}{'DUMP':<6}{'LVL':<4}{'STATUS':<7}NOTE"
    print(hdr); print("-" * len(hdr))
    for name, exp in manifest.items():
        act = results.get(name, {"act_fwd": "err", "act_dump": "err", "act_level": "0", "srcip": ""})
        st = status_for(exp, act)
        npass += st == "PASS"; nskip += st == "SKIP"; nfail += st in ("FAIL", "ERROR")
        print(f"{name:<14}{exp['group']:<4}{exp['class']:<10}"
              f"{SYMB.get(act.get('act_fwd',''),'?'):<5}{SYMB.get(act.get('act_dump',''),'?'):<6}"
              f"{(act.get('act_level') or '-'):<4}{st:<7}{exp['note']}")
        rows.append({"name": name, "group": exp["group"], "class": exp["class"],
                     "expected": {"fwd": exp["exp_fwd"], "dump": exp["exp_dump"], "level": exp["exp_level"]},
                     "actual": {"fwd": act.get("act_fwd"), "dump": act.get("act_dump"),
                                "level": act.get("act_level"), "srcip": act.get("srcip")},
                     "status": st})
    print("-" * len(hdr))
    print(f"\n{npass} PASS   {nfail} FAIL   {nskip} SKIP   ({len(manifest)} rows)\n")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump({"mode": args.mode, "pass": npass, "fail": nfail, "skip": nskip, "rows": rows},
                      fh, indent=2, ensure_ascii=False)
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
