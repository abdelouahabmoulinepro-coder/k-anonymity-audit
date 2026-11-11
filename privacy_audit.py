"""Aggregate-only k-anonymity screening for selected quasi-identifiers."""
from __future__ import annotations

import argparse
import csv
import json
import random
from collections import Counter
from pathlib import Path


def load_csv(path: Path, quasi_ids: list[str]) -> list[dict[str, str]]:
    if not quasi_ids or len(set(quasi_ids)) != len(quasi_ids):
        raise ValueError("Indiquez au moins un quasi-identifiant, sans doublons")
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames:
            raise ValueError("Le CSV doit contenir une ligne d'en-tête")
        if len(reader.fieldnames) != len(set(reader.fieldnames)):
            raise ValueError("Les noms de colonnes doivent être uniques")
        missing = [name for name in quasi_ids if name not in reader.fieldnames]
        if missing:
            raise ValueError("Colonnes absentes: " + ", ".join(missing))
        rows = []
        for line, row in enumerate(reader, 2):
            if None in row:
                raise ValueError(f"Ligne {line}: trop de champs par rapport à l'en-tête")
            rows.append({name: (row.get(name) or "").strip() for name in quasi_ids})
    return rows


def audit(rows: list[dict[str, str]], quasi_ids: list[str], k: int = 5) -> dict:
    if not quasi_ids or len(set(quasi_ids)) != len(quasi_ids):
        raise ValueError("Indiquez au moins un quasi-identifiant, sans doublons")
    if k < 2:
        raise ValueError("k doit être supérieur ou égal à 2")
    classes = Counter()
    for index, row in enumerate(rows, 1):
        missing = [name for name in quasi_ids if name not in row]
        if missing:
            raise ValueError(f"Ligne {index}: colonnes absentes: " + ", ".join(missing))
        key = tuple((row.get(name) or "").strip() for name in quasi_ids)
        classes[key] += 1
    sizes = list(classes.values())
    below_classes = sum(size < k for size in sizes)
    below_records = sum(size for size in sizes if size < k)
    counts = Counter(sizes)
    return {
        "records": len(rows), "quasi_identifiers": list(quasi_ids), "k_threshold": k,
        "equivalence_classes": len(classes),
        "unique_records": sum(size == 1 for size in sizes),
        "records_in_classes_below_k": below_records,
        "share_records_below_k": (below_records / len(rows)) if rows else None,
        "classes_below_k": below_classes,
        "minimum_class_size": min(sizes) if sizes else None,
        "class_size_histogram": {str(size): counts[size] for size in sorted(counts)},
        "screen_passed": bool(rows) and below_records == 0,
    }


def write_report(result: dict, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "audit.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    share = result["share_records_below_k"]
    share_text = "n/a" if share is None else f"{share:.1%}"
    status = "PASS" if result["screen_passed"] else "FAIL"
    lines = ["# Quasi-identifier privacy screen", "",
        f"- Records: **{result['records']}**; quasi-identifier columns: **{', '.join(result['quasi_identifiers'])}**.",
        f"- Threshold: **k = {result['k_threshold']}**; equivalence classes: **{result['equivalence_classes']}**.",
        f"- Unique records: **{result['unique_records']}**.",
        f"- Records in classes smaller than k: **{result['records_in_classes_below_k']} ({share_text})**.",
        f"- Minimum observed class size: **{result['minimum_class_size'] if result['minimum_class_size'] is not None else 'n/a'}**.",
        f"- Screening result: **{status}**.", "",
        "## Class-size histogram", "", "| Class size | Number of classes |", "|---:|---:|"]
    for size, count in result["class_size_histogram"].items():
        lines.append(f"| {size} | {count} |")
    lines.extend(["", "## Interpretation", "",
        "This screen counts how often each selected quasi-identifier tuple appears. A class smaller than k fails the configured threshold. "
        "Only aggregate counts are written to the report; raw tuples and records are not emitted.", "",
        "## Limits", "",
        "Passing this check does not prove that a dataset is anonymous or safe to publish. Results depend on the chosen columns, recoding, "
        "external data an attacker may hold, and the data subject's context. This tool does not inspect direct identifiers or sensitive attributes, "
        "measure attribute disclosure, or perform suppression/generalization. Use it as an early warning and obtain a context-specific privacy review.", ""])
    (output / "report.md").write_text("\n".join(lines), encoding="utf-8")


def generate_demo(path: Path, seed: int = 20261111) -> None:
    rng = random.Random(seed)
    zones = ["north", "south", "east", "west"]
    ages = ["18-29", "30-44", "45-59", "60+"]
    days = ["weekday", "weekend"]
    rows = []
    # Balanced common cells plus sparse edge groups make the screen's purpose visible.
    for zone in zones:
        for age in ages:
            for day in days:
                count = 8 if age != "60+" or zone != "west" else 2
                rows.extend({"region": zone, "age_band": age, "visit_type": day} for _ in range(count))
    rng.shuffle(rows)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["region", "age_band", "visit_type"])
        writer.writeheader(); writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit agrégé des classes d'équivalence de quasi-identifiants")
    subs = parser.add_subparsers(dest="command", required=True)
    demo = subs.add_parser("demo", help="génère un exemple synthétique reproductible")
    demo.add_argument("--output", type=Path, default=Path("demo-output")); demo.add_argument("--k", type=int, default=5)
    run = subs.add_parser("audit", help="audite un CSV sans réémettre les lignes")
    run.add_argument("csv", type=Path); run.add_argument("--quasi-id", nargs="+", required=True)
    run.add_argument("--k", type=int, default=5); run.add_argument("--output", type=Path, default=Path("audit-output"))
    args = parser.parse_args()
    if args.command == "demo":
        args.output.mkdir(parents=True, exist_ok=True)
        source = args.output / "synthetic_records.csv"
        generate_demo(source)
        result = audit(load_csv(source, ["region", "age_band", "visit_type"]), ["region", "age_band", "visit_type"], args.k)
    else:
        result = audit(load_csv(args.csv, args.quasi_id), args.quasi_id, args.k)
    write_report(result, args.output)
    print(f"{result['records']} lignes; {result['equivalence_classes']} classes; {result['records_in_classes_below_k']} sous k; écran {'PASS' if result['screen_passed'] else 'FAIL'}; rapport {args.output / 'report.md'}")


if __name__ == "__main__": main()
