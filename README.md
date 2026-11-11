# K-Anonymity Audit

A dependency-free command-line screen for finding small equivalence classes in tabular data. Choose the columns that could identify someone in combination (quasi-identifiers); the tool reports only aggregate class sizes and counts.

## Use case

Before sharing a dataset, a data team can check whether combinations such as region, age band, and visit type are rare in the dataset. For a configured threshold `k`, each tuple should occur at least `k` times to pass this narrow screening rule.

The report deliberately omits raw quasi-identifier tuples and source records. It does include the selected column names, counts, class-size histogram, and screening outcome.

## Quick start

Requires Python 3.10+; no third-party libraries.

```bash
python privacy_audit.py demo --output demo-output --k 5
python -m unittest -v
```

Audit your own CSV:

```bash
python privacy_audit.py audit customers.csv \
  --quasi-id region age_band visit_type \
  --k 5 --output audit-output
```

The output folder receives `audit.json` and `report.md`. The CSV itself remains at its input path.

## Input format

UTF-8 CSV, optionally with a UTF-8 BOM, and a header row. Each selected quasi-identifier must be a column name in the header. Duplicate column names, missing selected columns, and rows with more fields than the header are rejected. Blank quasi-identifier values are grouped as an empty category; decide how missing values should be handled for your own context before interpreting results.

## Metrics

- **Equivalence class**: records with the same values across the chosen quasi-identifier columns.
- **Unique records**: records in a class of size one.
- **Records below k**: all records belonging to any class whose size is less than `k`.
- **Screen result**: `PASS` only when the dataset is non-empty and every observed class has at least `k` records; otherwise `FAIL`.

The histogram reports the number of classes at each exact size. No record values are written to the generated JSON or Markdown report.

## Reproducible demo result

The fixed-seed generator creates 244 fictional records across 32 combinations of region, age band, and visit type. With `k=5`, two sparse classes contain two records each, so four records (1.6%) are below the threshold. The screen returns **FAIL**. This is a synthetic demonstration, not a statement about a real dataset.

## Important limits

Passing is not proof of anonymity or safe publication. This basic k-anonymity screen depends on which columns were selected and does not account for outside data an attacker may possess. It does not detect direct identifiers, evaluate sensitive-attribute disclosure, estimate re-identification probability, or perform generalization or suppression. Anonymization risk depends on context and release design; use this result as an early warning in a broader privacy review.

All included example data are fictional and generated locally with a fixed seed. No external or private data are included.

## License

MIT. See [LICENSE](LICENSE).
