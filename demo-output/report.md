# Quasi-identifier privacy screen

- Records: **244**; quasi-identifier columns: **region, age_band, visit_type**.
- Threshold: **k = 5**; equivalence classes: **32**.
- Unique records: **0**.
- Records in classes smaller than k: **4 (1.6%)**.
- Minimum observed class size: **2**.
- Screening result: **FAIL**.

## Class-size histogram

| Class size | Number of classes |
|---:|---:|
| 2 | 2 |
| 8 | 30 |

## Interpretation

This screen counts how often each selected quasi-identifier tuple appears. A class smaller than k fails the configured threshold. Only aggregate counts are written to the report; raw tuples and records are not emitted.

## Limits

Passing this check does not prove that a dataset is anonymous or safe to publish. Results depend on the chosen columns, recoding, external data an attacker may hold, and the data subject's context. This tool does not inspect direct identifiers or sensitive attributes, measure attribute disclosure, or perform suppression/generalization. Use it as an early warning and obtain a context-specific privacy review.
