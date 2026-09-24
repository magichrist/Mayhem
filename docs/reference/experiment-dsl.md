# Experiment DSL duration reference

`src/mayhem/domain/common.py` accepts plain seconds and duration suffixes:

- `s` seconds
- `m` minutes
- `h` hours
- `d` days

Examples: `30`, `30s`, `5m`, `1h`, and `2d`. Invalid values are rejected during schema validation. Catalog maximum duration remains the upper bound for a fault lease.
