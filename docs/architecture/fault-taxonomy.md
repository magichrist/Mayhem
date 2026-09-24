# Fault taxonomy reference

Fault definitions are frozen `FaultDefinition` records in `src/mayhem/domain/faults.py` and `src/mayhem/domain/catalog.py`. Each definition declares its id, category, risk, applicable node kinds, maximum duration, reversible status, required capabilities, and parameter schema.

The catalog table is the planner authority. The Kubernetes dispatch register is the execution authority. A catalog entry can be schema-valid and catalog-only without being executable.
