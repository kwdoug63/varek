# VAREK: Type-Safe CI/CD Model Validation

This example demonstrates how VAREK acts as a strictly typed, compiled gatekeeper for Machine Learning CI/CD pipelines, replacing brittle Bash scripts and YAML orchestration.

### The Problem with ML CI/CD
In standard GitHub Actions or Jenkins pipelines, model validation usually consists of Bash scripts triggering Python evaluation files. If a Data Scientist modifies an evaluation script and changes an output key from `f1_score` to `f1`, the Bash script's regex might fail to parse it. The CI pipeline might silently pass, allowing a degraded or broken model to merge into production.

### The VAREK Solution
VAREK elevates CI/CD to a compiled language. By defining the exact schemas (`DriftResult` and `EvalResult`) in `pipeline.vrk`, VAREK mathematically guarantees that the evaluation scripts conform to the testing contracts. 
* **Deterministic Halting:** If thresholds are breached or schemas are violated, VAREK halts with a non-zero exit code, immediately blocking the Pull Request.
* **Clean Actions:** The GitHub Actions YAML becomes a single `varek run pipeline.vrk` command, moving complex orchestration logic out of YAML and into a testable, typed environment.

### Architecture
* `.github/workflows/pr_validation.yml` - The standard GitHub Action triggering VAREK.
* `pipeline.vrk` - The compiled gatekeeper containing the test assertions.
* `tests/` - The raw Python scripts performing statistical and performance checks.
