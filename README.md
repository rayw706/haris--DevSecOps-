# Haris (حارس) — DevSecOps AI vulnerability scanner

Haris is a minimal prototype scanner that performs static analysis on Python code, ranks findings using a trained ML model, and generates a ranked vulnerability report. It integrates with GitHub Actions to block merges when Critical or High severity issues are detected.

Usage:

1. Install dependencies: `pip install -r requirements.txt`
2. Train model (optional): `python -m src.ml_ranker --samples src/vulnerable_samples --labels src/vulnerable_samples/labels.csv`
3. Run scanner: `python main.py path/to/file_or_folder`

Files:
- `src/scanner.py` — static AST + regex heuristics
- `src/ml_ranker.py` — trains and predicts severity
- `src/report_generator.py` — generates markdown report
- `src/vulnerable_samples/` — 40 labeled vulnerable samples for training
- `.github/workflows/security-scan.yml` — CI pipeline
