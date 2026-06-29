import os
import sys
import argparse
from src.scanner import scan_file
from src.ml_ranker import load_model, train_model, predict_severity
from src.report_generator import generate_markdown_report


def scan_and_report(path: str, model_path: str, labels_csv: str, model=None):
    findings = scan_file(path)
    if model is None:
        model = load_model(model_path)
    if model is None:
        # train quick model from provided labels
        print('No model found — training from labels...')
        train_model('src/vulnerable_samples', labels_csv, model_path)
        model = load_model(model_path)

    pred = predict_severity(findings, model) if findings else {'severity': 'Low', 'score': 0.0}
    # attach severity to each finding for report
    ranked = []
    for f in findings:
        ff = f.copy()
        ff['severity'] = pred['severity']
        ranked.append(ff)

    out = generate_markdown_report(path, findings, ranked, out_path='reports/report.md')
    print('Report generated at', out)
    return pred['severity']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('path')
    parser.add_argument('--model', default='model.joblib')
    parser.add_argument('--labels', default='src/vulnerable_samples/labels.csv')
    args = parser.parse_args()

    if os.path.isdir(args.path):
        # scan all .py files
        severities = []
        for root, _, files in os.walk(args.path):
            for f in files:
                if f.endswith('.py'):
                    p = os.path.join(root, f)
                    sev = scan_and_report(p, args.model, args.labels)
                    severities.append(sev)
    else:
        sev = scan_and_report(args.path, args.model, args.labels)
        severities = [sev]

    # If any severity is High or Critical, exit with non-zero to block CI
    if any(s in ('High', 'Critical') for s in severities):
        print('High or Critical findings detected — failing scan')
        sys.exit(1)
    print('No blocking findings')
    sys.exit(0)


if __name__ == '__main__':
    main()
