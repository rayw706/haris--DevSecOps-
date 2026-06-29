import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from typing import List, Dict

from src.scanner import scan_file, VULN_SQLI, VULN_SECRET, VULN_EVAL, VULN_PATH, VULN_WEAK_CRYPTO, VULN_XSS, VULN_DESERIAL, VULN_CMD

SEVERITY_MAP = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}
INV_SEVERITY = {v: k for k, v in SEVERITY_MAP.items()}


def extract_features_from_findings(findings: List[Dict]) -> Dict:
    types = [f['type'] for f in findings]
    features = {
        'count': len(findings),
        'sqli': types.count(VULN_SQLI),
        'secret': types.count(VULN_SECRET),
        'eval': types.count(VULN_EVAL),
        'path': types.count(VULN_PATH),
        'weak_crypto': types.count(VULN_WEAK_CRYPTO),
        'xss': types.count(VULN_XSS),
        'deserial': types.count(VULN_DESERIAL),
        'cmd': types.count(VULN_CMD),
    }
    return features


def build_dataset(samples_dir: str, labels_csv: str) -> pd.DataFrame:
    df_labels = pd.read_csv(labels_csv)
    rows = []
    for _, row in df_labels.iterrows():
        fname = os.path.join(samples_dir, row['filename'])
        findings = []
        try:
            findings = scan_file(fname)
        except Exception:
            findings = []
        feats = extract_features_from_findings(findings)
        feats['label'] = SEVERITY_MAP.get(row['severity'], 0)
        feats['filename'] = row['filename']
        rows.append(feats)
    return pd.DataFrame(rows)


def train_model(samples_dir: str, labels_csv: str, model_path: str = 'model.joblib') -> Dict:
    df = build_dataset(samples_dir, labels_csv)
    X = df[['count','sqli','secret','eval','path','weak_crypto','xss','deserial','cmd']]
    y = df['label']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    clf = RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42)
    clf.fit(X_train, y_train)
    preds = clf.predict(X_test)
    report = classification_report(y_test, preds, target_names=[INV_SEVERITY[i] for i in sorted(INV_SEVERITY)])
    joblib.dump(clf, model_path)
    return {'model_path': model_path, 'report': report}


def load_model(model_path: str = 'model.joblib'):
    if not os.path.exists(model_path):
        return None
    return joblib.load(model_path)


def predict_severity(findings: List[Dict], model) -> Dict:
    feats = extract_features_from_findings(findings)
    X = np.array([[
        feats['count'], feats['sqli'], feats['secret'], feats['eval'], feats['path'], feats['weak_crypto'], feats['xss'], feats['deserial'], feats['cmd']
    ]])
    pred = model.predict(X)[0]
    probs = model.predict_proba(X)[0]
    return {'severity': INV_SEVERITY[int(pred)], 'score': float(probs[int(pred)])}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--samples', default='src/vulnerable_samples')
    parser.add_argument('--labels', default='src/vulnerable_samples/labels.csv')
    parser.add_argument('--out', default='model.joblib')
    args = parser.parse_args()
    res = train_model(args.samples, args.labels, args.out)
    print('Trained model saved to', res['model_path'])
    print(res['report'])
