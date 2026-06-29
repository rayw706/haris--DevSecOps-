import ast
import re
from typing import List, Dict

VULN_SQLI = 'sql_injection'
VULN_SECRET = 'hardcoded_secret'
VULN_EVAL = 'insecure_eval'
VULN_PATH = 'path_traversal'
VULN_WEAK_CRYPTO = 'weak_crypto'
VULN_XSS = 'xss'
VULN_DESERIAL = 'insecure_deserialization'
VULN_CMD = 'command_injection'


class VulnerabilityFinder(ast.NodeVisitor):
    def __init__(self, code: str):
        self.code = code
        self.tree = ast.parse(code)
        self.findings: List[Dict] = []

    def find(self) -> List[Dict]:
        self.visit(self.tree)
        return self.findings

    def visit_Call(self, node: ast.Call):
        # detect eval/exec
        func = getattr(node.func, 'id', None) or getattr(node.func, 'attr', None)
        if func in ('eval', 'exec'):
            self.findings.append({'type': VULN_EVAL, 'lineno': node.lineno, 'message': f'use of {func}() detected'})

        # detect subprocess with shell=True or os.system
        if func in ('system',):
            self.findings.append({'type': VULN_CMD, 'lineno': node.lineno, 'message': 'os.system detected — possible command injection'})

        # detect pickle.loads
        if getattr(node.func, 'attr', '') == 'loads' or getattr(node.func, 'id', '') == 'loads':
            self.findings.append({'type': VULN_DESERIAL, 'lineno': node.lineno, 'message': 'pickle.loads detected — insecure deserialization'})

        # detect render_template_string (flask) as XSS risk
        if func == 'render_template_string':
            self.findings.append({'type': VULN_XSS, 'lineno': node.lineno, 'message': 'render_template_string used — potential XSS'})

        # detect SQL execute patterns where string formatting is used
        if getattr(node.func, 'attr', '') == 'execute' or func == 'execute':
            for arg in node.args:
                if isinstance(arg, ast.BinOp) or isinstance(arg, ast.JoinedStr) or isinstance(arg, ast.Call):
                    self.findings.append({'type': VULN_SQLI, 'lineno': node.lineno, 'message': 'SQL execution with dynamic query detected — possible SQL injection'})

        # detect subprocess.run with shell=True
        if getattr(node.func, 'attr', '') == 'run' or func == 'run':
            for kw in node.keywords:
                if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.findings.append({'type': VULN_CMD, 'lineno': node.lineno, 'message': 'subprocess.run(shell=True) — command injection risk'})

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # hardcoded secrets detection: variable names like password/secret/token and string literal assigned
        for target in node.targets:
            name = getattr(target, 'id', '')
            if name and re.search(r'pass(word)?|secret|token|api_key|apikey', name, re.I):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    self.findings.append({'type': VULN_SECRET, 'lineno': node.lineno, 'message': f'hardcoded secret assigned to {name}'})

        # detect hashlib with weak algorithms
        if isinstance(node.value, ast.Call):
            func = getattr(node.value.func, 'attr', '') or getattr(node.value.func, 'id', '')
            dump = ast.dump(node.value).lower()
            if func in ('md5', 'sha1') or 'md5' in dump or 'sha1' in dump:
                self.findings.append({'type': VULN_WEAK_CRYPTO, 'lineno': node.lineno, 'message': 'weak hashing algorithm used (md5/sha1)'})

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        # path traversal: uses os.path.join with suspicious input (heuristic)
        if node.attr == 'join' and isinstance(node.value, ast.Attribute) and getattr(node.value, 'attr', '') == 'path':
            self.findings.append({'type': VULN_PATH, 'lineno': node.lineno, 'message': 'os.path.join usage — check for path traversal'})
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        # detect imports of insecure modules or pickle
        for n in node.names:
            if n.name == 'pickle':
                self.findings.append({'type': VULN_DESERIAL, 'lineno': node.lineno, 'message': 'pickle imported — inspect uses for insecure deserialization'})
        self.generic_visit(node)


def detect_vulnerabilities(code: str) -> List[Dict]:
    """Run a set of heuristics to find likely vulnerabilities in Python code."""
    finder = VulnerabilityFinder(code)
    findings = finder.find()

    # simple regex checks for hard patterns
    if re.search(r"\beval\s*\(", code):
        findings.append({'type': VULN_EVAL, 'lineno': None, 'message': 'eval() call detected by regex'})

    if re.search(r"\bexec\s*\(|\bexec\s+", code):
        findings.append({'type': VULN_EVAL, 'lineno': None, 'message': 'exec usage detected by regex'})

    if re.search(r"\bsubprocess\.Popen\b|\bos\.system\b", code):
        findings.append({'type': VULN_CMD, 'lineno': None, 'message': 'subprocess/os.system usage detected'})

    # simple SQL pattern
    if re.search(r"\.execute\s*\(|\bSELECT\b.*\+|%\(|format\(|f\".*SELECT", code, re.I):
        findings.append({'type': VULN_SQLI, 'lineno': None, 'message': 'possible dynamic SQL detected (heuristic)'})

    # XSS heuristic
    if re.search(r"render_template_string|<script>|innerHTML|unsafe", code):
        findings.append({'type': VULN_XSS, 'lineno': None, 'message': 'possible XSS pattern detected'})

    # hardcoded secrets via assignment patterns
    if re.search(r"(password|secret|api_key)\s*=\s*['\"]{1}.{4,}['\"]{1}", code, re.I):
        findings.append({'type': VULN_SECRET, 'lineno': None, 'message': 'hardcoded credential pattern detected by regex'})

    # deduplicate by (type,message,lineno)
    unique = []
    seen = set()
    for f in findings:
        key = (f.get('type'), f.get('message'), f.get('lineno'))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


def scan_file(path: str) -> List[Dict]:
    with open(path, 'r', encoding='utf-8') as fh:
        code = fh.read()
    findings = detect_vulnerabilities(code)
    for f in findings:
        f.setdefault('file', path)
    return findings


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        path = sys.argv[1]
        print(scan_file(path))
    else:
        print('Usage: python src/scanner.py path/to/file.py')
