"""Lab 6: simple source-code pattern scanner."""
import re

RULES = (
    ('eval() call', r'\beval\s*\(', 'Critical', 'Avoid evaluating untrusted code.'),
    ('exec() call', r'\bexec\s*\(', 'Critical', 'Avoid executing untrusted code.'),
    ('Possible hardcoded secret', r'\b(?:password|passwd|secret|api_?key)\s*[:=]\s*[\'\"][^\'\"]+[\'\"]', 'High', 'Store secrets outside source code.'),
    ('Shell command', r'\bos\.system\s*\(', 'High', 'Use a safer subprocess call with fixed arguments.'),
    ('Possible SQL concatenation', r'\b(?:SELECT|INSERT|UPDATE|DELETE)\b.*\+', 'Medium', 'Use parameterized queries.'),
)


def scan(code, filename='source.txt'):
    if not isinstance(code, str) or not isinstance(filename, str):
        raise ValueError('code and filename must be strings')
    if len(code) > 200_000:
        raise ValueError('code must be at most 200,000 characters')
    findings = []
    for number, line in enumerate(code.splitlines(), 1):
        for name, pattern, severity, advice in RULES:
            if re.search(pattern, line, re.I):
                findings.append({'line': number, 'type': name, 'severity': severity,
                                 'suggestion': advice, 'excerpt': line.strip()[:160]})
    return {'filename': filename, 'findings': findings, 'count': len(findings)}
