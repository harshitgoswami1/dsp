"""Lab 11a: identify likely PII in text or CSV rows."""
import re

PATTERNS = {
    'email': re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', re.I),
    'phone': re.compile(r'(?<!\d)\d{10}(?!\d)'),
    'aadhaar': re.compile(r'(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)'),
    'pan': re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b'),
}


def classify(data, source='at_rest'):
    if source not in ('at_rest', 'in_transit', 'in_use'):
        raise ValueError('source must be at_rest, in_transit, or in_use')
    if isinstance(data, str):
        kind = 'unstructured'
        fields = {'text': data}
    elif isinstance(data, list) and all(isinstance(row, dict) for row in data):
        kind = 'structured'
        fields = {str(column): ' '.join(str(row.get(column, '')) for row in data)
                  for column in {key for row in data for key in row}}
    else:
        raise ValueError('data must be text or a list of objects')
    matches = {column: {name: pattern.findall(value) for name, pattern in PATTERNS.items()
                        if pattern.search(value)} for column, value in fields.items()}
    return {'type': kind, 'state': source, 'processing_state': 'in_use',
            'pii': {column: found for column, found in matches.items() if found}}
