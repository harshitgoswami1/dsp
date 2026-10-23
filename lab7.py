"""Lab 7: a small URL-feature classifier trained with scikit-learn."""
from urllib.parse import urlsplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

SAMPLE = [
    ('https://www.wikipedia.org', 'legitimate'),
    ('https://www.python.org/docs', 'legitimate'),
    ('https://www.university.edu/admissions', 'legitimate'),
    ('https://www.example.com/contact', 'legitimate'),
    ('https://docs.example.org/guide', 'legitimate'),
    ('https://library.example.edu/search', 'legitimate'),
    ('https://www.openstreetmap.org', 'legitimate'),
    ('https://news.example.com/latest', 'legitimate'),
    ('http://verify-account@bad.example/login', 'phishing'),
    ('http://bank-update.example/secure-login', 'phishing'),
    ('http://account-verify.example/update', 'phishing'),
    ('http://secure-login.example/verify', 'phishing'),
    ('http://login-update.example/account', 'phishing'),
    ('http://verify-now.example/secure', 'phishing'),
    ('http://account-help.example/login', 'phishing'),
    ('http://secure-account.example/verify', 'phishing'),
]


def features(url):
    parsed = urlsplit(url)
    host = parsed.hostname or ''
    lower = url.lower()
    return [len(url), int('@' in url), int(parsed.scheme == 'https'), url.count('-'),
            host.count('.'), int(any(word in lower for word in ('login', 'verify', 'secure', 'update', 'account')))]


def classify(url, dataset=None):
    if not isinstance(url, str) or not url.strip() or len(url) > 2048:
        raise ValueError('url must be a nonempty string of at most 2048 characters')
    rows = SAMPLE if dataset is None else dataset
    if not isinstance(rows, list) or not 8 <= len(rows) <= 5000 or not all(
        isinstance(row, (list, tuple)) and len(row) == 2 and
        isinstance(row[0], str) and row[1] in ('legitimate', 'phishing') for row in rows
    ):
        raise ValueError('dataset must have 8–5000 [url, label] rows')
    labels = [label for _, label in rows]
    if min(labels.count('legitimate'), labels.count('phishing')) < 4:
        raise ValueError('dataset needs at least 4 examples of each label')
    x = [features(item) for item, _ in rows]
    train_x, test_x, train_y, test_y = train_test_split(x, labels, test_size=0.25, random_state=42, stratify=labels)
    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(train_x, train_y)
    accuracy = accuracy_score(test_y, model.predict(test_x))
    model.fit(x, labels)
    prediction = model.predict([features(url)])[0]
    return {'prediction': prediction, 'test_accuracy': round(float(accuracy), 3),
            'training_rows': len(rows), 'features': features(url),
            'note': 'Small educational dataset; a prediction is not proof that a site is safe.'}
