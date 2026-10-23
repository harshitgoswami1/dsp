"""Lab 4: bounded, local dictionary and brute-force password demonstrations."""
import hashlib
import itertools
import string

ALGORITHMS = ('plain', 'md5', 'sha1', 'sha256')
MAX_ATTEMPTS = 100_000


def strength(password):
    kinds = sum(bool(set(password) & set(chars)) for chars in
                (string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation))
    return 'Strong' if len(password) >= 12 and kinds >= 3 else 'Medium' if len(password) >= 8 and kinds >= 2 else 'Weak'


def attack(target, words, algorithm='plain', brute_length=0):
    if not isinstance(target, str) or not isinstance(words, list) or not all(isinstance(w, str) for w in words):
        raise ValueError('target and a list of words are required')
    if algorithm not in ALGORITHMS:
        raise ValueError('algorithm must be plain, md5, sha1, or sha256')
    if not isinstance(brute_length, int) or isinstance(brute_length, bool) or not 0 <= brute_length <= 4:
        raise ValueError('brute_length must be between 0 and 4')
    if len(words) > MAX_ATTEMPTS:
        raise ValueError('word list is too large')
    attempts = 0

    def matches(candidate):
        value = candidate if algorithm == 'plain' else hashlib.new(algorithm, candidate.encode()).hexdigest()
        return value == target

    for word in words:
        attempts += 1
        if matches(word):
            return {'found': word, 'method': 'dictionary', 'attempts': attempts, 'strength': strength(word)}
    if brute_length:
        for length in range(1, brute_length + 1):
            for chars in itertools.product(string.ascii_lowercase + string.digits, repeat=length):
                if attempts >= MAX_ATTEMPTS:
                    return {'found': None, 'attempts': attempts, 'limit_reached': True}
                candidate = ''.join(chars)
                attempts += 1
                if matches(candidate):
                    return {'found': candidate, 'method': 'brute_force', 'attempts': attempts,
                            'strength': strength(candidate)}
    return {'found': None, 'attempts': attempts, 'limit_reached': False}
