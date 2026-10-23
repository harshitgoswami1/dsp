"""Run with: python smoke_test.py"""
import lab9
import lab10a
import lab11a
import lab11b

assert lab9.hash_text('abc')['sha256'] == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
for method in ('base64', 'hex', 'rot13', 'url', 'xor'):
    assert lab9.deobfuscate(lab9.obfuscate('Hello ✓', method, 42), method, 42) == 'Hello ✓'

keys = lab10a.generate_keys()
signature = lab10a.sign('hello', keys['private_key'])
assert lab10a.verify('hello', signature, keys['public_key'])
assert not lab10a.verify('changed', signature, keys['public_key'])

assert lab11a.classify('a@example.com')['pii']['text']['email'] == ['a@example.com']
rows = [
    {'Name': 'A', 'Age': 21, 'Zip': '56001', 'Diagnosis': 'Flu'},
    {'Name': 'B', 'Age': 22, 'Zip': '56002', 'Diagnosis': 'Cold'},
]
result = lab11b.anonymize(rows, ['Age', 'Zip'], 'Diagnosis', k=2, l=2)
assert result['k_anonymous'] and result['l_diverse']
assert result['risk_after']['minimum_class_size'] == 2
assert all('Name' not in row for row in result['rows'])
print('Smoke checks passed')

import hashlib
import lab1
import lab2
import lab3
import lab4
import lab5
import lab6
import lab7

assert lab1.caesar('Abc', 3)['result'] == 'Def'
assert lab2.inspect_input('DROP TABLE users')['sql_pattern_found']
assert not lab3.demonstrate('before', 'after')['integrity']['unchanged']
assert lab4.attack(hashlib.sha256(b'password').hexdigest(), ['password'], 'sha256')['found'] == 'password'
assert lab5.simulate(computers=3, rounds=2)['timeline'][0]['states'][0] == 'infected'
assert lab6.scan('eval(data)')['count'] == 1
assert lab7.classify('http://verify-account.example/login')['prediction'] == 'phishing'
print('Labs 1–8 core checks passed')
