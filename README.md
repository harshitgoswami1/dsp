# DSP lab backend

Python 3.12+ FastAPI JSON API. Interactive API docs are at `/docs`. Each lab's core logic is in its own `lab*.py` file; `app.py` only handles HTTP requests. The manual's GUI code was adapted into backend functions.

```sh
cd backend
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload
```

| Lab | Endpoint | JSON body |
| --- | --- | --- |
| 1 basics | `POST /lab1/run` | `{"operation":"caesar","text":"Hello","shift":3}`; other operations: `password`, `login`, `network`, `hex` |
| 2 tools | `POST /lab2/run` | `{"operation":"input","text":"SELECT * FROM users"}`; other operations: `system`, `network`, `hex` |
| 3 CIA | `POST /lab3/demo` | `{"message":"original","changed_message":"edited"}` |
| 4 dictionary | `POST /lab4/attack` | `{"target":"secret","words":["guess","secret"],"algorithm":"plain","brute_length":0}` |
| 5 simulation | `POST /lab5/simulate` | `{"computers":5,"rounds":5,"spread_chance":0.3,"quarantine_chance":0.35}` |
| 6 code scan | `POST /lab6/scan` | `{"code":"eval(data)","filename":"example.py"}` |
| 7 phishing | `POST /lab7/classify` | `{"url":"http://verify-account.example/login"}`; optional `dataset` is `[url, label]` rows |
| 8 encrypted chat | `WS /lab8/ws/{room}` | Two clients in one room relay opaque encrypted messages |
| 9 hashing | `POST /lab9/hash` | `{"text":"hello"}` |
| 9 file hashing | `POST /lab9/hash-file` | Raw file bytes (`Content-Type: application/octet-stream`) |
| 9 obfuscation | `POST /lab9/obfuscate` | `{"text":"hello","method":"base64","action":"encode"}`; methods: `base64`, `hex`, `rot13`, `url`, `xor` (add integer `key` for XOR); use `decode` to reverse |
| 10a keys | `POST /lab10a/keys` | `{}`; save the returned private key yourself |
| 10a sign | `POST /lab10a/sign` | `{"message":"hello","private_key":"<PEM>"}` |
| 10a verify | `POST /lab10a/verify` | `{"message":"hello","signature":"<base64>","public_key":"<PEM>"}` |
| 10b register | `POST /lab10b/register` | `{"username":"student","password":"password123"}` |
| 10b login | `POST /lab10b/login` | Same credentials; returns a one-hour token |
| 10b protected | `GET /lab10b/profile` | Header `Authorization: Bearer <token>` |
| 10b admin | `GET /lab10b/admin` | Requires an admin token |
| 11a PII | `POST /lab11a/classify` | `{"data":"Contact me at a@b.com","source":"at_rest"}`; `data` can also be a list of CSV-like row objects |
| 11b anonymity | `POST /lab11b/anonymize` | `{"rows":[{"Age":21,"Zip":"56001","Diagnosis":"Flu"},...],"quasi_identifiers":["Age","Zip"],"sensitive":"Diagnosis","k":2}`; optional `l` and `t` checks plus `epsilon` for a noisy count |

Lab 10b keeps users in memory. For an admin demonstration, set `LAB_ADMIN_PASSWORD` before starting the server (and optionally `LAB_ADMIN_USER`; default `admin`), then log in as that user. `LAB_JWT_SECRET` can be set to keep tokens valid across restarts. Lab 9's MD5 and SHA-1 outputs are included for comparison only; use SHA-256 or SHA-512 for integrity checks. Obfuscation is reversible and provides no confidentiality. Lab 11b reports whether the chosen `l` and `t` targets hold; it guarantees `k` by generalizing or suppressing quasi-identifiers. Use synthetic data for these exercises.

Lab 7 uses a small built-in training dataset by default; use the optional dataset field for your own labeled examples. Lab 8 derives an AES-GCM key from a shared passphrase in each browser. The relay never receives that passphrase or plaintext. Local development uses `ws`; serve the frontend over HTTPS and the backend WebSocket over WSS for TLS between devices. The relay is in memory and supports two clients per room on one server process.

Run `python smoke_test.py` from the `backend` directory for the core logic check.
