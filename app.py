"""FastAPI routes for the Data Security and Privacy labs."""
import binascii
from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket
from fastapi.responses import JSONResponse

import lab1
import lab2
import lab3
import lab4
import lab5
import lab6
import lab7
import lab8
import lab9
import lab10a
import lab10b
import lab11a
import lab11b

app = FastAPI(title='DSP Lab Backend')


@app.exception_handler(ValueError)
async def bad_request(_, error):
    return JSONResponse({'detail': str(error)}, status_code=400)


@app.exception_handler(KeyError)
async def missing_field(_, error):
    return JSONResponse({'detail': f'Missing field: {error.args[0]}'}, status_code=400)


@app.exception_handler(binascii.Error)
async def bad_encoding(_, error):
    return JSONResponse({'detail': str(error)}, status_code=400)


def current_user(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(status_code=401, detail='Bearer token required')
    try:
        return lab10b.authenticate(authorization[7:])
    except ValueError as error:
        raise HTTPException(status_code=401, detail=str(error)) from None


@app.post('/lab1/run')
def lab1_run(data: dict):
    operation = data.get('operation')
    if operation == 'password':
        return lab1.password_strength(data.get('password'))
    if operation == 'login':
        return lab1.demo_login(data.get('username'), data.get('password'))
    if operation == 'network':
        return lab1.network_info()
    if operation == 'caesar':
        return lab1.caesar(data.get('text'), data.get('shift', 3))
    if operation == 'hex':
        return lab1.hex_text(data.get('text'), data.get('decode', False))
    raise ValueError('Unknown Lab 1 operation')


@app.post('/lab2/run')
def lab2_run(data: dict):
    operation = data.get('operation')
    if operation == 'system':
        return lab2.system_info()
    if operation == 'input':
        return lab2.inspect_input(data.get('text'))
    if operation == 'hex':
        return lab2.hex_text(data.get('text'), data.get('decode', False))
    if operation == 'network':
        return {'status': 'Request received by FastAPI',
                'tip': 'Capture this local request in your network analysis tool.'}
    raise ValueError('Unknown Lab 2 operation')


@app.post('/lab3/demo')
def lab3_demo(data: dict):
    return lab3.demonstrate(data.get('message'), data.get('changed_message'))


@app.post('/lab4/attack')
def lab4_attack(data: dict):
    return lab4.attack(data.get('target'), data.get('words'), data.get('algorithm', 'plain'),
                       data.get('brute_length', 0))


@app.post('/lab5/simulate')
def lab5_simulate(data: dict):
    return lab5.simulate(data.get('computers', 5), data.get('rounds', 5),
                         data.get('spread_chance', 0.3), data.get('quarantine_chance', 0.35),
                         data.get('seed', 7))


@app.post('/lab6/scan')
def lab6_scan(data: dict):
    return lab6.scan(data.get('code'), data.get('filename', 'source.txt'))


@app.post('/lab7/classify')
def lab7_classify(data: dict):
    return lab7.classify(data.get('url'), data.get('dataset'))


@app.websocket('/lab8/ws/{room}')
async def lab8_chat(websocket: WebSocket, room: str):
    await lab8.relay(websocket, room)


@app.post('/lab9/hash')
def hash_data(data: dict):
    if not isinstance(data.get('text'), str):
        raise ValueError('text must be a string')
    return {'hashes': lab9.hash_text(data['text'])}


@app.post('/lab9/hash-file')
async def hash_file(request: Request):
    """Send the file bytes as the raw request body (application/octet-stream)."""
    return {'hashes': lab9.hash_bytes(await request.body())}


@app.post('/lab9/obfuscate')
def obfuscate(data: dict):
    if not isinstance(data.get('text'), str):
        raise ValueError('text must be a string')
    action = data.get('action', 'encode')
    if action not in ('encode', 'decode'):
        raise ValueError('action must be encode or decode')
    operation = lab9.obfuscate if action == 'encode' else lab9.deobfuscate
    return {'result': operation(data['text'], data.get('method'), data.get('key'))}


@app.post('/lab10a/keys')
def keys():
    return lab10a.generate_keys()


@app.post('/lab10a/sign')
def sign(data: dict):
    return {'signature': lab10a.sign(data['message'], data['private_key'])}


@app.post('/lab10a/verify')
def verify(data: dict):
    return {'valid': lab10a.verify(data['message'], data['signature'], data['public_key'])}


@app.post('/lab10b/register', status_code=201)
def register(data: dict):
    lab10b.register(data.get('username'), data.get('password'))
    return {'message': 'Registered'}


@app.post('/lab10b/login')
def login(data: dict):
    try:
        return {'access_token': lab10b.login(data.get('username'), data.get('password'))}
    except ValueError as error:
        raise HTTPException(status_code=401, detail=str(error)) from None


@app.get('/lab10b/profile')
def profile(user: dict = Depends(current_user)):
    return {'username': user['sub'], 'role': user['role']}


@app.get('/lab10b/admin')
def admin(user: dict = Depends(current_user)):
    if user['role'] != 'admin':
        raise HTTPException(status_code=403, detail='Forbidden')
    return {'message': f"Welcome, {user['sub']}"}


@app.post('/lab11a/classify')
def classify(data: dict):
    return lab11a.classify(data.get('data'), data.get('source', 'at_rest'))


@app.post('/lab11b/anonymize')
def anonymize(data: dict):
    return lab11b.anonymize(data.get('rows'), data.get('quasi_identifiers'),
                            data.get('sensitive'), data.get('k', 2),
                            data.get('l', 1), data.get('t', 1.0), data.get('epsilon', 1.0))
