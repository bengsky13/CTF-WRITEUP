# Raid Safety Assays

We are given a script to encrypt the flag

```python
from Crypto.Util.number import  *
import random

p = getPrime(96)
q = getPrime(96)
n = p*q
e =  65537

flag =  b'ctf{0000000000000000}'
flag =  str(pow(bytes_to_long(flag), e, n))

perm =  list(range(10))
random.shuffle(perm)
perm =  list(map(str, perm))

c =  ''.join([perm[int(x)] for x in flag])
print(f'e = {e}')
print(f'n = {n}')
print(f'c = {c}')
```

The flag to this challenge is all lowercase, with no underscores.

```python
e = 65537
n = 4629059450272139917534568159172903078573041591191268130667
c = 6743459147531103219359362407406880068975344190794689965016
```

# Analyisis

This script performs a simple encryption operation using **RSA** with a fixed public exponent e and randomly generated primes p and q. It encrypts the flag string by converting it to a number, raising it to the power of e modulo n, and then **mapping the resulting characters using a permutation**. The encrypted string is printed as c, along with the values of e and n.

**So there was 2 encryption technique involves in this challenge**

# Solution

The first encryption technique is RSA
Luckily **n** is a weak number so we can find **p** and **q** easily using [FACTORDB](http://factordb.com/index.php?query=4629059450272139917534568159172903078573041591191268130667)

To perform RSA decryption, we need the private key, which consists of the modulus n, the private exponent d, and the prime factors p and q,. Since we have the prime factors p and q,, we can calculate the remaining components of the private key. Here's the RSA decryption algorithm in

```python
p = 73849754237166590568543300233
q = 62682123970325402653307817299
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
decrypted = pow(c, d, n)
decrypted = long_to_bytes(plaintext)
```

Since the c is encrypted with Permutation Cipher
but we don’t know the Permutation order therefore we need to **bruteforce** the Permutation Cipher
we can initialize the permutation order using **itertools**

```python
import itertools
permutations = list(itertools.permutations(range(10)))
```

it will generated all possible combination of permutation in range 0-10 (0, 1, 2, 3, 4, 5, 6, 7, 8 ,9)
and this is the final solver

```python
import random
import itertools
from Crypto.Util.number import long_to_bytes
def reversePermutation(cipher, permut):
    permut = [str(x) for x in permut]
    result = ""
    for x in cipher:
        result += str(permut.index(x))
    return result
def rsaDecrypt(c, d, n):
   plaintext = pow(c, d, n)
   plaintext = long_to_bytes(plaintext)
   return plaintext

p = 73849754237166590568543300233
q = 62682123970325402653307817299
n = p * q
e = 65537

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
permutations = list(itertools.permutations(range(10)))
for i in permutations:
    permut_c = "6743459147531103219359362407406880068975344190794689965016"
    reversed = reversePermutation(permut_c, i)
    flag = rsaDecrypt(int(reversed), d, n)
    try:
        flag = flag.decode()
        if "ctf{" in flag.lower():
            print(flag)
        break
    except:
        print("Failed ", permut_c , " with ", i)
```

The program will do bruteforcing to reverse the Permutation Cipher with all combination permutation order, after obtain the result within the order of the permutation it will try to decrypt with RSA algorithm

after obtain the decrypted RSA in byte it will try to decode it to printable ascii character when it success decoding it will convert the flag to lower for check is there any "ctf{" in the flag
and here is the flag
**ctf{cryptpainfulflag}**
