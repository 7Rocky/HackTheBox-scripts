#!/usr/bin/env python3

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

n = 113885866414967666002972488658501581523252563769498903942813659534669192201155190251383326523008134606996199193472232684661637386940661594327513591391999626564784682500337524012474617483098011060289946582371155292302705685943021986766584545105444481270761266224342249010400461266963638157749562695294713843509  
ct = bytes.fromhex('44a45518f4b49c2985a4e696d6fb48bc94e2e9e10b1b518786ab7205298d47250ae85ef69acd04f5daafdcdeda748eff1510ec8a42f1923dfd1bf893082eb7ebed7ca88441f92c1dac61ca5fdf0e9d968cf8213e2ca0a8e24dbfec2bbd58205c60abceb242025a1e8412a0a92a0ae7dd3d6bb0cde0bf28511376003ae907a52b')
p = '169785301867063487293453013833911015973907683687605489113424565682424824172371'
q = '02316166678868901218282182600315316354684047272123731927933503134218133661721'

p_digits = []
q_digits = []

for d in str(p):
    p_digits.append(d)
    p_digits.append('0')

p = int(''.join(p_digits[:-1]))

for d in str(q):
    q_digits.append('0')
    q_digits.append(d)

q_digits.append('0')

q = int(''.join(q_digits))

for i in range(len(q_digits)):
    if i % 2 == 0:
        while n % (10 ** (i + 1)) != (p * q) % (10 ** (i + 1)):
            q += 10 ** i
    else:
        while n % (10 ** (i + 1)) != (p * q) % (10 ** (i + 1)):
            p += 10 ** i

assert p * q == n

e = 65537
d = pow(e, -1, (p - 1) * (q - 1))
cipher = PKCS1_OAEP.new(RSA.construct((n, e, d)))
pt = cipher.decrypt(ct)
print(pt.decode())
