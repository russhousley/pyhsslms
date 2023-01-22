# pyhsslms

HSS/LMS Digital Signature library for Python
--------------------------------------------
[PyPI](https://pypi.org/project/pyhsslms)

[Python Versions](https://pypi.org/project/pyhsslms/)

[GitHub license](https://raw.githubusercontent.com/russhousley/pyhsslms/master/LICENSE.txt)

This Python package contains a free and open source implementation of
HSS/LMS Hash-based Digital Signatures as defined in [RFC 8554](https://www.rfc-editor.org/rfc/rfc8554.txt).

Features
--------

* Generate HSS/LMS private keys and then sign with them
* Validate signatures with HSS/LMS public keys
* 100% Python, works with Python 2.7 and 3.5+

How to use pyhsslms
-------------------

Generate a HSS/LMS private key:

```python
priv_key = pyhsslms.HssLmsPrivateKey.genkey('mykey', levels=2)
```

The private key is stored in mykey.prv, and the public key is
stored in mykey.pub.  Of course, the mykey.prv must be protected
from disclosure, and it gets updated every time a signature is
created.  Restoring mykey.prv from backup can cause a node in the
tree to be used more that once, forfeiting all security.


Sign a file with a HSS/LMS private key:

```python
priv_key.signFile('myfile.txt')
```
The private key was generated above is used to sign the content of
myfile.txt, and the signature is stored in myfile.txt.sig.


Sign a buffer with a HSS/LMS private key:

```python
sigbuf = prv_key.sign(buffer)
```
The private key was generated above is used to sign the content of
buffer, and the signature is returned in sigbuf.


Verify a signature on a file with a HSS/LMS public key:

```python
pub_key = pyhsslms.HssLmsPublicKey('mykey')
if pub_key.verifyFile('myfile.txt'):
    print('Signature is valid')
else:
    print('Signature is NOT valid!')
```


Verify a signature on a buffer with a HSS/LMS public key:

```python
pub_key = pyhsslms.HssLmsPublicKey('mykey')
validity = pub_key.verify(buffer, sigbuf)
if validity:
    print('Signature is valid')
else:
    print('Signature is NOT valid!')
```

Use different parameter sets on different LMS levels:

```python
T = [pyhsslms.lms_sha256_m24_h5, pyhsslms.lms_shake_m32_h10] 
L = [pyhsslms.lmots_sha256_n32_w8, pyhsslms.lmots_shake_n24_w4]
priv_key = pyhsslms.HssLmsPrivateKey.genkey('mykey', levels=2, lms_type=T, lmots_type=L)
```

If you want the hierarchy to be homogeneous do either:

```python
T = [pyhsslms.lms_shake_m24_h5]*2 
L = [pyhsslms.lmots_shake_n24_w8]*2
priv_key = pyhsslms.HssLmsPrivateKey.genkey('mykey', levels=2, lms_type=T, lmots_type=L)
```

or

```python
T = pyhsslms.lms_shake_m24_h5 
L = pyhsslms.lmots_shake_n24_w8
priv_key = pyhsslms.HssLmsPrivateKey.genkey('mykey', levels=2, lms_type=T, lmots_type=L)
```

How to get pyhsslms
-------------------

The pyhsslms package is distributed under terms and conditions of
[license](https://raw.githubusercontent.com/russhousley/pyhsslms/master/LICENSE.txt).

Source code is freely available as a GitHub [repo](https://github.com/russhousley/pyhsslms).

You could `pip install pyhsslms` or download it from [PyPI](https://pypi.org/project/pyhsslms).

Copyright (c) 2020, Vigil Security, LLC
All rights reserved.
