# pyhsslms.py
#
# Provide routines for HSS/LMS Hash-based Signatures as defined
# in RFC 8554.  It uses the same .pub and .sig file format as the
# C code made available by Cisco Systems, Inc. in GitHub at
# https://github.com/cisco/hash-sigs/
#
# For simplicity of the interfaces, all of the trees in the HSS
# private key hierarchy are the same size; however, the signature
# verification code works correctly on signatures that are generated
# by another program that allows different tree sizes in the hierarchy.
#
#
# Copyright (c) 2020-2021, Vigil Security, LLC
# All rights reserved.
#
# Redistribution and use, with or without modification, are permitted
# provided that the following conditions are met:
#
# (1) Redistributions must retain the above copyright notice, this
#     list of conditions, and the following disclaimer.
#
# (2) Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the following
#     disclaimer in the documentation and/or other materials provided
#     with the distribution.
#
# (3) Neither the name of the Vigil Security, LLC nor the names of the
#     contributors to this code may be used to endorse or promote any
#     products derived from this software without specific prior written
#     permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
# COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
# OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) REGARDLESS OF THE
# CAUSE AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
# WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


import os
import hashlib
from .compat import NoFileError, FoundFileError
from .compat import randBytes, toBytes, toHex, fromHex
from .compat import charNum, u32, u16, u8, int32, shake256


# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------

# LMOTS typecodes and parameters
#
lmots_sha256_n32_w1 = fromHex('00000001')
lmots_sha256_n32_w2 = fromHex('00000002')
lmots_sha256_n32_w4 = fromHex('00000003')
lmots_sha256_n32_w8 = fromHex('00000004')
lmots_sha256_n24_w1 = fromHex('00000005')
lmots_sha256_n24_w2 = fromHex('00000006')
lmots_sha256_n24_w4 = fromHex('00000007')
lmots_sha256_n24_w8 = fromHex('00000008')
lmots_shake_n32_w1  = fromHex('00000009')
lmots_shake_n32_w2  = fromHex('0000000A')
lmots_shake_n32_w4  = fromHex('0000000B')
lmots_shake_n32_w8  = fromHex('0000000C')
lmots_shake_n24_w1  = fromHex('0000000D')
lmots_shake_n24_w2  = fromHex('0000000E')
lmots_shake_n24_w4  = fromHex('0000000F')
lmots_shake_n24_w8  = fromHex('00000010')

lmots_params = {
    #                     alg         n   p    w  ls
    lmots_sha256_n32_w1: ('sha256',   32, 265, 1, 7), 
    lmots_sha256_n32_w2: ('sha256',   32, 133, 2, 6), 
    lmots_sha256_n32_w4: ('sha256',   32,  67, 4, 4), 
    lmots_sha256_n32_w8: ('sha256',   32,  34, 8, 0),
    lmots_sha256_n24_w1: ('sha256',   24, 200, 1, 8),
    lmots_sha256_n24_w2: ('sha256',   24, 101, 2, 6),
    lmots_sha256_n24_w4: ('sha256',   24,  51, 4, 4),
    lmots_sha256_n24_w8: ('sha256',   24,  26, 8, 0),
    lmots_shake_n32_w1:  ('shake256', 32, 265, 1, 7), 
    lmots_shake_n32_w2:  ('shake256', 32, 133, 2, 6),
    lmots_shake_n32_w4:  ('shake256', 32,  67, 4, 4),
    lmots_shake_n32_w8:  ('shake256', 32,  34, 8, 0),
    lmots_shake_n24_w1:  ('shake256', 24, 200, 1, 8),
    lmots_shake_n24_w2:  ('shake256', 24, 101, 2, 6),
    lmots_shake_n24_w4:  ('shake256', 24,  51, 4, 4),
    lmots_shake_n24_w8:  ('shake256', 24,  26, 8, 0) }


# LMS typecodes and parameters
#
lms_sha256_m32_h5  = fromHex('00000005')
lms_sha256_m32_h10 = fromHex('00000006')
lms_sha256_m32_h15 = fromHex('00000007')
lms_sha256_m32_h20 = fromHex('00000008')
lms_sha256_m32_h25 = fromHex('00000009')
lms_sha256_m24_h5  = fromHex('0000000A')
lms_sha256_m24_h10 = fromHex('0000000B')
lms_sha256_m24_h15 = fromHex('0000000C')
lms_sha256_m24_h20 = fromHex('0000000D')
lms_sha256_m24_h25 = fromHex('0000000E')
lms_shake_m32_h5   = fromHex('0000000F')
lms_shake_m32_h10  = fromHex('00000010')
lms_shake_m32_h15  = fromHex('00000011')
lms_shake_m32_h20  = fromHex('00000012')
lms_shake_m32_h25  = fromHex('00000013')
lms_shake_m24_h5   = fromHex('00000014')
lms_shake_m24_h10  = fromHex('00000015')
lms_shake_m24_h15  = fromHex('00000016')
lms_shake_m24_h20  = fromHex('00000017')
lms_shake_m24_h25  = fromHex('00000018')

lms_params = {
    #                    alg         m    h 
    lms_sha256_m32_h5:  ('sha256',   32,  5), 
    lms_sha256_m32_h10: ('sha256',   32, 10), 
    lms_sha256_m32_h15: ('sha256',   32, 15), 
    lms_sha256_m32_h20: ('sha256',   32, 20),
    lms_sha256_m32_h25: ('sha256',   32, 25),
    lms_sha256_m24_h5:  ('sha256',   24,  5),
    lms_sha256_m24_h10: ('sha256',   24, 10),
    lms_sha256_m24_h15: ('sha256',   24, 15),
    lms_sha256_m24_h20: ('sha256',   24, 20),
    lms_sha256_m24_h25: ('sha256',   24, 25),
    lms_shake_m32_h5:   ('shake256', 32,  5), 
    lms_shake_m32_h10:  ('shake256', 32, 10), 
    lms_shake_m32_h15:  ('shake256', 32, 15), 
    lms_shake_m32_h20:  ('shake256', 32, 20),
    lms_shake_m32_h25:  ('shake256', 32, 25),
    lms_shake_m24_h5:   ('shake256', 24,  5),
    lms_shake_m24_h10:  ('shake256', 24, 10),
    lms_shake_m24_h15:  ('shake256', 24, 15),
    lms_shake_m24_h20:  ('shake256', 24, 20),
    lms_shake_m24_h25:  ('shake256', 24, 25) }


# Size-related constants
#
MaxHssLevels = 8
LenI = 16
LenS = LenI + 4


# Diversification constants
#
D_PBLC = fromHex('8080') # hash of iterations in the LM-OTS 
D_MESG = fromHex('8181') # hash of the message in the LMOTS
D_LEAF = fromHex('8282') # for hash of a leaf in LMS tree
D_INTR = fromHex('8383') # for hash of an interior node in LMS tree
D_PRG  = fromHex('ff')   # for computing LMS private keys


# Error strings for ValueError
#
err_pub_file_not_found    = 'public key file not found'
err_unknown_typecode      = 'unrecognized typecode'
err_bad_algorithm         = 'unsupported hash algorithm'
err_bad_length            = 'parameter has wrong length'
err_bad_value             = 'parameter has unknown value'
err_bad_number_of_levels  = 'unsupported number of levels'
err_private_key_exhausted = 'private key is exhausted'
err_algorithm_mismatch    = 'LMOTS and LMS with different hash algorithms'

# ----------------------------------------------------------------------
# The internal utility routines
# ----------------------------------------------------------------------

def H(alg, buf, rvlen):
    """
    Hash a buffer
    :param alg: the hash algorithm to use
    :param buf: input to be hashed
    :param rvlen: length of the returned value
    :return: hash value, either 24 bytes or 32 bytes
    """
    if rvlen not in (32, 24):
        raise ValueError(err_bad_length, str(rvlen))
    if alg == 'sha256':
        h = hashlib.sha256()
        h.update(buf)
        rv = h.digest()[0:rvlen]
    elif alg == 'shake256':
        h = shake256()
        h.update(buf)
        rv = h.digest(rvlen)
    else:
        raise ValueError(err_bad_algorithm, alg)
    return rv


def H_start(alg):
    """
    Start a hash computation
    :param alg: the hash algorithm to use
    :return: a handle for H_update and H_finish
    """
    if alg == 'sha256':
        h = hashlib.sha256()
    elif alg == 'shake256':
        h = shake256()
    else:
        raise ValueError(err_bad_algorithm, alg)
    return h


def H_update(h, buf):
    """
    Update a hash computation
    :param h: the handle from H_start
    :param buf: input for the hash computation
    """
    h.update(buf)
    return


def H_finish(h, rvlen):
    """
    Finish a hash computation
    :param h: the handle from H_start
    :param rvlen: length of the returned value
    :return: hash value, either 24 bytes or 32 bytes
    """
    if rvlen not in (32, 24):
        raise ValueError(err_bad_length, str(rvlen))
    if h.name == 'sha256':
        rv = h.digest()[0:rvlen]
    elif h.name == 'shake_256':
        rv = h.digest(rvlen)
    return rv


def coef(S, i, w):
    """
    Return the i-th, w-bit value, of S
    :param S: the bytes
    :param i: the i-th value (an integer)
    :param w: either 1, 2, 4, or 8 (an integer)
    :return: the coef value
    """
    return ((2**w)-1) & (charNum(S[(i*w)//8]) >> (8-(w*(i%(8//w))+w)))


def checksum(x, w, ls):
    """
    Checksum Calculation from RFC 8554, Section 4.4
    :param x: the bytes to checksum
    :param w: either 1, 2, 4, or 8 (an integer)
    :param ls: the number of left-shift bits (an integer)
    :return: the 16-bit checksum value
    """ 
    sum = 0
    num_coefs = len(x)*(8//w)
    for i in range(0, num_coefs):
        sum = sum + ((2**w)-1) - coef(x, i, w)
    return u16(sum << ls)


def serialize_list(l):
    """
    Concatenate the list members one after another
    :param l: list that will be serialized
    :return: bytes representing the list
    """
    result = toBytes('')
    for e in l:
        result += e
    return result


# ----------------------------------------------------------------------
# The LM-OTS routines
# ----------------------------------------------------------------------

class LmotsSignature():
    """
    Leighton-Micali One Time Signature
    """
    def __init__(self, C, y, typecode=lmots_sha256_n32_w8):
        self.C = C
        self.y = y
        self.type = typecode

    def serialize(self):
        return self.type + self.C + serialize_list(self.y)

    def buildPublic(self, S, message):
        alg, n, p, w, ls = lmots_params[self.type]
        if len(S) != LenS:
            raise ValueError(err_bad_length, str(len(S)))
        hash1 = H(alg, S + D_MESG + self.C + message, n)
        V = hash1 + checksum(hash1, w, ls)
        hash = H_start(alg)
        H_update(hash, S + D_PBLC)
        for i, y in enumerate(self.y):
            tmp = y
            for j in range(coef(V, i, w), (2**w)-1):
                tmp = H(alg, S + u16(i) + u8(j) + tmp, n)
            H_update(hash, tmp)
        return H_finish(hash, n)

    @classmethod
    def deserialize(cls, buffer):
        if len(buffer) < 4:
            raise ValueError(err_bad_length, str(len(buffer)))
        lmots_type = buffer[0:4]
        if lmots_type not in lmots_params:
           raise ValueError(err_unknown_typecode, toHex(lmots_type))
        alg, n, p, w, ls = lmots_params[lmots_type]
        if len(buffer) != 4+(n*(p+1)):
            raise ValueError(err_bad_length, str(len(buffer)))
        C = buffer[4:n+4]
        y = []
        pos = n+4
        for i in range(0, p):
            y.append(buffer[pos:pos+n])
            pos += n
        return cls(C, y, lmots_type)

    @classmethod
    def sizeof(cls, buffer):
        if len(buffer) < 4:
            raise ValueError(err_bad_length, str(len(buffer)))
        lmots_type = buffer[0:4]
        if lmots_type not in lmots_params:
           raise ValueError(err_unknown_typecode, toHex(lmots_type))
        alg, n, p, w, ls = lmots_params[lmots_type]
        rv = 4+(n*(p+1))
        if len(buffer) < rv:
            raise ValueError(err_bad_length, str(len(buffer)))
        return rv

    def prettyPrint(self):
        rv = "LMOTS signature\n"
        rv += ("   LMOTS type: %s\n" % toHex(self.type))
        rv += ("   C         : %s\n" % toHex(self.C))
        for i, e in enumerate(self.y):
            rv += ("   y[%03d]    : %s\n" % (i, toHex(e), ))
        return rv


class LmotsPrivateKey:
    """
    Leighton-Micali One Time Signature Private Key
    """
    # Generate an LMOTS Private Key
    #
    def __init__(self, S=None, SEED=None, lmots_type=lmots_sha256_n32_w8):
        if lmots_type not in lmots_params:
            raise ValueError(err_unknown_typecode, toHex(lmots_type))
        self.type = lmots_type
        alg, n, p, w, ls = lmots_params[lmots_type]
        if S is None:
            self.S = randBytes(LenS)
        else:
            if len(S) != LenS:
                raise ValueError(err_bad_length, str(len(S)))
            self.S = S
        if SEED is None:
            self.SEED = randBytes(n)
        else:
            if len(SEED) != n:
                raise ValueError(err_bad_length, str(len(SEED)))
            self.SEED = SEED
        self._signatures_remaining = 1

    def remaining(self):
        return self._signatures_remaining

    def is_exhausted(self):
        return not bool(self._signatures_remaining)

    def publicKey(self): 
        alg, n, p, w, ls = lmots_params[self.type]
        hash = H_start(alg)
        H_update(hash, self.S + D_PBLC)
        for i in range(0, p):
            tmp = H(alg, self.S + u16(i+1) + D_PRG + self.SEED, n)
            for j in range(0, (2**w)-1):
                tmp = H(alg, self.S + u16(i) + u8(j) + tmp, n)
            H_update(hash, tmp)
        return LmotsPublicKey(self.S, H_finish(hash, n), self.type)

    def sign(self, message):
        if self._signatures_remaining != 1:
            raise ValueError(err_private_key_exhausted)
        alg, n, p, w, ls = lmots_params[self.type]
        C = randBytes(n)
        hash1 = H(alg, self.S + D_MESG + C + message, n)
        V = hash1 + checksum(hash1, w, ls)
        y = []
        for i in range(0, p):
            tmp = H(alg, self.S + u16(i+1) + D_PRG + self.SEED, n)
            for j in range(0, coef(V, i, w)):
                tmp = H(alg, self.S + u16(i) + u8(j) + tmp, n)
            y.append(tmp)
        self._signatures_remaining = 0
        return LmotsSignature(C, y, self.type).serialize()

    def prettyPrint(self):
        rv = "LMOTS private key\n"
        rv += ("   LMOTS type: %s\n" % toHex(self.type))
        rv += ("   S         : %s\n" % toHex(self.S))
        rv += ("   SEED      : %s\n" % toHex(self.SEED))
        return rv


class LmotsPublicKey:
    """
    Leighton-Micali One Time Signature Public Key
    """
    def __init__(self, S, K, lmots_type):
        self.S = S
        self.K = K
        self.type = lmots_type

    def verify(self, message, sig):
        signature = LmotsSignature.deserialize(sig)
        if (signature.type != self.type):
            raise ValueError(err_unknown_typecode)
        alg, n, p, w, ls = lmots_params[self.type]
        hash1 = H(alg, self.S + D_MESG + signature.C + message, n)
        V = hash1 + checksum(hash1, w, ls)
        hash = H_start(alg)
        H_update(hash, self.S + D_PBLC)
        for i, tmp in enumerate(signature.y):
            for j in range(coef(V, i, w), (2**w)-1):
                tmp = H(alg, self.S + u16(i) + u8(j) + tmp, n)
            H_update(hash, tmp)
        return self.K == H_finish(hash, n)

    def serialize(self):
        return self.type + self.S + self.K 

    @classmethod
    def deserialize(cls, buffer):
        if len(buffer) < 4:
            raise ValueError(err_bad_length, str(len(buffer)))
        lmots_type = buffer[0:4]
        if lmots_type not in lmots_params():
           raise ValueError(err_unknown_typecode, toHex(lmots_type))
        alg, n, p, w, ls = lmots_params[lmots_type]
        if len(buffer) != 4+(2*n):
            raise ValueError(err_bad_length)
        S = buffer[4:4+n]
        K = buffer[4+n:4+2*n]
        return cls(S, K, lmots_type)

    @classmethod
    def sizeof(cls, buffer):
        if len(buffer) < 4:
            raise ValueError(err_bad_length, str(len(buffer)))
        lmots_type = buffer[0:4]
        if lmots_type not in lmots_params():
           raise ValueError(err_unknown_typecode, toHex(lmots_type))
        alg, n, p, w, ls = lmots_params[lmots_type]
        rv = 4+(2*n)
        if len(buffer) < rv:
            raise ValueError(err_bad_length, str(len(buffer)))
        return rv

    def prettyPrint(self):
        rv = "LMOTS public key\n"
        rv += ("   LMOTS type: %s\n" % toHex(self.type))
        rv += ("   S         : %s\n" % toHex(self.S))
        rv += ("   K         : %s\n" % toHex(self.K))
        return rv


# ----------------------------------------------------------------------
# The N-time Leighton-Micali Signature (LMS) signature routines
# ----------------------------------------------------------------------

class LmsSignature():
    """
    N-time Leighton-Micali Signature (LMS)
    """
    def __init__(self, leaf_num, lmots_sig, path, typecode=lms_sha256_m32_h5):
        if typecode not in lms_params:
            raise ValueError(err_unknown_typecode, toHex(typecode))
        if lmots_sig[0:4] not in lmots_params:
            raise ValueError(err_unknown_typecode, toHex(lmots_sig[0:4]))
        alg, m, h = lms_params[typecode]
        if len(path) != h:
            raise ValueError(err_bad_length, str(len(path)))
        self.lmots_sig = LmotsSignature.deserialize(lmots_sig)
        self.type = typecode    
        self.lmots_type = lmots_sig[0:4]
        self.q = leaf_num
        self.path = path

    def serialize(self):
        return u32(self.q) + LmotsSignature.serialize(self.lmots_sig) + \
               self.type + serialize_list(self.path)
    
    @classmethod
    def deserialize(cls, buffer):
        if len(buffer) < 8:
            raise ValueError(err_bad_length, str(len(buffer)))
        q = int32(buffer[0:4])
        lmots_type = buffer[4:8]
        if lmots_type not in lmots_params:
            raise ValueError(err_unknown_typecode, toHex(lmots_type))
        alg, n, p, w, ls = lmots_params[lmots_type]
        lmots_sig_size = 4+(n*(p+1))
        if len(buffer) < 4+lmots_sig_size:
            raise ValueError(err_bad_length, str(len(buffer)))
        lmots_sig = buffer[4:4+lmots_sig_size]
        rest = buffer[4+lmots_sig_size:]
        lms_type = rest[0:4]
        if lms_type not in lms_params:
            raise ValueError(err_unknown_typecode, toHex(lms_type))
        alg2, m, h = lms_params[lms_type]
        if (alg != alg2):
            raise ValueError(err_algorithm_mismatch, alg + ' and ' + alg2)
        pos = 4
        if (q >= 2**h):
            raise ValueError(err_bad_value, str(q))
        if len(rest) != 4+(m*h):
            raise ValueError(err_bad_value, str(len(buffer)))
        path = []
        for i in range(0, h):
            path.append(rest[pos:pos+m])
            pos = pos + m
        return cls(q, lmots_sig, path, typecode=lms_type)

    @classmethod
    def sizeof(cls, buffer):
        if len(buffer) < 8:
            raise ValueError(err_bad_length, str(len(buffer)))
        lmots_type = buffer[4:8]
        if lmots_type not in lmots_params:
            raise ValueError(err_unknown_typecode, toHex(lmots_type))
        alg, n, p, w, ls = lmots_params[lmots_type]
        lmots_sig_size = 4+(n*(p+1))
        if len(buffer) < 4+lmots_sig_size:
            raise ValueError(err_bad_length, str(len(buffer)))
        lmots_sig = buffer[4:4+lmots_sig_size]
        lms_type = buffer[4+lmots_sig_size:8+lmots_sig_size]
        if lms_type not in lms_params:
            raise ValueError(err_unknown_typecode, toHex(lms_type))
        alg2, m, h = lms_params[lms_type]
        if (alg != alg2):
            raise ValueError(err_algorithm_mismatch, alg + ' and ' + alg2)
        rv = 4+lmots_sig_size+4+(h*m)
        if len(buffer) < rv:
            raise ValueError(err_bad_length, str(len(buffer)))
        return rv

    def prettyPrint(self):
        rv = "LMS signature\n"
        rv += ("   q         : %s\n" % toHex(u32(self.q)))
        rv += ("   LMOTS type: %s\n" % toHex(self.lmots_sig.type))
        rv += ("   C         : %s\n" % toHex(self.lmots_sig.C))
        for i, e in enumerate(self.lmots_sig.y):
            rv += ("   y[%03d]    : %s\n" % (i, toHex(e), ))
        rv += ("   LMS type  : %s\n" % toHex(self.type))
        for i, e in enumerate(self.path):
            rv += ("   path[%02d]  : %s\n" % (i, toHex(e), ))
        return rv


class LmsPrivateKey(object):
    """
    N-Time Leighton-Micali Signature (LMS) Private Key
    """
    def __init__(self, lms_type=lms_sha256_m32_h5,
                 lmots_type=lmots_sha256_n32_w8, SEED=None, I=None, q=0):
        if lmots_type not in lmots_params:
            raise ValueError(err_unknown_typecode, toHex(lmots_type))
        if lms_type not in lms_params:
            raise ValueError(err_unknown_typecode, toHex(lms_type))
        alg, n, p, w, ls = lmots_params[lmots_type]
        alg2, m, h = lms_params[lms_type]
        if (alg != alg2):
            raise ValueError(err_algorithm_mismatch, alg + ' and ' + alg2)
        self.lms_type = lms_type
        self.lmots_type = lmots_type
        if I is None:
            self.I = randBytes(LenI)
        else:
            if len(I) != LenI:
                raise ValueError(err_bad_length, str(len(I)))
            self.I = I
        if SEED is None:
            self.SEED = randBytes(n)
        else:
            if len(SEED) != n:
                raise ValueError(err_bad_length, str(len(SEED)))
            self.SEED = SEED 
        self.ots_priv = []
        self.ots_pub = []
        self._nodes = {}
        for j in range(0, 2**h):
            S = self.I + u32(j)
            priv = LmotsPrivateKey(S=S, SEED=self.SEED, lmots_type=lmots_type)
            pub = priv.publicKey()
            self.ots_priv.append(priv)
            self.ots_pub.append(pub)
        self.pub = self._T(1)
        self.q = q

    # Computes the root and other nodes
    #
    def _T(self, r):
        alg2, m, h = lms_params[self.lms_type]
        if (r >= 2**h):
            self._nodes[r] = H(alg2, self.I + u32(r) + D_LEAF + \
                               self.ots_pub[r-(2**h)].K, m)
        else:
            self._nodes[r] = H(alg2, self.I + u32(r) + D_INTR + \
                               self._T(2*r) + self._T((2*r)+1), m)
        return self._nodes[r] 

    def serialize(self):
        return self.lms_type + self.lmots_type + self.SEED + \
               self.I + u32(self.q)

    @classmethod
    def deserialize(cls, buffer):
        lms_type = buffer[0:4]
        lmots_type = buffer[4:8]
        if lmots_type not in lmots_params:
            raise ValueError(err_unknown_typecode, toHex(lmots_type))
        if lms_type not in lms_params:
            raise ValueError(err_unknown_typecode, toHex(lms_type))
        alg, n, p, w, ls = lmots_params[lmots_type]
        alg2, m, h = lms_params[lms_type]
        if (alg != alg2):
            raise ValueError(err_algorithm_mismatch, alg + ' and ' + alg2)
        SEED = buffer[8:8+n]
        I = buffer[8+n:8+n+LenI]
        q = int32(buffer[8+n+LenI:8+n+LenI+4])
        return cls(lms_type, lmots_type, SEED, I, q)

    def path(self, node_num):
        p = []
        while node_num > 1:
            if (node_num % 2):
                p.append(self._nodes[node_num-1])
            else:
                p.append(self._nodes[node_num+1])
            node_num = node_num//2
        return p
        
    def sign(self, message):
        alg, m, h = lms_params[self.lms_type]
        if (self.q >= 2**h):
            raise ValueError(err_private_key_exhausted)
        ots_sig = self.ots_priv[self.q].sign(message)
        p = self.path(self.q + 2**h)
        leaf_num = self.q
        self.q += 1
        return u32(leaf_num) + ots_sig + self.lms_type + serialize_list(p)
        
    def publicKey(self):
        return LmsPublicKey(self.I, self.pub, self.lms_type, self.lmots_type)

    def remaining(self):
        alg2, m, h = lms_params[self.lms_type]
        return (2**h)-self.q

    def is_exhausted(self):
        return not bool(self.remaining())

    def maxSignatures(self):
        alg2, m, h = lms_params[self.lms_type]
        return 2**h

    def prettyPrint(self):
        rv = "LMS private key\n"
        rv += ("   LMS type  : %s\n" % toHex(self.lms_type))
        rv += ("   LMOTS type: %s\n" % toHex(self.lmots_type))
        rv += ("   I         : %s\n" % toHex(self.I))
        rv += ("   SEED      : %s\n" % toHex(self.SEED))
        rv += ("   q         : %s\n" % toHex(u32(self.q)))
        rv += ("   pub       : %s\n" % toHex(self.pub))
        rv += ("   max signs : %d\n" % self.maxSignatures())
        return rv


class LmsPublicKey(object):
    """
    N-time Leighton-Micali Signature (LMS) Public Key
    """
    def __init__(self, I, K, lms_type, lmots_type):
        self.I = I
        self.K = K
        self.lms_type = lms_type
        self.lmots_type = lmots_type

    def verify(self, message, sig):
        alg2, m, h = lms_params[self.lms_type]
        alg, n, p, w, ls = lmots_params[self.lmots_type]
        if (alg != alg2):
            raise ValueError(err_algorithm_mismatch, alg + ' and ' + alg2)
        lms_sig = LmsSignature.deserialize(sig)
        if lms_sig.type != self.lms_type:
            return False
        if len(lms_sig.path) != h:
            return False
        if lms_sig.q > 2**h:
            return False
        S = self.I + u32(lms_sig.q)
        Kc = lms_sig.lmots_sig.buildPublic(S, message)
        node_num = lms_sig.q + (2**h)
        tmp = H(alg, self.I + u32(node_num) + D_LEAF + Kc, m)
        for pv in lms_sig.path:
            if (node_num % 2):
                 tmp = H(alg, self.I + u32(node_num//2) + D_INTR + pv + tmp, m)
            else:
                 tmp = H(alg, self.I + u32(node_num//2) + D_INTR + tmp + pv, m)
            node_num = node_num//2
        return bool(tmp == self.K)

    def serialize(self):
        return self.lms_type + self.lmots_type + self.I + self.K

    @classmethod
    def deserialize(cls, buffer):
        if len(buffer) < 8:
            raise ValueError(err_bad_length, str(len(buffer)))
        lms_type = buffer[0:4]
        if lms_type not in lms_params:
            raise ValueError(err_unknown_typecode, toHex(lms_type))
        alg2, m, h = lms_params[lms_type]
        lmots_type = buffer[4:8]
        if lmots_type not in lmots_params:
            raise ValueError(err_unknown_typecode, toHex(lmots_type))
        if len(buffer) < 8+LenI+m:
            raise ValueError(err_bad_length, str(len(buffer)))
        I = buffer[8:8+LenI]
        K = buffer[8+LenI:8+LenI+m]
        return cls(I, K, lms_type, lmots_type)

    @classmethod
    def sizeof(cls, buffer):
        if len(buffer) < 8:
            raise ValueError(err_bad_length, str(len(buffer)))
        lms_type = buffer[0:4]
        if lms_type not in lms_params:
            raise ValueError(err_unknown_typecode, toHex(lms_type))
        alg2, m, h = lms_params[lms_type]
        lmots_type = buffer[4:8]
        if lmots_type not in lmots_params:
            raise ValueError(err_unknown_typecode, toHex(lmots_type))
        rv = 8+LenI+m
        if len(buffer) < rv:
            raise ValueError(err_bad_length, str(len(buffer)))
        return rv

    def maxSignatures(self):
        alg2, m, h = lms_params[self.lms_type]
        return 2**h
    
    def prettyPrint(self):
        rv = "LMS public key\n"
        rv += ("   LMS type  : %s\n" % toHex(self.lms_type))
        rv += ("   LMOTS type: %s\n" % toHex(self.lmots_type))
        rv += ("   I         : %s\n" % toHex(self.I))
        rv += ("   K         : %s\n" % toHex(self.K))
        rv += ("   max signs : %d\n" % self.maxSignatures())
        return rv


# ----------------------------------------------------------------------
# The Hierarchical Signature System (HSS)
# ----------------------------------------------------------------------

class HssSignature():
    """
    Hierarchical Signature System (HSS) Signature
    """
    def __init__(self, levels, publist, siglist, lms_sig):
        if levels < 1 or levels > MaxHssLevels:
            ValueError(err_bad_number_of_levels, str(levels))
        self.levels = levels
        if len(publist) != levels:
            ValueError(err_bad_length, str(len(publist)))
        if len(siglist) != levels:
            ValueError(err_bad_length, str(len(siglist)))
        self.pub = []
        self.sig = []
        for i in range(0, levels-1):
            self.pub.append(publist[i])
            self.sig.append(siglist[i])
        self.lms_sig = lms_sig

    def serialize(self):
        rv = u32(self.levels - 1)
        for i in range(0, self.levels-1):
            rv += self.sig[i].serialize()
            rv += self.pub[i].serialize()
        return rv + self.lms_sig.serialize()

    @classmethod
    def deserialize(cls, buffer):
        if len(buffer) < 4:
            ValueError(err_bad_length, str(len(buffer)))
        levels = int32(buffer[0:4]) + 1
        if levels < 1 or levels > MaxHssLevels:
            ValueError(err_bad_number_of_levels, str(levels))
        siglist = []
        publist = []
        rest = buffer[4:]
        for i in range(0, levels-1):
            length = LmsSignature.sizeof(rest)
            lms_sig = LmsSignature.deserialize(rest[0:length])
            rest = rest[length:]
            length = LmsPublicKey.sizeof(rest)
            lms_pub = LmsPublicKey.deserialize(rest[0:length])
            rest = rest[length:]
            siglist.append(lms_sig)
            publist.append(lms_pub)
        length = LmsSignature.sizeof(rest)
        if len(rest) != length:
            ValueError(err_bad_length, str(len(buffer)))
        msg_sig = LmsSignature.deserialize(rest[0:length])
        return cls(levels, publist, siglist, msg_sig)

    def prettyPrint(self):
        rv = "HSS signature\n"
        rv += ("   Nspk      : %s\n" % toHex(u32(self.levels - 1)))
        for j in range(0, self.levels-1):
            rv += ("   sig[%02d]   : LMS Signature\n" % j)
            rv += ("   q         : %s\n" % toHex(u32(self.sig[j].q)))
            rv += ("   LMOTS type: %s\n" % toHex(self.sig[j].lmots_sig.type))
            rv += ("   C         : %s\n" % toHex(self.sig[j].lmots_sig.C))
            for i, e in enumerate(self.sig[j].lmots_sig.y):
                rv += ("   y[%03d]    : %s\n" % (i, toHex(e), ))
            rv += ("   LMS type  : %s\n" % toHex(self.sig[j].type))
            for i, e in enumerate(self.sig[j].path):
                rv += ("   path[%02d]  : %s\n" % (i, toHex(e), ))
            rv += ("   pub[%02d]   : LMS public key\n" % j)
            rv += ("   LMS type  : %s\n" % toHex(self.pub[j].lms_type))
            rv += ("   LMOTS type: %s\n" % toHex(self.pub[j].lmots_type))
            rv += ("   I         : %s\n" % toHex(self.pub[j].I))
            rv += ("   K         : %s\n" % toHex(self.pub[j].K))
        rv += "   LMS sig   : LMS Signature\n"
        rv += ("   q         : %s\n" % toHex(u32(self.lms_sig.q)))
        rv += ("   LMOTS type: %s\n" % toHex(self.lms_sig.lmots_sig.type))
        rv += ("   C         : %s\n" % toHex(self.lms_sig.lmots_sig.C))
        for i, e in enumerate(self.lms_sig.lmots_sig.y):
            rv += ("   y[%03d]    : %s\n" % (i, toHex(e), ))
        rv += ("   LMS type  : %s\n" % toHex(self.lms_sig.type))
        for i, e in enumerate(self.lms_sig.path):
            rv += ("   path[%02d]  : %s\n" % (i, toHex(e), ))
        return rv


class HssPrivateKey(object):
    """
    Hierarchical Signature System (HSS) Private Key
    """
    def __init__(self, levels=2, lms_type=lms_sha256_m32_h5,
                 lmots_type=lmots_sha256_n32_w8, SEED=None,
                 remaining_signatures=None, prv0=None):
        if levels < 1 or levels > MaxHssLevels:
            ValueError(err_bad_number_of_levels, str(levels))
        if lmots_type not in lmots_params:
            raise ValueError(err_unknown_typecode, toHex(lmots_type))
        if lms_type not in lms_params:
            raise ValueError(err_unknown_typecode, toHex(lms_type))
        self.levels = levels
        self.lms_type = lms_type
        self.lmots_type = lmots_type
        alg2, m, h = lms_params[lms_type]
        alg, n, p, w, ls = lmots_params[lmots_type]
        if (alg != alg2):
            raise ValueError(err_algorithm_mismatch, alg + ' and ' + alg2)
        if SEED is None:
            self.SEED = randBytes(n)
        else:
            if len(SEED) != n:
                raise ValueError(err_bad_length, str(len(SEED)))
            self.SEED = SEED
        if prv0 is None:
            prv0 = LmsPrivateKey(lms_type=lms_type,
                                 lmots_type=lmots_type, SEED=SEED)
        self.prv = [prv0]
        if remaining_signatures is None:
            self._signatures_remaining = 2**(levels*h)
        else:
            self._signatures_remaining = remaining_signatures
        self.pub = [prv0.publicKey()]
        self.sig = []
        for i in range(1, self.levels):
            self.prv.append(LmsPrivateKey(
                lms_type=lms_type, lmots_type=lmots_type, SEED=SEED))
            self.pub.append(self.prv[-1].publicKey())
            self.sig.append(self.prv[-2].sign(self.pub[-1].serialize()))

    def sign(self, message):
        if self._signatures_remaining == 0:
            raise ValueError(err_private_key_exhausted)
        # remove exhausted trees
        while (self.prv[-1].is_exhausted()):
            self.prv.pop()
            self.pub.pop()
            self.sig.pop()
        # refresh exhausted trees
        while (len(self.prv) < self.levels):
            self.prv.append(LmsPrivateKey(lms_type=self.lms_type,
                                lmots_type=self.lmots_type, SEED=self.SEED))
            self.pub.append(self.prv[-1].publicKey())
            self.sig.append(self.prv[-2].sign(self.pub[-1].serialize()))           
        # sign message
        self._signatures_remaining += -1
        msg_sig = self.prv[-1].sign(message)
        rv = u32(self.levels-1)
        for i in range(0, self.levels - 1):
            rv += self.sig[i] + self.pub[i+1].serialize()
        rv += msg_sig
        return rv

    def publicKey(self):
        return HssPublicKey(self.pub[0], self.levels)

    def remaining(self):
        return self._signatures_remaining

    def is_exhausted(self):
        return not bool(self._signatures_remaining)

    def maxSignatures(self):
        alg2, m, h = lms_params[self.lms_type]
        return 2**(self.levels*h)

    def serialize(self):
        assert self._signatures_remaining.bit_length() <= 32, "_signatures_remaining=0x%x, %d bits"%(self._signatures_remaining,self._signatures_remaining.bit_length())
        return u32(self.levels) + u32(self._signatures_remaining) + \
               self.prv[0].serialize()

    @classmethod
    def deserialize(cls, buffer):
        if len(buffer) < 8:
            raise ValueError(err_bad_length, str(len(buffer)))
        levels = int32(buffer[0:4])
        rs = int32(buffer[4:8])
        prv = LmsPrivateKey.deserialize(buffer[8:])
        return cls(levels, lms_type=prv.lms_type, lmots_type=prv.lmots_type, \
                   remaining_signatures=rs, prv0=prv)

    def prettyPrint(self):
        rv = "HSS private key\n"
        rv += ("   levels    : %01d\n" % self.levels)
        for i, prv in enumerate(self.prv):
            rv += ("   level=%01d   : LMS private key\n" % i)
            rv += ("   LMS type  : %s\n" % toHex(prv.lms_type))
            rv += ("   LMOTS type: %s\n" % toHex(prv.lmots_type))
            rv += ("   I         : %s\n" % toHex(prv.I))
            rv += ("   SEED      : %s\n" % toHex(prv.SEED))
            rv += ("   q         : %s\n" % toHex(u32(prv.q)))
            rv += ("   pub       : %s\n" % toHex(prv.pub))
        rv += ("   max signs : %d\n" % self.maxSignatures())
        return rv

class HssPublicKey(object):
    """
    Hierarchical Signature System (HSS) Public Key
    """
    def __init__(self, rootpub, levels):
        self.pub = rootpub
        self.levels = levels

    def verify(self, message, sig):
        hss_sig = HssSignature.deserialize(sig)
        if hss_sig.levels != self.levels:
            return False
        # verify the chain of signed public keys
        pk = self.pub
        for i in range(0, self.levels - 1):
            if pk.verify(hss_sig.pub[i].serialize(), hss_sig.sig[i].serialize()):
                pk = hss_sig.pub[i]
            else:
                return False
        # verify the signature on the message
        return pk.verify(message, hss_sig.lms_sig.serialize())  

    def serialize(self):
        return u32(self.levels) + self.pub.serialize()

    @classmethod
    def deserialize(cls, buffer):
        if len(buffer) < 4:
            ValueError(err_bad_length, str(len(buffer)))
        levels = int32(buffer[0:4])
        rootpub = LmsPublicKey.deserialize(buffer[4:])
        return cls(rootpub, levels)
        
    def maxSignatures(self):
        alg2, m, h = lms_params[self.pub.lms_type]
        return 2**(self.levels*h)

    def prettyPrint(self):
        rv = "HSS public key\n"
        rv += ("   levels    : %01d\n" % self.levels)
        rv += ("   LMS type  : %s\n" % toHex(self.pub.lms_type))
        rv += ("   LMOTS type: %s\n" % toHex(self.pub.lmots_type))
        rv += ("   I         : %s\n" % toHex(self.pub.I))
        rv += ("   K         : %s\n" % toHex(self.pub.K))
        rv += ("   max signs : %d\n" % self.maxSignatures())
        return rv


# ----------------------------------------------------------------------
# The public interface for the HSS/LMS signature and keys
# ----------------------------------------------------------------------

class HssLmsSignature():

    def __init__(self, filename):
        """
        Load a HSS/LMS signature from a file.

        Parameters
        ----------
        filename: :class:`str`
            The name of the signed file: filename.sig.

        Returns
        -------
        rv: :class:`HssLmsSignature`
            The HSS/LMS signature.

        Raises
        ------
        FileNotFoundError or IOError
            If filename.sig does not exist.
        """
        if filename.endswith('.sig'):
            sig_filename = os.path.abspath(filename)
        else:
            sig_filename = os.path.abspath(filename + '.sig')
        if not os.path.exists(sig_filename):
            raise NoFileError
        try:
            with open(sig_filename, 'rb') as f:
                sig_buffer = f.read()
        except IOError:
            raise NoFileError
        self.sig_filename = sig_filename
        self.hss_sig = HssSignature.deserialize(sig_buffer)


class HssLmsPrivateKey():

    def __init__(self, keyname):
        """
        Load a HSS/LMS private and public keys from files.

        Parameters
        ----------
        keyname: :class:`str`
            The key name.  Two files will be created based on this
            name: keyname.prv and keyname.pub.

        Returns
        -------
        rv: :class:`HssLmsPrivateKey`
            Used to sign.

        Raises
        ------
        ValueError
            If the parameters have inconsistent values.
        FileNotFoundError or IOError
            If keyname.prv or keyname.pub does not exist.
        """
        prv_filename = os.path.abspath(keyname + '.prv')
        if not os.path.exists(prv_filename):
            raise NoFileError
        pub_filename = os.path.abspath(keyname + '.pub')
        if not os.path.exists(pub_filename):
            raise NoFileError
        try:
            with open(prv_filename, 'rb') as f:
                prv_buffer = f.read()
        except IOError:
            raise NoFileError
        try:
            with open(pub_filename, 'rb') as f:
                pub_buffer = f.read()
        except IOError:
            raise NoFileError
        self.pub_filename = pub_filename
        self.prv_filename = prv_filename
        self.hss_pub = HssPublicKey.deserialize(pub_buffer)
        self.hss_prv = HssPrivateKey.deserialize(prv_buffer)

    @classmethod
    def genkey(cls, keyname, levels=2,
               lms_type=lms_sha256_m32_h5,
               lmots_type=lmots_sha256_n32_w8):
        """
        Generate a HSS/LMS private and public keys, saving them
        in files.

        Parameters
        ----------
        keyname: :class:`str`
            The key name.  Two files will be created based on this
            name: keyname.prv and keyname.pub.
        levels: :class:`int`
            The number of levels in the HSS hierarchy.
        lms_type: :class:`bytes`
            The type for LMS parameters.  Choices:
                pyhsslms.lms_sha256_m32_h5
                pyhsslms.lms_sha256_m32_h10
                pyhsslms.lms_sha256_m32_h15
                pyhsslms.lms_sha256_m32_h20
                pyhsslms.lms_sha256_m32_h25
                pyhsslms.lms_sha256_m24_h5
                pyhsslms.lms_sha256_m24_h10
                pyhsslms.lms_sha256_m24_h15
                pyhsslms.lms_sha256_m24_h20
                pyhsslms.lms_sha256_m24_h25
                pyhsslms.lms_shake_m32_h5
                pyhsslms.lms_shake_m32_h10
                pyhsslms.lms_shake_m32_h15
                pyhsslms.lms_shake_m32_h20
                pyhsslms.lms_shake_m32_h25
                pyhsslms.lms_shake_m24_h5
                pyhsslms.lms_shake_m24_h10
                pyhsslms.lms_shake_m24_h15
                pyhsslms.lms_shake_m24_h20
from .pyhsslms import lms_shake_m24_h25
        lmots_type: :class:`bytes`
            The type for LM-OTS parameters.  Choices:
                pyhsslms.lmots_sha256_n32_w1
                pyhsslms.lmots_sha256_n32_w2
                pyhsslms.lmots_sha256_n32_w4
                pyhsslms.lmots_sha256_n32_w8
                pyhsslms.lmots_sha256_n24_w1
                pyhsslms.lmots_sha256_n24_w2
                pyhsslms.lmots_sha256_n24_w4
                pyhsslms.lmots_sha256_n24_w8
                pyhsslms.lmots_shake_n32_w1
                pyhsslms.lmots_shake_n32_w2
                pyhsslms.lmots_shake_n32_w4
                pyhsslms.lmots_shake_n32_w8
                pyhsslms.lmots_shake_n24_w1
                pyhsslms.lmots_shake_n24_w2
                pyhsslms.lmots_shake_n24_w4
                pyhsslms.lmots_shake_n24_w8

        Returns
        -------
        rv: :class:`HssLmsPrivateKey`
            Used to sign.

        Raises
        ------
        ValueError
            If the parameters have inconsistent values.
        FileExistsError or IOError
            If keyname.prv and keyname.pub already exists.
        """
        if levels < 1 or levels > MaxHssLevels:
            raise ValueError(err_bad_number_of_levels)
        if not lms_type in lms_params:
            raise ValueError(err_unknown_typecode)
        if not lmots_type in lmots_params:
            raise ValueError(err_unknown_typecode)
        key_filename = os.path.abspath(keyname)
        prv_filename = key_filename + '.prv'
        if os.path.exists(prv_filename):
            raise FoundFileError
        pub_filename = key_filename + '.pub'
        if os.path.exists(pub_filename):
            raise FoundFileError
        hss_prv = HssPrivateKey(levels=levels,
                      lms_type=lms_type, lmots_type=lmots_type)
        try:
            with open(prv_filename, 'wb') as prv_file:
                prv_file.write(hss_prv.serialize())
        except IOError:
            return False
        try:
            with open(pub_filename, 'wb') as pub_file:
                pub_file.write(hss_prv.publicKey().serialize())
        except IOError:
           return False
        return cls(key_filename)

    def signFile(self, filename):
        """
        Sign a file.  Produces signature in filename.sig file.

        Parameters
        ----------
        filename: :class:`str`
            The name of the file to sign.

        Returns
        -------
        rv: :class:`bool`
            Set to True for success; otherwise set to False.

        Raises
        ------
        ValueError
            If the private key is exhausted.
        FileNotFoundError or IOError
            If the file to be signed is not found.
        FileExistsError or IOError
            if the filename.sig file already exists.
        """
        pathname = os.path.abspath(filename)
        if not os.path.exists(pathname):
            raise NoFileError
        sig_pathname = os.path.abspath(filename + '.sig')
        if os.path.exists(sig_pathname):
            raise FoundFileError
        try:
            with open(pathname, 'rb') as to_sign_file:
                buffer = to_sign_file.read()
        except IOError:
            raise NoFileError
        sig_buffer = self.hss_prv.sign(buffer)
        try:
            with open(self.prv_filename, 'wb') as f:
                f.write(self.hss_prv.serialize())
        except IOError:
            return False
        try:
            with open(sig_pathname, 'wb') as sig_file:
                sig_file.write(sig_buffer)
        except IOError:
            return False
        return True

    def sign(self, buffer):
        """
        Sign a buffer.

        Parameters
        ----------
        buffer: :class:`bytes`
            The buffer to sign.

        Returns
        -------
        sig: :class:`bytes`
            The signature; zero length if something went wrong.

        Raises
        ------
        ValueError
            If the private key is exhausted.
        FileNotFoundError or IOError
            If the private key file is not found.
        """
        sig_buffer = self.hss_prv.sign(buffer)
        try:
            with open(self.prv_filename, 'wb') as f:
                f.write(self.hss_prv.serialize())
        except IOError:
            return toBytes('')
        return sig_buffer


class HssLmsPublicKey():
    def __init__(self, keyname):
        """
        Load a HSS/LMS public key from the keyname.pub file.

        Parameters
        ----------
        keyname: :class:`str`
            The key name.  It identifies the keyname.pub file.

        Returns
        -------
        rv: :class:`HssLmsPublicKey`
            Used to verify signatures.

        Raises
        ------
        ValueError
            If the parameters have inconsistent values.
        FileNotFoundError or IOError
            If keyname.pub does not exist.
        """
        if keyname.endswith('.pub'):
            pub_filename = os.path.abspath(keyname)
        else:
            pub_filename = os.path.abspath(keyname + '.pub')
        if not os.path.exists(pub_filename):
            raise NoFileError
        try:
            with open(pub_filename, 'rb') as f:
                pub_buffer = f.read()
        except IOError:
            raise NoFileError
        self.pub_filename = pub_filename
        self.hss_pub = HssPublicKey.deserialize(pub_buffer)

    def I(self):
        """
        Get the I value from the public key.
        
        Returns
        -------
        I: :class:`bytes`
             The I value extracted from the public key.
        """
        return self.hss_pub.pub.I

    def verifyFile(self, filename):
        """
        Verify the signature on a file.  Signature is in filename.sig.

        Parameters
        ----------
        filename: :class:`str`
            The name of the file to that was signed.

        Returns
        -------
        rv: :class:`bool`
            Set to True for success; otherwise set to False.

        Raises
        ------
        FileNotFoundError or IOError
            If the file to be signed is not found.
        """
        if filename.endswith('.sig'):
            sig_pathname = os.path.abspath(filename)
            pathname = os.path.splitext(sig_pathname)[0]
        else:
            sig_pathname = os.path.abspath(filename + '.sig')
            pathname = os.path.abspath(filename)
        if not os.path.exists(pathname):
            raise NoFileError
        if not os.path.exists(sig_pathname):
            raise NoFileError
        try:
            with open(pathname, 'rb') as f:
                buffer = f.read()
        except IOError:
            raise NoFileError
        try:
            with open(sig_pathname, 'rb') as f:
                sigbuffer = f.read()
        except IOError:
            raise NoFileError
        return self.hss_pub.verify(buffer, sigbuffer)

    def verify(self, buffer, sig):
        """
        Verify the signature on a buffer.

        Parameters
        ----------
        buffer: :class:`bytes`
            The buffer that was signed.
        sig: :class:`bytes`
            The signature value.

        Returns
        -------
        rv: :class:`bool`
            Set to True for success; otherwise set to False.
        """
        return self.hss_pub.verify(buffer, sig)
