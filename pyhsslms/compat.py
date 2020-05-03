# compat.py
#
# For compatibility between Python2 and Python3 within the routines
# for HSS/LMS Hash-based Signatures as defined in RFC 8554.
#
#
# Copyright (c) 2020, Vigil Security, LLC
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

from sys import version_info


if version_info[0] <= 2:
    import os
    import struct
    import binascii
    
    u32 = lambda i: struct.pack('>I', i)
    u16 = lambda i: struct.pack('>H', i)
    u8 = chr
    fromHex = binascii.unhexlify
    toHex = binascii.hexlify
    toBytes = lambda x: x
    randBytes = os.urandom
    int32 = lambda x: struct.unpack('>L', x)[0]
    charNum = ord
    NoFileError = IOError
    FoundFileError = IOError

else:
    from secrets import token_bytes as random_bytes

    u32 = lambda i: i.to_bytes(4, byteorder='big', signed=False)
    u16 = lambda i: i.to_bytes(2, byteorder='big', signed=False)
    u8 = lambda i: i.to_bytes(1, byteorder='big', signed=False)
    fromHex = bytes.fromhex
    toHex = lambda x: x.hex()
    toBytes = lambda x: x.encode()
    randBytes = random_bytes
    int32 = lambda x: int.from_bytes(x, byteorder='big')
    charNum = lambda x: x
    NoFileError = FileNotFoundError
    FoundFileError = FileExistsError
