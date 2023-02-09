# test_pyhsslms.py
#
# Test routines for HSS/LMS Hash-based Signatures.
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
import tempfile
import unittest
from pyhsslms import *
from pyhsslms.compat import fromHex, toHex, toBytes, charNum, u8


def mangle(buffer, offset=30):
    hex_byte = toHex(u8(charNum(buffer[offset]) ^ 1))
    return buffer[0:offset] + fromHex(hex_byte) + buffer[offset+1:]


class TestHash(unittest.TestCase):

    def testSHA256(self):
        known = fromHex(
         'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        hv = pyhsslms.H('sha256', fromHex('616263'), 32)
        self.assertEqual(32, len(hv))
        self.assertEqual(known, hv)
        hv = pyhsslms.H('sha256', fromHex('616263'), 24)
        self.assertEqual(24, len(hv))
        self.assertEqual(known[0:24], hv)

    def testSHAKE256(self):
        known = fromHex(
         'f7d02b4512be5ddcc25d148c71664dfd34e16abea26d6e7287f45e08ed6fcd87')
        hv = pyhsslms.H('shake256', fromHex('21eda6'), 32)
        self.assertEqual(32, len(hv))
        self.assertEqual(known, hv)
        hv = pyhsslms.H('shake256', fromHex('21eda6'), 24)
        self.assertEqual(24, len(hv))
        self.assertEqual(known[0:24], hv)


class TestLMOTS(unittest.TestCase):

    def testChecksum(self):
        x = fromHex('f0660906f4586869d1618a758223a8e7' + \
                    '0d6c7224080fa4d1436f4906ac7936e9')
        checksum = pyhsslms.checksum(x, 8, 0)
        self.assertEqual(fromHex('1219'), checksum)
        x = fromHex('22810fac106936fb891993ae9d768cb1' + \
                    '399483f6a22fb4d0f6e574a1b95c5722')
        checksum = pyhsslms.checksum(x, 4, 4)
        self.assertEqual(fromHex('1f40'), checksum)

    def testBuildPublic(self):
        S = fromHex('61a5d57d37f5e46bfb7520806b07a1b800000005')
        msg = fromHex('0000000500000004d2f14ff6346af964569f7d6cb880a1b66' + \
         'c5004917da6eafe4d9ef6c6407b3db0e5485b122d9ebe15cda93cfec582d7ab')
        buf = fromHex( '00000004d32b56671d7eb98833c49b433c272586bc' + \
         '4a1c8a8970528ffa04b966f9426eb9965a25bfd37f196b9073f3d4a232feb6' + \
         '9128ec45146f86292f9dff9610a7bf95a64c7f60f6261a62043f86c70324b7' + \
         '707f5b4a8a6e19c114c7be866d488778a0e05fd5c6509a6e61d559cf1a77a9' + \
         '70de927d60c70d3de31a7fa0100994e162a2582e8ff1b10cd99d4e8e413ef4' + \
         '69559f7d7ed12c838342f9b9c96b83a4943d1681d84b15357ff48ca579f19f' + \
         '5e71f18466f2bbef4bf660c2518eb20de2f66e3b14784269d7d876f5d35d3f' + \
         'bfc7039a462c716bb9f6891a7f41ad133e9e1f6d9560b960e7777c52f06049' + \
         '2f2d7c660e1471e07e72655562035abc9a701b473ecbc3943c6b9c4f2405a3' + \
         'cb8bf8a691ca51d3f6ad2f428bab6f3a30f55dd9625563f0a75ee390e385e3' + \
         'ae0b906961ecf41ae073a0590c2eb6204f44831c26dd768c35b167b28ce8dc' + \
         '988a3748255230cef99ebf14e730632f27414489808afab1d1e783ed04516d' + \
         'e012498682212b07810579b250365941bcc98142da13609e9768aaf65de762' + \
         '0dabec29eb82a17fde35af15ad238c73f81bdb8dec2fc0e7f932701099762b' + \
         '37f43c4a3c20010a3d72e2f606be108d310e639f09ce7286800d9ef8a1a402' + \
         '81cc5a7ea98d2adc7c7400c2fe5a101552df4e3cccfd0cbf2ddf5dc6779cbb' + \
         'c68fee0c3efe4ec22b83a2caa3e48e0809a0a750b73ccdcf3c79e6580c154f' + \
         '8a58f7f24335eec5c5eb5e0cf01dcf4439424095fceb077f66ded5bec73b27' + \
         'c5b9f64a2a9af2f07c05e99e5cf80f00252e39db32f6c19674f190c9fbc506' + \
         'd826857713afd2ca6bb85cd8c107347552f30575a5417816ab4db3f603f2df' + \
         '56fbc413e7d0acd8bdd81352b2471fc1bc4f1ef296fea1220403466b1afe78' + \
         'b94f7ecf7cc62fb92be14f18c2192384ebceaf8801afdf947f698ce9c6ceb6' + \
         '96ed70e9e87b0144417e8d7baf25eb5f70f09f016fc925b4db048ab8d8cb2a' + \
         '661ce3b57ada67571f5dd546fc22cb1f97e0ebd1a65926b1234fd04f171cf4' + \
         '69c76b884cf3115cce6f792cc84e36da58960c5f1d760f32c12faef477e94c' + \
         '92eb75625b6a371efc72d60ca5e908b3a7dd69fef0249150e3eebdfed39cbd' + \
         'c3ce9704882a2072c75e13527b7a581a556168783dc1e97545e31865ddc46b' + \
         '3c957835da252bb7328d3ee2062445dfb85ef8c35f8e1f3371af34023cef62' + \
         '6e0af1e0bc017351aae2ab8f5c612ead0b729a1d059d02bfe18efa971b7300' + \
         'e882360a93b025ff97e9e0eec0f3f3f13039a17f88b0cf808f488431606cb1' + \
         '3f9241f40f44e537d302c64a4f1f4ab949b9feefadcb71ab50ef27d6d6ca85' + \
         '10f150c85fb525bf25703df7209b6066f09c37280d59128d2f0f637c7d7d7f' + \
         'ad4ed1c1ea04e628d221e3d8db77b7c878c9411cafc5071a34a00f4cf07738' + \
         '912753dfce48f07576f0d4f94f42c6d76f7ce973e9367095ba7e9a3649b7f4' + \
         '61d9f9ac1332a4d1044c96aefee67676401b64457c54d65fef6500c59cdfb6' + \
         '9af7b6dddfcb0f086278dd8ad0686078dfb0f3f79cd893d314168648499898' + \
         'fbc0ced5f95b74e8ff14d735cdea968bee74')
        expected_pub = fromHex('87be83923a22106731e8f10f826faf4d02' + \
         '17b07d99694d1174d350fba7d578a1')
        sig = pyhsslms.LmotsSignature.deserialize(buf)
        pub = sig.buildPublic(S, msg)
        self.assertEqual(expected_pub, pub)

    def testKnownPrivateKey(self):
        msg = toBytes('The way to get started is to quit talking and ' + \
                      'begin doing.')
        S = fromHex('c6d47a98577cd2f13007908fd14309ca00000001')
        seed = fromHex('1e305866bfc4d18c4735bfc677711109' + \
                             'a886656dc432e39281bc5a129b518172')
        prv = pyhsslms.LmotsPrivateKey(S=S, SEED=seed)
        self.assertEqual(1, prv.remaining())
        self.assertFalse(prv.is_exhausted())
        sigbuffer = prv.sign(msg)
        self.assertEqual(1124, len(sigbuffer))
        self.assertEqual(0, prv.remaining())
        self.assertTrue(prv.is_exhausted())
        sig = pyhsslms.LmotsSignature.deserialize(sigbuffer)
        pub = prv.publicKey()
        self.assertTrue(pub.verify(msg, sigbuffer))
        self.assertFalse(pub.verify(msg, mangle(sigbuffer)))
        self.assertFalse(pub.verify(mangle(msg), sigbuffer))
        self.assertTrue(sig.prettyPrint())
        prvpp = prv.prettyPrint()
        self.assertIn('LMOTS type: 00000004', prvpp)
        self.assertIn('S         : c6d47a98577cd2f13007908fd14309ca', prvpp)
        self.assertIn('SEED      : 1e305866bfc4d18c4735bfc677711109', prvpp)
        pubpp = pub.prettyPrint()
        self.assertIn('S         : c6d47a98577cd2f13007908fd14309ca', pubpp)

    def testRandomPrivateKey(self):
        msg = toBytes('The way to get started is to quit talking and ' + \
                      'begin doing.')
        prv = pyhsslms.LmotsPrivateKey()
        sigbuffer = prv.sign(msg)
        sig = pyhsslms.LmotsSignature.deserialize(sigbuffer)
        pub = prv.publicKey()
        self.assertTrue(pub.verify(msg, sigbuffer))
        self.assertFalse(pub.verify(msg, mangle(sigbuffer)))
        self.assertFalse(pub.verify(mangle(msg), sigbuffer))
        self.assertTrue(sig.prettyPrint())
        self.assertTrue(prv.prettyPrint())
        self.assertTrue(pub.prettyPrint())


class TestLMS(unittest.TestCase):

    def testKnownPrivateKey(self):
        lmots_sha256_n32_w8 = pyhsslms.lmots_sha256_n32_w8
        lms_sha256_m32_h5 = pyhsslms.lms_sha256_m32_h5
        msg = toBytes('The way to get started is to quit talking and ' + \
                      'begin doing.')
        buffer = fromHex('0000000500000004' + \
                         '0c0fe552dcf77d4bbe16b28605759ea4' + \
                         'bb06873c809d0b9a00d753deec2e5845' + \
                         'e4a9fccb86dc9c49d71b72d5696acb54' + \
                         '00000000')
        prv = pyhsslms.LmsPrivateKey.deserialize(buffer)
        self.assertEqual(32, prv.remaining())
        sigbuffer = prv.sign(msg)
        self.assertEqual(1292, len(sigbuffer))
        self.assertEqual(31, prv.remaining())
        self.assertFalse(prv.is_exhausted())
        sig = pyhsslms.LmsSignature.deserialize(sigbuffer)
        pub = prv.publicKey()
        self.assertTrue(pub.verify(msg, sigbuffer))
        self.assertFalse(pub.verify(msg, mangle(sigbuffer)))
        self.assertFalse(pub.verify(mangle(msg), sigbuffer))
        self.assertTrue(sig.prettyPrint())
        prvpp = prv.prettyPrint()
        self.assertIn('LMS type  : 00000005', prvpp)
        self.assertIn('LMOTS type: 00000004', prvpp)
        self.assertIn('I         : e4a9fccb86dc9c49d71b72d5696acb54', prvpp)
        self.assertIn('SEED      : 0c0fe552dcf77d4bbe16b28605759ea4', prvpp)
        self.assertIn('pub       : a8b35f4c521183a05d81fbcf8a81ffc9', prvpp)
        pubpp = pub.prettyPrint()
        self.assertIn('I         : e4a9fccb86dc9c49d71b72d5696acb54', pubpp)
        self.assertIn('K         : a8b35f4c521183a05d81fbcf8a81ffc9', pubpp)

    def testRandomPrivateKey(self):
        msg = toBytes('The way to get started is to quit talking and ' + \
                      'begin doing.')
        prv = pyhsslms.LmsPrivateKey()
        sigbuffer = prv.sign(msg)
        sig = pyhsslms.LmsSignature.deserialize(sigbuffer)
        pub = prv.publicKey()
        self.assertTrue(pub.verify(msg, sigbuffer))
        self.assertFalse(pub.verify(msg, mangle(sigbuffer)))
        self.assertFalse(pub.verify(mangle(msg), sigbuffer))
        self.assertTrue(sig.prettyPrint())
        self.assertTrue(prv.prettyPrint())
        self.assertTrue(pub.prettyPrint())


class TestHSS(unittest.TestCase):

    def testKnownPrivateKey(self):
        msg = toBytes('The way to get started is to quit talking and ' + \
                      'begin doing.')
        buffer = fromHex('00000002000003ff0000000500000004' + \
            '3df0eddf9856dea6d6d89135515c04d337a692dd8879b5ef3ec58f3a9bcc7595' + \
            'ee9a2418209ce10bc035de0f55c5eecf' + \
            '000000010000000500000004' + \
            '22611c481e5b25c3bc637b771334ddd546a58e1df2d40831ab53fe94dc3a48ef' + \
            'fe4f1f9de36f743deeaa4784dafb2a00' + \
            '00000000' + \
            'c584f571bbfdf285b9a8ac5bafb7738a6dfb3f22129dd88898071725791d3d91' + \
            '8074a0f608cce80b32ad771094c4a7cfd9fc6d9e7591e9d3af9dc6e7afce8905' + \
            '0000000000000004' + \
            '8fe0ef60d82ee4f5681be3124436afcae2dce5d249742aeb6e1e2a5c30c19b60' + \
            '636d00292ccc8f6f4824ca2e4d4a4e28a2b5246447adfb4328d1263b3a8d9289' + \
            '6a53fa12d499286e7721ffd52add23f10fc2615eeed57e1193c9ac326b042f20' + \
            'b4708bb7053fbfda2e3832e10e875154d9ca3bb9f9f8b937cda03a6cd0e530ff' + \
            '75e9595e71e76c98ef282500bd1b9ba6d802b3c40cf98f19fc318ef06a4a746f' + \
            'f4c6c5bf9be9a1cdd6bc161e18afcabc193c8b0e1b0123ece777b6200abcdfdd' + \
            'faa2f36913f25cf75fa7e0b673a1e2121e76d0bdcf89a8eb2c1283b147f99516' + \
            '81288127a882dd80c9a1bc0ecc5978780b4f529bc8dae05778d9e51bcf664b04' + \
            '52b02eb3b9f562c9edc165d4021ec9f954f7b3f114584b49687205d4d74910a9' + \
            '18a1c0aff404dcd987fa649f0800944e15a8791931d728fa8148ce3c68c24c12' + \
            '065f35c2451dd88cbfc3f8853611ecd54a679b48e2c7a08131ba9b0565e1472a' + \
            '00be955dde587fc0bb359240ff0be6e7dc2def844cc7914c1846e15303582275' + \
            '602d094eafbf49035aaff85be6baa35a5b1243c86effbcbd9ebb2d14550cdf37' + \
            '3a475700a69c5885665e85f874f595219bdf0bc87d87c1d105c49a73a8038462' + \
            '433975e3d370cd2fb3cb18d05f74984250d446452171ce432dff60d0862ea3c6' + \
            '75be0511d0857b9d0a233b5270f95770aa9579853371d208d677457d7bc37bbf' + \
            '4d235f6dbfa0fd13621115e2a4b5c39262fb355df862e4927b9c3e42d522c9d2' + \
            'f2433d434f6b30f1c5b4cccc3a9485d8d29b3c68431d50eb0455fd7dd49bde22' + \
            '6092dcd38682cdf07528be25b643856e3a2c644a09785cd1210087f5f8d828e4' + \
            '049c257669320f4fe4ca8e70ef9bc34eb6afbb65c6ab25f90e6d4f9913357a10' + \
            'a78e5f04bd231e9297118eea9ca192a6395a415ee6c4ebbb6cff49378fbef209' + \
            '93ffcce86aebce772a485cb49965703ec85c1476d335042723c51973f883154a' + \
            '91f2bccc1f39e9b6fcd15b2f71f72894ef508120023b83eee2ab375a316ef64d' + \
            'ddaa73bbaeb44a9743c85d1cb5a72c8803a645e5c8ee7eaa6133e6c483d34d1e' + \
            '24e9206a5c23730f00658ca79d23bec53f9d61657abd36839d296aafef17135d' + \
            '18b528f5cbbb0d86ba4553cc503ad188878fe37774448e397661f48eb7094a51' + \
            'bb5597f0bc4b61dd4aae0a1acd84b18e4cf77a9e721e808ffa6e1d86d0db7a0a' + \
            '6000bca678260704885e7a1d8852f78a291bf0673a40a2cbb800bd95567c4e36' + \
            '81cf3fe16a03bc1158191243ac5e34471a9a53b54bc86e7f4e24d0d16d460127' + \
            '4df37c707e7fe76acd8c7d5c857d6687f050f177e3f42c007bdc4787ece36635' + \
            'fc330943353160d713bdc001ee4f67232a47f7ae258a33fea6a46ed5df9419f7' + \
            '16259f93ff93d7b8d28eba91b2f4c536c6a70399e7a2291e2a0063179fc32d34' + \
            'a329abf0b4015bb2f32d97b38d4bbbdbd00f30c6a9d74436c54d24f49b8b7265' + \
            '7329106b234d82fab605b2218607ddbfa28afc230f0ed50ea38cdf63347fd307' + \
            'cc7f2e25c50a540d29c42ea927b4eac204b012acff1d1cf6021fcda56ac27d56' + \
            '00000005' + \
            '9e0125d72f60a5c4e692ee92e5e965db6770d5a5a15d97d73aa9614666888971' + \
            'ffbabfb28059284c675759522677345af3658086bd95398855072a89c92d925f' + \
            '812c571d33d028e0e0c7741420bc788f1c223628ea54a1cd37e8c7698915d386' + \
            'b4f4868508835e4a3bd52e2296833290946fd0f92e4475d5dd86c0325d47c59e' + \
            '8e5f4b3314196b48875804d8bb333092270b10a7e5c2f9a6de8de15a19d30fc3')
        prv = pyhsslms.HssPrivateKey.deserialize(buffer)
        self.assertEqual(1023, prv.remaining())
        sigbuffer = prv.sign(msg)
        self.assertEqual(2644, len(sigbuffer))
        self.assertEqual(1022, prv.remaining())
        self.assertFalse(prv.is_exhausted())
        sig = pyhsslms.HssSignature.deserialize(sigbuffer)
        pub = prv.publicKey()
        self.assertTrue(pub.verify(msg, sigbuffer))
        self.assertFalse(pub.verify(msg, mangle(sigbuffer)))
        self.assertFalse(pub.verify(mangle(msg), sigbuffer))
        self.assertTrue(sig.prettyPrint())
        prvpp = prv.prettyPrint()
        self.assertIn('levels    : 2', prvpp)
        self.assertIn('LMS type  : 00000005', prvpp)
        self.assertIn('LMOTS type: 00000004', prvpp)
        self.assertIn('q         : 00000001', prvpp)
        self.assertIn('I         : ee9a2418209ce10bc035de0f55c5eecf', prvpp)
        pubpp = pub.prettyPrint()
        self.assertIn('levels    : 2', pubpp)
        self.assertIn('I         : ee9a2418209ce10bc035de0f55c5eecf', pubpp)
        self.assertIn('K         : c584f571bbfdf285b9a8ac5bafb7738a', pubpp)

    def testSmallRandomPrivateKey(self):
        msg = toBytes('The way to get started is to quit talking and ' + \
                      'begin doing.')
        prv = pyhsslms.HssPrivateKey(levels=1)
        sigbuffer = prv.sign(msg)
        sig = pyhsslms.HssSignature.deserialize(sigbuffer)
        pub = prv.publicKey()
        self.assertTrue(pub.verify(msg, sigbuffer))
        self.assertFalse(pub.verify(msg, mangle(sigbuffer)))
        self.assertFalse(pub.verify(mangle(msg), sigbuffer))
        self.assertTrue(sig.prettyPrint())
        self.assertTrue(prv.prettyPrint())
        self.assertTrue(pub.prettyPrint())
        
    def testMediumRandomPrivateKey(self):
        msg = toBytes('The way to get started is to quit talking and ' + \
                      'begin doing.')
        prv = pyhsslms.HssPrivateKey(levels=2)
        sigbuffer = prv.sign(msg)
        sig = pyhsslms.HssSignature.deserialize(sigbuffer)
        pub = prv.publicKey()
        self.assertTrue(pub.verify(msg, sigbuffer))
        while(not prv.is_exhausted()):
            sigbuffer = prv.sign(msg)
        with self.assertRaises(ValueError):
            failed_sigbuffer = prv.sign(msg)
        sig = pyhsslms.HssSignature.deserialize(sigbuffer)
        pub = prv.publicKey()
        self.assertTrue(pub.verify(msg, sigbuffer))
        self.assertFalse(pub.verify(msg, mangle(sigbuffer)))
        self.assertFalse(pub.verify(mangle(msg), sigbuffer))
        self.assertTrue(sig.prettyPrint())
        self.assertTrue(prv.prettyPrint())
        self.assertTrue(pub.prettyPrint())

    def testLargerRandomPrivateKey(self):
        msg = toBytes('The way to get started is to quit talking and ' + \
                      'begin doing.')
        prv = pyhsslms.HssPrivateKey(levels=4)
        sigbuffer = prv.sign(msg)
        sig = pyhsslms.HssSignature.deserialize(sigbuffer)
        pub = prv.publicKey()
        self.assertTrue(pub.verify(msg, sigbuffer))
        self.assertFalse(pub.verify(msg, mangle(sigbuffer)))
        self.assertFalse(pub.verify(mangle(msg), sigbuffer))
        self.assertTrue(sig.prettyPrint())
        self.assertTrue(prv.prettyPrint())
        self.assertTrue(pub.prettyPrint())


class TestHSSLMS(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        self.fname = os.path.join(self.tempdir, 'test1234.txt')
        self.keyname = os.path.join(self.tempdir, 'testsigkey')

    def tearDown(self):
        if os.path.exists(self.tempdir):
            for basedir, dirs, files in os.walk(self.tempdir):
                for fn in files:
                    pathname = os.path.join(basedir, fn)
                    os.remove(pathname)
            os.rmdir(self.tempdir)

    def testGenSignSignVerifyVerifyFailFail(self):
        prv_key = pyhsslms.HssLmsPrivateKey.genkey(self.keyname, levels=2)
        self.assertTrue(prv_key)
        self.assertTrue(os.path.exists(self.keyname + '.prv'))
        self.assertTrue(os.path.exists(self.keyname + '.pub'))
        msg = toBytes('This is a test message to be signed.\n')
        with open(self.fname, 'wb') as f:
            f.write(msg)
        self.assertTrue(os.path.exists(self.fname))
        self.assertTrue(prv_key.signFile(self.fname))
        self.assertTrue(os.path.exists(self.fname + '.sig'))
        sigbuf = prv_key.sign(msg)
        self.assertTrue(len(sigbuf))
        pub_key = pyhsslms.HssLmsPublicKey(self.keyname)
        self.assertTrue(pub_key)
        self.assertTrue(pub_key.verifyFile(self.fname))
        self.assertTrue(pub_key.verifyFile(self.fname + '.sig'))
        self.assertTrue(pub_key.verify(msg, sigbuf))
        self.assertFalse(pub_key.verify(msg, mangle(sigbuf)))
        self.assertFalse(pub_key.verify(mangle(msg), sigbuf))

    def testFromPublicKeyGetI(self):
        buffer = fromHex('000000010000000500000004' + \
                         '616d2133c3275326e591f26c748e3588' + \
                         '9ab949c09b231bc43a2748486ba78492' + \
                         '190208cf5a3d8491e774d8301dc8510a')
        expected = fromHex('616d2133c3275326e591f26c748e3588')
        with open(self.keyname + '.pub', 'wb') as pub_file:
            pub_file.write(buffer)
        pub_key = pyhsslms.HssLmsPublicKey(self.keyname)
        I = pub_key.I()
        self.assertEqual(expected, I)


class TestInterop(unittest.TestCase):

    def testVerifyHashSigs(self):
        msg = fromHex('5468697320697320612074657374206d6573736167652' + \
         '0746f206265207369676e65642e0a')
        pubbuffer = fromHex('000000020000000500000004' + \
         '616d2133c3275326e591f26c748e35889ab949c09b231bc43a2748486ba78492' + \
         '190208cf5a3d8491e774d8301dc8510a')
        sigbuffer = fromHex('000000010000000000000004' + \
         '19c1e5adebca8c25313c3d0060d9373bbfbe75fdfedef7321f08d99f763eadbd' + \
         '86774810914ff571cd5d61c5e3364cd215f4baaee6a88901c878d3a1f47fd621' + \
         'f6c0433c75fcc106a6f530f543b946a700d4a998a51448eb448c422f86b4760f' + \
         '22573c72b8c497d0e77260f5703386188898a00c612e21b226629af4a5ed4fa0' + \
         'bef780407ccc75ab54a2c3246a7f268569f06e8b2e553b2dcb5237bb0d144a2a' + \
         '968844103741e09ed5e604ded124a49b028d6548aa0fe014b420598d68a251a4' + \
         '510582062a2695a96056f606c07bb8cfa9de87a6ce1f734c8f793b5853dc05b2' + \
         '1bb3ddecce509d7b4514c5b823f6970696e73cbeff3700f9e3ce2a45ec057477' + \
         '9d229c340a2d37bbd54b0483240c0b6cca3d27ede4910fca621e03ebd0aee22d' + \
         'fce1f4be9fc9473b6427d48464806878e624c77b20aee4d18834525649e6826e' + \
         'fb6b2cd068619193c4204831ddaed01b0be3275be23cdfccc9b7eff52678b3cd' + \
         'e11315ad936872f5d14573cb0b94e3350fa92a6e3099f6ed34665640145a2866' + \
         'bd4dbd6f7bfe4897d30ba701be0f9d47fe384f0bc11ecd9628d4797732a77e15' + \
         '0726a8756f3054ef7f52cd4eadf6732506f2b738af77eb85c55dc412f25052b1' + \
         'cd6b8d0fb916687420f3587106daf3e390a8837716fec4bc8cb314af1ed11d71' + \
         '35ef40800e281a0c44089e066f501e64ee2eae65603e747e14034a2d5a344172' + \
         '9d2d124dfb90d6d78c095a8196dbd064543ffff184a774292ea7be195fcaf039' + \
         '25ace1c9cf625798ee1725f2544290b81a86ae2fa213b1e5b7a78250bbceaf27' + \
         '476ced5b04adbe0794a11ec3ea3b3adbc885d270700021edb6d2a6df15470db4' + \
         'd58fd24bfeeda6cb0e1a119dc5c7a8819abf4c4ed7e8ed03cb834db8e73073a7' + \
         '23ba6a2e475dbad63dbac768fd1e4ef66649e1780bd1ea2e6dc0705106880e9c' + \
         'b9bc641808248d2030d95dbdcba485ae4f11df726b106bb6caebb3a379dfad9f' + \
         '807c1c97f73941382766d90a5a6b902bad9c81d5a1a58420bffe0a26b28616a2' + \
         'c65512b5e137a838d91bfb160e84ec0169091098abacafa537918ed29217a9d4' + \
         'd8001ca0d05e31a5fa39eca9d89ed4355d25ab05621c46636fb8dafdde5408da' + \
         'ec262285675df50be528d7673b745fd6df89c1f091b432dbad633b1c8eb35cee' + \
         'f58ec6078e2dd6bd47cd12120bff70a4628a61a507fe9774e9fa90f7486c5fb6' + \
         '0ddd9c14dfe1540768e64a036a6e3e57ee9f00765401227c0a77c81e61f59c4f' + \
         'd217bfd342617a922e03bf16a96d69e142a25cc3c1964be7de3f416ac32b494b' + \
         '726d9c583578e8b54f28803b19b3cca8155485fa06a2512cbd84d2d876ba01db' + \
         'c554db4df25d939685dead655d0b047879e6f1dfc7c4984ec32edd12ac8f9ad9' + \
         '68a56d8eb3af863539db84b88840a79b0e200c7bdf1e0db402464c263fa2b12a' + \
         '0f55baefa4650dc9e0c70a0b115becfd10b49eb3f7e566a7d60115e461875625' + \
         '6c8ecf2a95850a18426f79ec70e4508407e7c8b297e0fdc8350e0ab2c352684f' + \
         '1ef9bb97f47eccfff0badb36c040a10b922b5a5691df0cdf1e50bf908ab8f4f4' + \
         '0000000522572d3011b5d9a4212ade8ee3e9c93393066a83bd28fad993d4e8d2' + \
         'f992f456407fd2405c28d4f063cfd5dd5944e29d73fdadd1986242407dac73af' + \
         '3b7163dbc999afc5fcfd100c53ca4e22d2d2157a44a7699596fedb96e03e29a9' + \
         '23a2a4c227cc7318ed9164f9d5b0b942635392484929ad31bcbaa23e785a72dd' + \
         '483f7c1f6f5b8f5f6e07de9451267e647af09adc8a3f15d3cb29ff87873563fe' + \
         'd0b5931c0000000500000004809ed32be95fb6d01915f606d0d02eb527479101' + \
         '96c7aca46e5d6344c1b1e3b26c7e6ee14c183542ddcc6d69490717d400000002' + \
         '0000000482fa02475f9de33ea21cf5da3a6b8fec729ddfe963befa915f0f8db7' + \
         '3374e1d3699d6e4d7ea4f785d162595ba73b6243a8cefad1663cdae5f58a2d1f' + \
         '712c01113b06ffceee0ade3b9aeab14a09139ab4355b17e087a3adb0a6de6167' + \
         '6cef3fc57d6be0ad58c370a2b100645e009aa94263414150f3b05e7cdceb91ac' + \
         '02039ca08b258ead263ed918954108735643068f23c771ea55912f36461f9998' + \
         '3d8e4fd18f97c7dc39f470fde9c4b23ace60caa60be2f0e1319d72c49387b26d' + \
         'c1f1d3a38aaa64086c7ff91e418990264b21de5a5ede207e7d1b0867045f95d9' + \
         '1b7ed27be026388f8c06043e78476a5b9606c5f72fd0505c9fdfe9ba692ae3ec' + \
         'caadbb2a4036b2a0fc2a278cb6e4905ac71eabaed4cb86bcacf72d92f9b0c977' + \
         '4cdf38888e4c13e17665942ee5227a96f03c6f3eb9849250a1b8ef1449659133' + \
         '7768e198b90a7bcd77e859906a733062b1a6c7990e05ff748f864f3af1d6aa3f' + \
         '13896d0635f1f3848c9e3b4c606ba2d8b232b6728c47fd7fd4cb02ef49c34fc2' + \
         '398dbefc87a65d90c49c685ac14021adf7da235d6a1a9a24e8d5b529ae61092a' + \
         '16de15f57d80c8f3d51c33aa2207d2a3d05f3ae7260df96e52c473d38761d274' + \
         '2143d4d9e56e4d942cb329e5dbd2b8c7da6a0bdba37efc770833a284f7f57634' + \
         '9e63c5b6c81b6f0065f695616fdb4337639e1cc4c73e807debdbe9712655f70c' + \
         'fa7c7f0770460c9d14bc70f55558440c3b02decbffbb341064b5f04e3c1f844e' + \
         '86d3136a4cb778befd0a5cb6e9f45e384814fc7aa8eda544ff222ad5d8501613' + \
         'fdcb3c896ecbd3db6ca96c382b7cf698582620fd17dcf6eae3440acbd43835a0' + \
         'd0b4f491ebb8b49aa393db41ed383acab93daba86d5fb93a388667fc5bf2c664' + \
         'd0d93c52d81895e0587608e7ec4c5a2f82c739654805a82f307e89e2482aca16' + \
         '53865ef7e336d97e6c173ee77cdb4e145ede0fd359d50079dc4c3a477e095906' + \
         '31e06a1e5cdb0f843828499992f9267948e99dceb948fb12330b28a14be0a5ee' + \
         '132a62fda5cb3e27d1cf8a02ebfa7753249cfe23191d74dedc9b09b946796a6d' + \
         '0c51f204836ad47328a77aeea28dd67ddf614c934ecefd6c5d2105fc30ae9149' + \
         '7aeab41fc930ce068d9ebe2d0e0bd036595354eabcc3114441b1a9c96e9c247e' + \
         'bda9c3a43e4fe797b493fc90a661cf27efcc5f83f088f8f85eb150778da5098a' + \
         'b2e425c3e687774b9f39998cecb068f5beb3baae632591f9281f79de13c882ec' + \
         '4762d2d99b2bd50a1d9822b4c8672e7e2d7646b87e88f4d7ce0dc260dadb2655' + \
         '9b31708cf4cc01f3c4564bb38fb73fc5f0adb90d9a135e0230a1542d2e84c2b3' + \
         'adccd39b933a62bd84e819b47c1b28dcebd6018f45e5580c80ea950c67f387e0' + \
         '83e9015bf8343ca2858c3e5e747b5fd8575fd3afa036780cd9e7d9a8c5e8d7ff' + \
         '7673b7481b269f867709e53646f5a628cf363d96ab5e09e5e352acab1542a238' + \
         'cad97cce0ae60e63abff53fecb69687d10a4fb6fe3f696404d62541f82ee1bf9' + \
         'cd3b877a861b4eabef6610dac49c4dd583186ae0658d6e61ea8b8f5189db89dd' + \
         '78207a020000000528439cb3612a7df5c43968f2dcca8945bf397e998f13be92' + \
         'f8a584bb9c9b8eb56c5b8aab9f7851d9ec40fc73ecf6e6b4ee4fa30b080e4aec' + \
         'c3aea0c102b94cc3d2950ab92808cd864f26ca5eaed6623efec6a88d9b0b56d2' + \
         'e73d876b6752e4e925d7d60c46d761f4ebe04fc9e5ff79118e61b5fb12989cb4' + \
         'ac93335d108853eeac4aae6c0d3cd7d35df1d1e3834d8770b81f1584a3a88dfd' + \
         'b55c4fa171ed01d8')
        pub = pyhsslms.HssPublicKey.deserialize(pubbuffer)
        self.assertTrue(pub.prettyPrint())
        sig = pyhsslms.HssSignature.deserialize(sigbuffer)
        self.assertTrue(sig.prettyPrint())
        self.assertTrue(pub.verify(msg, sigbuffer))
        self.assertFalse(pub.verify(msg, mangle(sigbuffer)))
        self.assertFalse(pub.verify(mangle(msg), sigbuffer))

    def testVerifyHashSigsMixedSizeTrees(self):
        msg = fromHex('5468697320697320612074657374206d' + \
         '65737361676520746f206265207369676e65642e0a')
        pubbuffer = fromHex('000000020000000700000003f171a152' + \
         'fd41c92fa7f0d03544804d5a797e49fcbee2a4fde957e62b164c777895a7d224' + \
         'c36341672b8d780e5745fb8f')  
        sigbuffer = fromHex('0000000100000000000000037f6fc2f2' + \
         '6894aeef79f3d8fdc8e67879b18ef0c1e916488fcb400ce544b46076d1535759' + \
         'e09256dfad9898e0ee1ff03e8b3cdcce9b73327e3ef5eeacc037e073b3221eac' + \
         'e8f572c4df1876fc3ed728f515b06e6a5c8d8b08734afa370e35c20a16be184f' + \
         'd5471e75bdf79c679ed287c5b8cb39da361aef6845caea75709673f44b6d38a7' + \
         'a41d3a348349b26315d67ce2f0c06b5aff9406952f44e188de4eb0284075b8f5' + \
         '40a3fb8d5d51169e33596f5da6c46858bdf88cddd5a5eba032bd96df1f5732cb' + \
         'f27bec095afacf81f2c23df7145e43775613775c0e664e8a6969249fe97bafd4' + \
         '760228a27220ab3cd5c0011a6090cb653d8e14bc9e4bc8c75efaacd40426edf0' + \
         '1657fed67ae1448e289e8c913a20bb4d37c47a55e3ea6216afd5727fcb014ac0' + \
         'af50ee3008dc6472bb117ccba23a7d5175029b67f2e621f7ac7f73cdf7ebf318' + \
         '0de474f46b11c9cad7c4b96fed563834ccdf1f746a4a8cb9d01aadb08549126e' + \
         '4c87ab8222cd6c24e8da24708a18d3c15d68744ba7429f1fa72aa676f8c53e18' + \
         'ed60748d85faad03eb7e5c08b6951ae16577086aca8b22eb2d7017837d8904f2' + \
         'cc504cae217e16cacff56dc84496b6b0075b8bca6ce2559921a6e2e72606165d' + \
         'a2913c8ea85f44dd6911e51238292ce225e771c272260f0d02483aeeae117442' + \
         '83269c2bd6970e389e41fbb46371237e7036c4ef42a6ace55794290c1ecc49bd' + \
         '6dbdc565ad4011de91475e0b155a8bad8f9484834eb7aab2f52bb2c934d2bf95' + \
         '85676eda08091a9ab266df063a6e284d9355ea8cafb5bbc20fc627b194967f3c' + \
         '449af0ebd1e14f7ca10975b63f4ed86bed6c5d0f4fe21a3da13fd6b27db99b6a' + \
         'a9eeb68a9365c81edd4f041e0d9e8954475318065206d3fd37385e2986d285ac' + \
         'feead6b3029442ba449747466a5a533e8663310289b19a64ce9db01bf517a02a' + \
         '263d2114c45fe81647e3c5bfb145edefee34a842d3cd40977ac4a46085439c7d' + \
         'c64a541866c16010593bc5abad766266a2d4be0e9738d29c73eb56ddf28824a4' + \
         'b097176091000bdbc44b0299f12f94ebb867aec1664a1a7c81f72157a94a75e8' + \
         'b085885a7546c2570411eebde74107b7d83d967b7c64d99e7135f05015d1087b' + \
         '314be6deb392e102b09aae2f97ac52ccd58d6d4f69fbacf5f2a0dce3c4ab67e0' + \
         '99caaef2295ee1098acbf5eeac29b93f2d273a49d3a45760062adef91687cdb4' + \
         '14319ea0f673bcd351b362b498ae144595e6b6d26cb6c2981be55267be7c1eda' + \
         'acdfc7a7e4ca1f48b06ce40280a9f6eceb4a3aac74bad9fbfd3f78a1e97a1b47' + \
         'f6a5aa590ccb73246fc2ffe733f62aed86fc551a874f9d59f1c63b9e4e4056b8' + \
         '61ce9cc5e2b72aa3ecff1eba6f3e32b761dac5b303f4d5d7823766d035373176' + \
         '121fb73e8f2bdd5438cf55a777760fd31e2757fda6f7010ec912ef7a3d5bdeea' + \
         'c9601cc1e4d4441a2530cc3e3479c3d28caee062c8f8fece091f50aeb2b2c8da' + \
         '4fbc32665c2364a26e777842160b13147042a0a4a23a9028e1eb58538f306ae7' + \
         '849f542a66cccc87affb6c64793e0e37458ebc17f419dfbe12f021bbc099ac6a' + \
         '4fb3f738723763177ff9e5856428c556d7674bb9f7e43f2d3796ba6303bfd2ff' + \
         '5876c02a4c6aa3c7de55660af6c037a2cd744918494ceca61af101f2fcbde546' + \
         '39c07f3950f267c12e9347cf6cb90fe24959c27ef9be55531a499cd0fc8b959e' + \
         '11e7b0a34e3d169dd1873c62d1321d74bc35c80f40c7043c50d78c3605ea1a77' + \
         'fd169d2571fd4f7245ada2cdda2f800ca20820e8f09353a5c278ea166660d9cf' + \
         '1fbaf0560acfa3c968ae4f85d92d9c78f42ed7a3b6e82e9804c8b1e86c86dfca' + \
         '8a9f9ca1eb091847059e0dfe5000f3d4bc8861d6909a7923ddfba4c4cb908370' + \
         '3d6125782488d766b102cb511b4da78cae738541f7e1cc619315ff16df4b8259' + \
         '7307b59f5be7225df1422e36101d02306470b157c00f1c00a281076cf4a21862' + \
         '87d616f04b601c0c7d4ca84cb1a8ab6ad58fcb1b2eb0778203cd484770bb6665' + \
         '226abdd80b72d1e67c5b59e1f1aebadd9a2eabddf568286c07921ea2c491909d' + \
         'c7356dcef436e12a067e929da271ac1a3871dc95d2bd68fd5a41c2a3400db31a' + \
         'cdae6b596af8c72e8d8c33096e3f60725b841d72e2176deee99db6c27b544bff' + \
         '5a41cba4b2cff7e5a8a79c93eae59ea3febcc9398434420cd39be9629716da47' + \
         '568a7b6389e43a632d11e5a626a1d584d86a1d0383edd7e0a808c0e76b741db9' + \
         '5e114c48c3fa37db0df0c8f690e6a77b161f154418f1b2aab43edc6233571c73' + \
         '970df7e7eade6a4d7149c1aa7de1e6a32a7e7f919f261c7193481e06417a9295' + \
         '40e697e6938ba2195b521a4e1aaa3498f51fbae169d86f4ea4ebb7d65ce0251e' + \
         '96a1da90e2a864abf0d1c241b44901d4d6b310084f0a795ade9abb85acb91c1b' + \
         '917c48c933c8ac08c1c17cc8e36eb1b1f74a7db162f008e06a8f4b5d28eb0d7b' + \
         '88c7a3cf654fb9a64579717d659e333e3169e75d03902fe147bea092a84a7bb6' + \
         '92bc28afd59e34df09cd5e4bc29c6f7c0248ce87640d974ae2b31318443524e7' + \
         '2be15d0cc6a8df1c9bec3a839a4f851a1b43fdc91cfafddf5dea91a6cf7b7b01' + \
         '5ef0f3801e2948fe8657f24fe701a096999a05e84b924b08370fd235267b5374' + \
         '337c30247de5dfd39991414c24fe575342d80d1a2d08c36399f62e61d7af5fba' + \
         '5aaf9b122218657a469ff39c61d503b469d3c97f9337f16656721d7d5e91584e' + \
         '17027c3e68ea8b8d7ed88baa18b07c911a4c19f1f4981048bea9548e04b02f30' + \
         '5a09afec6d57d5ce406ecc345c47da985e85daef490ba35e41a1755352f10b51' + \
         'f71e47deaf1338d862ca4ef4a2cf4bac22f3a0b790f5344a73f6b9b8d6d611c2' + \
         '4231c27a288439de571c03a08daa750b7767342e935f73fad6cd9dd1e6c8ed5e' + \
         '80328051014692d9fc68e6615b75ac9357b5d2f9102db23a6c977bca6db90f09' + \
         '6c5fd53606fc91cfba3f2ce711cc81023c6a76c1e87e857b7ca872e93c8c7de3' + \
         '1a89a149cd271a19185f31d1abfcd81d87a4fcaed7aebf0676538f6f00000007' + \
         'dad9d25c27ff89ffe2dd8d2b546286a42d13949e2f725d154896d82238b04feb' + \
         '8bc3299eaa6421245ac8ced4a4a982be81522d5f4b5be5c9e2e0c50b8beaf78f' + \
         'bc7533ba89ada55488247e5cab2648c48163c2e5be7b655de12963ec9c2fdd1b' + \
         '90de8ed3c8a506f2b2526ed1e94c99834c1a288c7ef82e4fbb78f2cef5223c7c' + \
         'cecb9ae99f8b16fc104b259dfd147390eaaab623a21503706ee05adc097970a9' + \
         '12a038586f91df535894074a3294a6dc684759f0da9cc1bd1c441bcaf8113db2' + \
         '93e3fb1e5a774545b5f490ab6e423c4cd647594690abe10a317a3f81f278eed7' + \
         '103846b9114226dfc1bd87ff322c09f9d795cd92d52afd7d1758973264c3919f' + \
         '78ed2eaf0ebb6a5a1c666fb4c1c832a21591d4337463333440e9a4b1b618b645' + \
         '2bfdb6912ba266b6b9fceaf3674060321c82f219802959e40d87a42467bb7b5f' + \
         '3a182bed49f985156cfb9f69a43ea6f7f26f9127db64f8a4ee3a066c5e080a2b' + \
         'a6e4fb7357d54c71b3046840fd3cb4106493ab63c7749ee7ed605e8c7e7adeff' + \
         '55c7d180ccfba10b348d9c79a05f6f710cf16d9033a11b543d128afdc5421d2f' + \
         'cd6c871825ce19d88e71ae5682f801f6ef91b88da9e7cd424e2e1404652538e3' + \
         '39a4893667aac02fa273a79713407c5306a14785c78d5a51bbe4ee994f779fc3' + \
         '0000000600000004e9bd2ee63bc56b54455cda15bc70f95726fee498f23472e5' + \
         'ae6896b9d947946898e9a1e2d1f8575b53bc4724df0461780000000000000004' + \
         '82e653986041d9dbf52604bfceae1243858ba37e178c36cdb6d2b3921e1a44d5' + \
         'b217ebb12c4da84908425a66fa37be8d3c49b3a8280c16d2c097e0e4371d2876' + \
         '19f5168df75f0cf1a554bd1795b9248e049fd54f0f2205ad3511e64fc303d646' + \
         '03286d4a760e1a28d57e11f61fc058a93374db06334a3e2f8c8b63a4e30a508d' + \
         '0ed19e45248c206165358bb6a9744728c2ee38586ed1aba597b0bff8a749a71b' + \
         '98ca8b679725146a39323d7ac321c556fae2e5a9ae90a59fc19883d356d83517' + \
         'ca1e9841fec0c8a91a15b0375ac4c32931ae6a6a2044afccfd1a89fc5fbab254' + \
         '26c088a99a2163856d074a65ce6015d80c3603af83a6841b771d46b9a5b60b12' + \
         '3a35e8e3b2642351bf0b53aa80b3c7abc9caf0907f468439aa5e48e797195fb8' + \
         '22e0c4bd6adda633b82e28973ce2b2064e53bda8c9feb4182d09f83a3df04834' + \
         'e3eac43fd6b2e9e7fc0f6bf2d9c39afac6977c357ec766993d814b09215b8b06' + \
         '2c9d233fe956bf2eaa89f607d10d8211b1be4771daa15d19b2b68b5290b9185e' + \
         '65cc62e32c65bb78c6fdf89dc9e16199401ab11c755f5182064f6f9a89733e33' + \
         '39c398a2cdcc35b6062db2c7d02acd3f85549828a523043d2a6425291f30d3d6' + \
         '6d4a4510f2692adee82b010b58d1471c4999bad7a125cc3f97d0694c2e7bc422' + \
         '338581ea6c7cc4913e354fb0b40af34889b84f996ac23f3704d45def4df49325' + \
         'a0a84b1cb1d58312c301ded6a7ebc4ffab4bd26ae191970ebaccce0dffa78013' + \
         '87b77f3d8eb41ad61eb7b7cb6319c51dc982ec6281c74641517a82b178264b4d' + \
         '5f24f8ddc59562b4a9bbcbfd74b244ecdef6cfaaa68b83ddee9a964bb97cabe0' + \
         '815bd6487b68e1ad636f69f8af1bad9a632cf104718c9722d81260a67898e2c7' + \
         '08a31f1b8f891b41c0c906cebdebd2885c3b41bbc3089e036f6bc1ded2ea6d93' + \
         'a1f515d217f89fc20a3ee59940709f41452351bbfef6567ff6d1ec6eb0079f8f' + \
         'b9308ff891e2990603874dc0629802cdd390dfb668ea1f0e76271b7dde6e0538' + \
         'ee9390f9a62a75ad975d62466182698713fef33574941b898be07710503100be' + \
         '6fdd58cbfce444ad6cdfa96b9de6a8aa539c970e7210770d01e2f20e62567cbf' + \
         '2cf8e130062118e2b01e9dd67adca43e436bd00009f837fb8a43d8c307045d90' + \
         '3e3bf92146c6a11588cc3b86eccae91990fbdbfe4fe37b8a729e86340d0adc9d' + \
         '8629a6859ac8b8faf6ece2d6b3e5c16b40ab1638e51c5e0ef50e21b69a6b34eb' + \
         '473849f1417a0a2e2e7c766c714b25e6127c88bd7ebd72a35195970432ef6bd9' + \
         '5f1f7d41c1be93513ee35f663cd7fb63f6b40c1b19c536ae15b6cd9bdfcb10f4' + \
         'd069b17b0c56bfad5b7e5527816688a360f5024e3b92c5cfe6f16c5769ca3b10' + \
         'a65dd21f6a3a103402f28bf329b051dc47b6ea884b40c6fdb6deb25f456a0a70' + \
         '36295a6960b678103fd59f1b24b24295c030e9d08863eb579322f58f9f5e8063' + \
         '1ea9421d8cc30cbfc0cf66a624dc46907a1c689f6aa48b88da65ed917c40a5e4' + \
         '41c74265f5228295ff4e70432b2e8d3023e2ff31b568d6f56872e078ab46b260' + \
         '00000006dff428e18ad4ac9d392531f1fa73b5c62c84d850c92b8ba2fc81c2f3' + \
         'ad9a5ff6f183895fa672ca2c9a33672c74fa06b60116287599450624865bb59b' + \
         'ec5cd6ca705df7cb1a82f706176ea999ceaa69f1ed1e863bbea0a2253de93221' + \
         '13e6a6640c9d4bf91434cde1ea8987218c30b0b74542dbdc10c5630aad162b6c' + \
         '6f6d04119317b0e74a0a31ec2fbd2fe3c34db484722d75413d2ba8d61f7bf35c' + \
         'e80c80cd56ef5491e011a366f5219bd6d966c6c4715cee7d7356924d30d8b33b' + \
         'b308c3b9362d37a59a9924031dbda583ecfca3555727cbad2722ff79fd1f35bd' + \
         '856f43c7bf9526d641d6b5198e2e70266053b0094a71c97b70c356a85fafc3cf' + \
         '00123e1eebc69dae50b29c7ae19614fbfb018ad9e55c8cc61943b308d2605a69' + \
         '414b6e6c3d8daf52943caab3e358eaf0d5e8262b5df0b8552ee5e0be27abfcad' + \
         'e60dfe0a')
        pub = pyhsslms.HssPublicKey.deserialize(pubbuffer)
        self.assertTrue(pub.prettyPrint())
        sig = pyhsslms.HssSignature.deserialize(sigbuffer)
        self.assertTrue(sig.prettyPrint())
        self.assertTrue(pub.verify(msg, sigbuffer))
        self.assertFalse(pub.verify(msg, mangle(sigbuffer)))
        self.assertFalse(pub.verify(mangle(msg), sigbuffer))

    def testVerifyCryptechLMS5LMOTS4(self):
        msg = fromHex('496e2074686520656c6465722064617973206f662041' + \
         '72740a20204275696c646572732077726f756768742077697468206772656174' + \
         '65737420636172650a45616368206d696e75746520616e6420756e7365656e20' + \
         '706172743b0a2020466f722074686520676f6473207365652065766572797768' + \
         '6572652e0a092d2048656e72792057616473776f727468204c6f6e6766656c6c' + \
         '6f770a')
        pubbuffer = fromHex('000000010000000500000004252f23eb390448e6bb27' + \
         '39d0dea7c26c19585e92cd428ba898cdbfaa0843e479dc8a0ed6539fbcf5475b' + \
         'c83f28f6e071')
        sigbuffer = fromHex('000000000000000000000004b555fe1dd483c70ce769' + \
         '05ead00e17607598369bd276fb9113a8ed8bccffd0862eee3ea17a2fc0017a1e' + \
         '46d57bf6ed4187b2c63a93dc4bb6c56343e5369c337a62d048ace6a26dfad23b' + \
         '2a714a1a90c4f0a6a0175a5d3f2b3235e18550f0e4c49b6fa6988ea4920f4220' + \
         '55dc196c57d909254d3d2156f6ff338e3a8c0a564f47722d3aec88401eba0628' + \
         '2663a5af7d88eec4a44afe891c54a8b9ed0f5fab9eff410fcaf8a3ad9e5410d6' + \
         '33862349515139410e3b0e62000ce8d0d82ca9e7bb7480af71f6b61f13e717f6' + \
         '995623acf9145ef65fcc2d0673e05c4df050dce485570099a116224d005b9cd4' + \
         '99ac34ee20ef0516f6496b8193d9bf0abcca9e6fab44ace5ae04b6ecbb3ebdf2' + \
         '79d0aa489b097869e42cb020e58e9b2077d1dc17fa5008aa346a0b4861e2f464' + \
         'c2f525baa53b3b13913bdcb2467da6ce744cd3ce527f515d5ebf9529d097ee9b' + \
         '2988af7830c0df01f4a843d327536f68e3c80819dce5fa58a5c54e2b1ee5edb8' + \
         '4de965b28af2439bf4442552cfab8b5891b59739fe3fa75de9dc8664b1ac066a' + \
         '26cb69d0f5b607597737c2a1e3eec1a982e745476e81f8c3a8c3cec09592fd04' + \
         'd07f2ae2639b07240f3fbc1738940d33e1fc9314b09c2af7910b50f5f76d6325' + \
         '471b8c836b190ffaf8f3ddb6abab81398a16575177a60959ab1522b775654a2b' + \
         '7a9a56c206a2030da9034ce908d02744f0b69c1291603e50b6afc65dc30f2307' + \
         'e3ed7886421eb24f2bf0722203a6bd33d901c0a04588c25f185d586e3689f0cf' + \
         'c265fa9aa39212b2435351fa1fcea26d8f14990f9d6b87953ad6dc4d07ad122c' + \
         '73cd91c41bc9fa7ce2cb0c8b7eb8044beb298da332a65a27fd304474605bed41' + \
         '65211c5ddb92ad127398bf9f975268d0299f0b3bc48fd14861b827705e5a997b' + \
         '8cd922989bd13fb74ed1196984cde8185678431ebc5e9c9e87a1fafe798ba9d6' + \
         '431779171de1a2ea1fd8cd118759afa3a6c35661913e9f209ec6f8860e82a8e2' + \
         'b9c4f2b759255f6b417907d9dc74c34155432cd3a52755ed6c4354b2e7e83fad' + \
         '5edf7427ad1ea2f9cf10109cf6347f94b913ac4e7d5d1fd8191a20460a9ef438' + \
         '0a58ee5beafd9653b575c70f06a5c961470e2a0844f11e237d25232204772732' + \
         '0684df25944a66c6dee3625c5eb6c3990ba4da029c8f5b17f74c5441f26b6279' + \
         '2f3e2057a92207360023c544e90ab01e01e12022a9a86a11806268e75d258bc8' + \
         'b8d2423e661b366be4a726b614ebdd300da9329436e90a44c7e59a360474d0bb' + \
         '99b16222b77f754f2a7cd310acabdfe82d4bb9d3998f0ed2d0b2cfa0948ed7d0' + \
         '8b5ab8e9ab132f4b0e90c83f112e5e37719132c944cda3089eb53f2825edbe81' + \
         'a30fce872b802d71be97013d26c32a89e6f911df0c7abcb67196a05c95ab2f1f' + \
         '02188d214f487334a4310563818831c36202c0248c789e5b9328109af0b7cc72' + \
         'af610c85f988b492821aabd5ed68b8495ac4baca394896c2ce2180cc5fbf9ebb' + \
         'a392a405b827b799cf011f0b684f2c3783836dc44ed6d6557d6a3bcd2df3d0c6' + \
         '69c7e823a96794db240596299f3635997ffcabb9e9c2000000050d3097937263' + \
         '943036a78ddd20c9a93feac4bd74094f9026356c3bc4aa53a5f5d9cf33adacc0' + \
         '8230f978fbe798dca261e84c7415bd7dc183595be9f7d2736ba578597e04b7a0' + \
         '1d74755ff18b9a0c2168d820cf5c9d2399e0713515bc5836d4460fae1a86a27a' + \
         'dc43b29f94cd809c94290efe9071430ff6ce3eb8ccf332d32b3688015072376e' + \
         '3df28d4dad3d80ed3cfb32a8a4bfbc56436a4dcfddd28ed3dca4')
        pub = pyhsslms.HssPublicKey.deserialize(pubbuffer)
        self.assertTrue(pub.prettyPrint())
        sig = pyhsslms.HssSignature.deserialize(sigbuffer)
        self.assertTrue(sig.prettyPrint())
        self.assertTrue(pub.verify(msg, sigbuffer))
        self.assertFalse(pub.verify(msg, mangle(sigbuffer)))
        self.assertFalse(pub.verify(mangle(msg), sigbuffer))

    def testVerifyCryptechLMS5LMOTS3(self):
        msg = fromHex('496c2073656d626c6520717565206c61207065726665' + \
         '6374696f6e20736f69742061747465696e7465206e6f6e207175616e6420696c' + \
         '206e2779206120706c75730a7269656e20c3a020616a6f757465722c206d6169' + \
         '73207175616e6420696c206e2779206120706c7573207269656e20c3a0207265' + \
         '7472616e636865722e0a092d20416e746f696e65206465205361696e742d4578' + \
         '75706572790a')
        pubbuffer = fromHex('000000020000000500000003c03bc9f29edd47c497cc' + \
         '136c258a3c9c8c9c6a1a79cf69fe0ab8e99327c536b43fd0876319c31988c943' + \
         'ebb6aeb97a11')
        sigbuffer = fromHex('00000001000000000000000333b2eef16b9598470c9d' + \
         '4612090b60ef997b20c16ce3501a62ea65ed8a31e3cd4e99098e7840e8cfb450' + \
         'b15817eb564c0395047f5c65e68ee7a4e440bb67a8bd654c3d984a4787aa0309' + \
         'd9e6ecde7a98ff57ee126c82d11d288caf619f7886f6b878bc1fa8efc11ae30d' + \
         '9e01c158a792fdf08768a98d163e9ab180eae8e46f69988c7e78ef421fbdc2ba' + \
         'd01b2623c0c557a0ca9816c1b76721590f2d39ded59edf780e3b9038499e7e3b' + \
         '40d35009b30a795d924f6bd0d602071f5873fdf6f7f0c1d8f046222f88b25168' + \
         '67254c6d8a2d148f36f05d7ca5ee6b20bc1011c5d33372d1a806d55a53733480' + \
         'ade434c195787269e20da87006da772d0d0079f50c0dc2676cc14e78109fa8de' + \
         '459b408e53be21bddc23f8bed95c86ec3ab348a5ae7fb484cd5397adeebc1324' + \
         'adab443d79c7b39aaa915536d3f2e3f0d7ae4ab3332605b9ae858509fbb1ada4' + \
         '64d84f1c5a26c99181d9587795c33563d55094e813d56cb58d9b20216ff43c58' + \
         '6a99e20eed3442407dcd59f7892d1b0545847bfa73503edadf17a517dafed839' + \
         '874adf8f4df3e8dda0863c9e6df9eeffb9097ccb27ea5929ce29087d523f285e' + \
         '0af8645012658fe06c8f0abc48a73cb19c0701a8ee1ef190a72b3fba90b3a636' + \
         'cf3edcfde978e378499f89a53df8984e8c760f6643ee7d18e63e3c80120d4a6a' + \
         '56c3a55100adf2384334b06530999fa94192e97184068cefbbe519b68198bcb9' + \
         '13ae2e5c5f2db2913dc3b881dda60ab2bd06d09074f230439e40be01ce080466' + \
         '6300ad7bfe72a43f18d50fdf2fec8c4fff2324a7502bb3e3614656ed5bc697f9' + \
         '72d5233c4fba2a81e7eede74cf109f1e0f7870e15f55da2fa200a874cf2d9952' + \
         '468b52d1bbf71889062d3a7a8753eef1e7b7b451d963f143c52d3193dafe6e7d' + \
         'eccb98e25b98c0e2ceb1a5eadac896108ece2cedcbca60e21fd00ee1d4b2e4ea' + \
         'd3df585c44b37809c0516133a644780702d4938a64630d5e8e4827dc70d2bbf2' + \
         '37f5dc46c50f38b5b3ca8d9ae4f676ce0755967d9ce5ce87abd017ac53409ff2' + \
         '318cc91c34e0a37ac810591262f7e7c29062e49b296c65594277723f38059fda' + \
         '499487e9233dfef2c1c70267a297a68ed3ab26af4ee73d155f23d56309359f75' + \
         '6e45697703db2e6172fa7c299e595c653df1ae360db5c3f5dbc73ed0ddfce960' + \
         'faec77d7aee8134965540789b4aefd32feb293854ef078a727afdece8247e900' + \
         '2c26436bafc9d5d5729dd933a5eaafb0f03c29f858715ae922149cd2c9e95351' + \
         'fa5483b74c203820e4f9991237df02a1d547f4944ac8039e11073e34716442ea' + \
         '1127712c084da05e4caeb0a11b73230841b83a89a749eeeedd825bdc0357d831' + \
         'fc57becfd79b49d41ff1e691a67c574ae5c1451b79d084441d4aa38c3e2f3ea9' + \
         'a215393175ba318170be62c3bd604bd9e0ab787189f29845d1f888e2db45d1b4' + \
         'ba758df3255b895b378dc235146720f73f65ddc1898f176b96bb93010d74567a' + \
         '79f042dd3e81080788fd4094b7c33e88de46c78f0eaa64ad7dccab3996b82340' + \
         'fc1f40d5f8e44c4ecda729fc11e8a7e1f8e25af8fe1a226b92d1108dfefd4928' + \
         'be2e37c6cbbf19a4f4e418eb89eb3e8a6cd629fe1e4eb87e9c1eebc148f58aa2' + \
         'd36dc539610765b5a4ad82c078c1f165ad63f208e53aaaa0f06a9fd52d2eac60' + \
         'f1fdc07c614b941fd4d643546c57c42e92385a6725c9da30e1237d184a6c87e0' + \
         '2d3eac0aec9046693fe9be312158ae9dcad1e0b9c7582e6fc3ffd430f8c43b36' + \
         '5d214454797cd7125201c2e705721e02f1a7c8b6cfbea7dec05fd2e62ebc340f' + \
         '5d654a644defe9cea45e2838de0f9c861cc7b3a9ed878aee2310ed25fc6273a1' + \
         'bf660fd2687546cd0e0bf9ee36f897bff1af3828c348af33fa6a3613c983b7f7' + \
         'a2cec4e045e7560626410f9937ad90a7358065881275e77c922772ed3aee4427' + \
         'a9c239476c338f775ca6fbe0b3d625c3e682cd15c3449ea37556c071822358bd' + \
         'a86165e3a7c38f4a41af1db75e8bf60027935526d0f2d9ab21b5da682f0b1bc8' + \
         '5d3516f1e0f9e586df153d86300a6ccfa7226bde26c625d94c09c6cf539e8a9c' + \
         '5dd653ec1ea92a9c4d4feca14bccae7f3c27037f4339ab582562b51ede9c2880' + \
         '52cab12549206624f14c34d2c9123ff82b2b6bb13115936f26d7fe741ee2ae20' + \
         'a6c8b8363b7a6c6d6af8bfa97d20230473271b0792890813633e48ef2dede6a9' + \
         '8110c02669615983999a7922dd36b57966055a6b42abb071e6079dab67a58989' + \
         'cb001b61d1569992c6a3b110c13d45da678c3969b0daa1a57d766695d7d3c064' + \
         '780381c85c96ce0a771aacd3d9bfb150bf6d5693da2366e49f3a243cf0828f89' + \
         'c5fae261e4a84bdd29a3f6b66c81adaacf861a57fdbb8d4131e17d23a926872a' + \
         '0f454ffc8440a96a78106f805dd966de41ec5c5d3e3124fe934e21ee715a887a' + \
         'cb14ae5d9c3e7717f5418f8f71c262189ad08f895832df42279392768fe9c123' + \
         '3bf184ad7c25762f2f51bf84ac5a52c96847176a2fed91c936228589fb9d6473' + \
         '67920f7904f63c481e5a617dd1e1635b8f6d087b6e4a9360cff1d0fe71f45e10' + \
         'ea01440b53cede5833851ab01da2a37063629e831eb08ac7d45989ebfc6d9b6c' + \
         'bdcb8c85f1255653d301c8cfd2ab2cfcd772426f7ca4f2f094fdbe743d7e4d5e' + \
         'f14c3392f252c897c79991e97f2cbe82dee67c5e1c14eee248a597b68b0a8bce' + \
         'acf513d1a4f9262e798063786130a49d48b9b0940640e8ffe1940afccb03a07c' + \
         'ec10445455f6ef41d1970a656f77c84cfa9e067a61338bd6819bb60a6ab955a7' + \
         '3d939b6773e6877ce1cd91119b8c6468fc09ad5d3d4344c8384be5b91eff6116' + \
         '5579bc1739a0b26be5dbf7e9b7850563304618a5c57ae2ae2443a805e2992af7' + \
         '16c273ceecb8dbcbf10f716f5afc221d6c2455a38a8a046cc8e8405a7cd55101' + \
         '9ef5889a042e09e2dbd5f771fe025f79bc596df54a73c3d7b46863fcb6c5bfbd' + \
         '937fd256b2a167896bea518dfe601fb38967a3323399949690af4d44958796c2' + \
         '2ca60f5095a2c443bc88a31b3e5c3a3c750c246f8fd90000000579f88118bcdc' + \
         '34431f15a8b630504eadd7fd1a2260997e3c413258b4ed85da96807b3b068482' + \
         '3567815312eabef25358d756b69f15d2a8630dae2ec73281113efbe11c8110dd' + \
         '416eb1090ad6b65693991829b472ce2bbd283f3254dccc64da67ec2a221aebca' + \
         '9d78e3b0007a89e97b9ea1a7fbc1769a3c6296ca07e93c74422a9963fda1dfa2' + \
         '3e4a4a1a20452d9da1ca50e3ac03fa21c50a75cfaef1faeda056000000050000' + \
         '0003c63549df46f94d1bb0dafb337aa176bcad04d3a2d7e9dd79b7e6237b5d05' + \
         'ff983a5bcb18e32a6de1d1fcdfb2a25142c100000000000000030da336e94bbc' + \
         'a4e836a4fac2e8974d178a2fa934c70762c3d9d8953dc09ae730cf60cd79e401' + \
         'd59111b9d27dea0363419893a77031222b3b9fee5acf5201d896d3a6c2b10d67' + \
         'd4e771036e5f8d89336762f5fb4e22decebfde67491af931561b7c16e6c28143' + \
         '30fe16839a915daaf8d521e41a1b0bbd43dd621b793fa982f5830e3249400632' + \
         '6773ea9ba5e0c1cd56322011f57adae278f3e4369cb01f1f900309404655f8d6' + \
         'b894afda905a2f5e4fcb406ef32d4eb3cdeee95116cf5e692dacb762491ed309' + \
         'ce6dc5d91e466af5ebe7086c6573d82f1531fec90ac05df454507a6de0e83cd0' + \
         '0cdc08ab1cedfe82a942f48529619556f8638ded2b1dd6bc16a96126bfbc766c' + \
         '79164f199f1494b7d98dcd2d6ecf9ce5134005fc1a1d984ff7702a0f0859cdb1' + \
         'df91871a750fdb24bf7cd87d031f299ffde038fa672ce8e80fc404a55cb56f3b' + \
         'b7898d62b8eb6e4870c95307f00d5c65a6b5122f58313ac4796ffe743585b2b6' + \
         '1f2a0a4206616118adc5810adcbc50e3e1f0fdff3bd748d433751eb43862df3a' + \
         'cd06d0716c940ad6e558dbc5bbd32617040e957bef267c3c34349f7c27f66408' + \
         '0388f6dcbe97c7689634438b87b0e30b84b0e7b55a697f4d1582ddf1078c3b18' + \
         '7b6010f115ffa14669b810b6d7040c243596c53e861c612d97f9d309bbfdfd0d' + \
         '635982b57e038b83a7ec376289b92826a8771b105b7f97ed49d55b77ff16ee44' + \
         '48cdc2176aea67075e5376dd9b25dfddad898699d2ece95bc61c717706ac3ff4' + \
         '0dd060137d1fabdf608f30befc797ebf71720497ec9a709a8325ecefb5e6f708' + \
         '010f03dd8c416d0c28b6e23625c1b675400ed34b69f43b6d26b9c2823ef6b727' + \
         '861b183032a5ef4d7f720aaeb2630f8957fe61814f8a752a0c429e8c8c9022a9' + \
         'f677ee2b799985f89dd311f904c17f21b8059d83e403f020b8ba98b04c195edc' + \
         '5cdadd3fb2f0dbf7fd6ece1a65b2f18f37c3d1340a807508c5e5bda9e6c60bc8' + \
         'fd3889f640eb8a9244902584570ace9fd0433c5efd2121c34f4ecd89eb020e03' + \
         '3a33dde3eb3c8b199560131459411379c4fcd2adf8f77d89c6727b35382d70e9' + \
         'cc8dc0b1a65cadbe559763c3f3bf9351ca749a7670e6d7f4f9850a584a78b4ed' + \
         '506a7a86ae650b301bd1feaa0f9d1221935e0f018cb8b2cd5ca4065bd732bda5' + \
         'e2a267e7736c87dc195b1eac50273ced1a8845d82b2024b782e2d5a310726ee4' + \
         'b6dc629c2ddc9c74a3568f33bdd731d4b6107dad07189eaee0a4ff550fdd9ca0' + \
         'da5778373856785ed0fcb10adcb6b1a631dda0d5a2eecb59d5deefb7e7007c01' + \
         '0f3009f399be1efe5f4bc924d327bcd3532e13ad2e43a1c737a28f378b9e5bf4' + \
         '81dd412689b7b313d2e3bf2ff2b78a7870e9914faeb45988a67955abfbda3e2f' + \
         '2d7c0b0cb257f9c13feb4989decf42d4480b468d18d7b2a921af14f354869fbc' + \
         'd05d63fae15de91ade383b506c7d974839e74f8783d38780b1ece3e7e08c222c' + \
         'ebc73dbce655cc2831d4e4e606ab965bb080613465dad3fbb16e827c1caadb3d' + \
         '26f1590c138ff21a080e9dc719daa990a072ed7b9aa494e3686381aa42b697d4' + \
         '2a033f0ad2cd0b79e5ea51681c225f13a2de9b89f6da99398b703ffc5b347317' + \
         '341e9f0aa47cf0ea495b9f2c1dc10c4ce243842b09e0dc1f0ea3363cd2d1921f' + \
         '000ff088e548b75a432595246ca66c06ccc95b9945f831bcc43e2fc7bb302006' + \
         '4b380ebb75bec3438be2b4300149c924f579692c397f0c20146d63a4acdb8ae2' + \
         '6eda44f0372d6cb2751dcaf05510a89a901b05c321e8faae428e38d1cfd0bc0e' + \
         'cd227c57aa8e22b2a87e801b0d189ab9c3624898ce3fed895cc99fcebbcdad76' + \
         'bb205b6e9879d8f5792b8619392f25e8f951548ce7b4fea562d8ceacbd38da62' + \
         '9654ae27a966ef6c6a6a0b91e9c6455d6ae45810cf250f60c4c8919bdff56f00' + \
         '8b535b8b932e2890b7252b53bb05fa205cd2850416a7aae97b16b10c86b46724' + \
         '0d054ee3d3f601a8f8d17d2b4db4e76452eee921cd6ebca350dd9b254737346f' + \
         'b67808f01fe206d1e473b055bd87d043e515d18262dcd29edcde34d8987c9d52' + \
         'edd05fa53b0eeae15bb052b9602e05feffed69e8a5c120c33c7d4f5140361688' + \
         '10ddfc837c815fa46fe6601be20fe1d643c1bb8421f624bcabb9124f1753f5aa' + \
         '180b648a90a3c45661cd570c2d2f4698e73b2b383d2525939a0ffdbb8c201bdc' + \
         '63997b8dd5e23c73e32f747b51d157670b9143155265c37e7a2b942c8f661ba9' + \
         '283d5309b2016382f1e6fd36740273445a85f5e8e0186229cde37bfebdec2e6a' + \
         'a38019eaf06401149fc4634c63f64fe0889784adaa7333254a6c8ccd26808b23' + \
         'da0381f9b51521b56ec64f36c7a5dd3336e135bafa7f982f0ad01eba2e9a9928' + \
         '1aaf73b53fdcfe3f0022f7e08c439a3e09f8aafec1a645b181492a6ca76302a1' + \
         '70813ef0d55537c08d4f0819985319c62d160870cb9b51d27f8cc5c23edf1dc3' + \
         '896181640bc03658a168676df3112600a845f546f17c4124af93e936bd5fa35f' + \
         '152666d3ec6c2c52bbf9d71fb779f639090932fab4f41a0feceeff1e19232da4' + \
         '3d409e2b516bc490601d8d23b5135bf7142ea3af65890c7969e3a6a8061e9a5c' + \
         '2146d20c20e838e90fc4090bed0d3a859c7e5d808ba59637f1976a474d6f3eef' + \
         '9fb9da3d1375073157909dc05dcf99b5be63c32227a1273928dbb0fc6c396790' + \
         'd78f3796b4a7c64bd5f4ae6cf107b9e8efa4839c462f6305143d4072389eff55' + \
         'e410d44fd50397ec44820585b4388b08cff6af4c5417e32072724256562e8aae' + \
         'f5da77b085af4ef6c7bdc5705edfadee134eccf1838c03574720c487501bcfd6' + \
         '83bb0dd52404dadf879dd77fd0b40dd3237ee83854ef817359e24db6edd72922' + \
         '946c518bde26d2aec51a136d027b9eecd12911f1ec0847d7f3c865f05d1f3f84' + \
         'a72cb8f2014153e77582698b8563fa4a7f88db7c76bfbe2760a2a1399d5083b3' + \
         '4f1077025cd0a075e99acc9fe19a96cb92e0b2d71efb5149a5478489d3fe4ad4' + \
         'd0d40971216f266b3b2357c06c906b2ae6ee3eecea3537c3a775000000050d68' + \
         '9fe64b6dad8a84803efd298f688d169d318e7dca25c42d50c00296cf53e897bc' + \
         '3d523cf3b8c8892d83c78da74dcc330b8534e53d922ce0ba1d4a9f0a14b5f428' + \
         '36ba9d191995cf485136805c41c4eb2821e48a42a5f7ce32fcaffb40c984b895' + \
         'b99cf60fd49133729e46a12fd6824c02f59413d4dea9085003527081e39416f8' + \
         'b935863df45990a385f5c437fcb745307e3046f5f1b6b10e6ea02262116a')
        pub = pyhsslms.HssPublicKey.deserialize(pubbuffer)
        self.assertTrue(pub.prettyPrint())
        sig = pyhsslms.HssSignature.deserialize(sigbuffer)
        self.assertTrue(sig.prettyPrint())
        self.assertTrue(pub.verify(msg, sigbuffer))
        self.assertFalse(pub.verify(msg, mangle(sigbuffer)))
        self.assertFalse(pub.verify(mangle(msg), sigbuffer))

    def testVerifyBouncyCastle(self):
        msg = fromHex('54657374696e67')
        pubbuffer = fromHex('000000010000000500000002' + \
         '4ef83a81f3197dcbd75e398b0594f335ace350fbd5cbff78552dd1ac1293c27b' + \
         'fc4e64365d65d88aeea3d64cb9cd4f42')
        sigbuffer = fromHex('000000000000000000000002d8217e20cdf4b3979f1a' + \
         '1f263a9b0a2d0a9f23aa2c3f605edc817a7077a3a977afdc80ba76094d257395' + \
         '5ce679a04b86fc98842e7bae5714864876e59919e7edff1445520feb31d963e4' + \
         '6c2f7a83f456e1ad7c9dbd1ef60e96bbd82fd6d82da839965da704e9ac617b33' + \
         'e967c5354ec532d9b974a699b59120b14832099b6cfc8a33a9fbacd84303075e' + \
         'a05fc27ddc0f19c3fc0353094443b6a73cfd9c6c9a728f3c9388c374ee6a1c4b' + \
         '3867cd91cdea2477d37d472b22c33a5d8d1e3231c309ac30c3bb2a5f5ae40ffd' + \
         '52905532a7eedd506b1836290a1358289bf2f9b1ef3ab691dfc702caaeef7215' + \
         '1a280ea3fe7e1e62e0e4bf4eba7b6c9e5e8f52bd04ef8d09beacd8511a432e8b' + \
         '26257d4be04d89d82550cbf429631b83ede1b98bb2780c28c0dddaa22b742a4e' + \
         '0eabffc5df90344f38376e1c412cb5de717d9ae9c3ee5c5af1e3b883ed4e5cd6' + \
         '5369bd28b4d6985c6d15159ed1bc925c367700625a04be797595f00e75348863' + \
         '9fb9b0d719aaa7fcd06d6aa29232ad5026eb2840b35ab12a6160ea04dfb42c79' + \
         '564a00d3045de779c2a27af9c1e1b8a90fc5c839e419a531ae063d4b69269afc' + \
         '8a27c90194944847b772b3ea540b738925146cddb6fe9a2600d3064d42ee1dad' + \
         '7a5cef82b85f66fd1312f860ac4ffac98a63f0f36273cecdc2fd794a113da102' + \
         '87ad27048727c2cc75953d1a68ed8408d2594c337013c0f4a75309b2d601a0fa' + \
         '75e894e216c1d20a8e9f2008a049fcbaece7c976d9b63e322cef897c325fdc05' + \
         'b8355e791ca0741f04a5f63da0d19311933b9beb1693c65642f67c742def23d9' + \
         '3d4931147948f819e3238a2ff463beca736fe7bcb110bf4b8eb2a20bcb697109' + \
         'd3a668e0b1c9256b934efffa8365c4e9960d7dd44fa765e083e755ebec6e6d09' + \
         '3759e0e8f8828aeff120a1e99bd54ef0b8a06b0382e6185a7a38094c97cecdf3' + \
         '59ac4e9318f40fe75bd450f44bbdaac5f83efa527aca7e653d2e5806becbb00c' + \
         '6151dbcaf98443e6291c2206b267b0ba0fb43de2fac14ae02f6b1f9e3ced461c' + \
         'b7514a232668ab42c65a8c3201713c23d21d7d1c10e9368d0a67965462d85128' + \
         '22f7f06e4eda9a289e3e4b7db55598d2e115e172f7de8f7f24f4375c9677e19f' + \
         '75b9803a8f8497ac7e881052f4df8ab7af9b45afcf24a90603a934b049cbc42f' + \
         'b9a3e1366802973ceae880186ad9931382fed38a2929d2a645f378fa1d6b86d1' + \
         '73ffdda074965fe2e1877f12a6ff0b1a7390926e75169af6dae7d3f26ec9d428' + \
         '697fc13b976f5e7a722f413ac8502803bb11e632b1c72da81d4a76423d76bf3b' + \
         '4bd8e54a3cb4ad10a76b553fb71051b77f29e5aa050997129139a03d5a1a9a93' + \
         'b47fdee344c30f56c5072d2330c62146bdddbc5bd7a25f0684ed95fc6deebfab' + \
         'e97af348897aece35f75b80060350fffab7e854786cae66d31d73b284e14853f' + \
         '27fae9483d8d2e0e59e635f41a403dde970efdeb9a31380f3e9855f715d08349' + \
         '06c86aa38ea757b97df4ac373f5d90151fde98f5a6aaddc54b3bbc11e3168dd7' + \
         'cbeeb07ea0dcd6624ec890c7f8ed4be9be106fdca96493ad90f4c95a622640cf' + \
         'b7a414aa2278c42b5e5ee6a1c38785c9db8d94dacfdc6b4793831b344853c0e6' + \
         '9ac2d77e33a323261bbf535ed3bc7830825ada5255b7e59e606bf58ad06799fc' + \
         '54836b0f411fc138aae0218db73cacae78fca15ccc79dffe38d1a8d08eb26496' + \
         '83d6b3bde49a4d4f34176b11577ddf0322c3d535a418c203b8defeb56750fcf6' + \
         'b9bff53550ac7c825716bda92fae1d1cc19cb096b97c267eca8d8b3ccd18324e' + \
         '00f67979d4c3c177cccda4109de9e7d9cf7fee60e550519c9bcb44aff282bd3f' + \
         '063928b7f9d86e3c0d58099fddd87d913a4350178bf807c383a3ed18ed3d3d3f' + \
         '5354eb2a0c36c71f0555467c1471fdef9569783a7ab8e0f593ded0d876caa1ef' + \
         'a9940d71933e41ebdf4d4e575904c1ddce0b7dcd2ecda9efcb572443039983ea' + \
         '2b394ab67264275656fe702c7a993af614add08e61970d1730af49daf882517b' + \
         '8ed9247f78cbb67ca171877fab25c2af085b679cfeac8427f810ffd71427596e' + \
         'c209d7231c3964b05461deb52e805a5540da985d11fe28f1bf606150ec993e29' + \
         'dd5baafcc3734f1e0a52d67dd4ae68b6247024ef5ac41e20b5ce53fca5ab344e' + \
         'fc860327db82a1a18cd13055c7bfe077cc342ae6ec81b9eea123934d3511ce46' + \
         '83b9c6020517780c8ee3f5c5fb67aff15ec03ced617dbfbe1bf8b0e67ff3b4b8' + \
         '2fb710ad5a88ab041cc34f4da5b667f67d683415ffb4d7bf35ec99c9a7e2c51b' + \
         'ebb34767049089e1318b8a5b7b3cd1456da350c8a230b901c0644d608d7f6d14' + \
         'dd18c4c0e755f8d8a79b6d411f174f07cf0d91d109172818bc7d0ecd75fc44d3' + \
         'f72e7a081abad2edf6c3bd0dc506abd539cfa83dddc9f0aba8d701db56b417d9' + \
         'f3b1c9c3805228504dcf021b2644b06517cb136a66935c7b0913d159f327e6c4' + \
         '54d17594fc8d8aadb3007e9fc5fc4f4aa2022e3e240bfaf8d1fc7ff30f1454a2' + \
         '8929d87ece48079ba5f4cdc26e1a0234a8fc4c39416ca3a66a7c4be70acd07ba' + \
         '283d9bb5f32faa908423b0b119aebc9df31c1a037dec4f595e932e06894306be' + \
         'bea8f577225edb6ab199000f7b19c01ecc67f88593b849d977e587394b37f6af' + \
         '9de3a838c4fa3e8cbc9b429b5620816d8e9311439f32430985b57b9534d07d7c' + \
         'e11e40da08ee083139aacc9888b68f3e62788d1b042839c083928551f46ff51a' + \
         '3dfd399c0945de6c230817109289424556600f289131cbd238db53631ae3eba2' + \
         '1ff00db0e2a3d0afe3dc2450064c192fd21ad06cd325ae3f6bb0343a754a84a4' + \
         '25b3780bf0237406151a73800faed251707546f0d521334e2607dc15525129d4' + \
         'cd3053d3e293c380fb38ee2971c1d32ffd8024848ddf463f98628a4300ec8120' + \
         '97575146f0a2157a53811ee8e6dccbf06185813d10ebd5fe2aa4c14dadabdafa' + \
         '7ed322ca9c47b1505867c4e3c7b80edb6378b811340222fd8f977fb0b676f0a1' + \
         '048445dba2375ac7073f873109cbcc2971c3bdafef262fb7e06d6a679bb8a77b' + \
         '1af0846fbb3fb3b3e73c68f097cb53e673c40d9e7881322b10ccfa609e0df885' + \
         '63d714dbf8f2fa735bda752b027fa24f2d289b34925675b23600a9f6f4a9bff8' + \
         '746deb48d084b8638dae616d138d38df8f9395e6b9c9965f76e39efd7ca00c54' + \
         '150dc10f5e30901788163ad163be59438415ef2e179e7381cd176c9b2bc0a127' + \
         '3770495161f3b6d23c9c833e0f6c8088ec4ec5ece0a6b62b5472d3a6d62b0a8d' + \
         'b8ba546782fc29cf3f0b91838ee564f35031c6e312c08c12abcc4e5d64905880' + \
         'b4d59a52d79113b7360df77cb26325c261aeb87708cdfdbbeb997940d8e3329e' + \
         'a8c198ed4feeb05e0691023470f5daac60155940992a82a1e6217812be3966c2' + \
         '686538201883c87ff80b9ae4630829c26c3399dd13e0d24259745398114028e9' + \
         '1be723feedc04a7752c3ddc5e8464a1ccdc5e85fb2186b4bd2bfd7f1afb9ab93' + \
         'b491d9f93f72f57624e21a4ba67cfa5b037f732b22ab5d506c54650c1091cd5a' + \
         '52a52e039519ca3decd6a07a6e4f3c7c2dd3d941efd3ba657400ac0b4905f2c0' + \
         '6014980cac4cd57ff14fc33dcb210458b7aaec62b466d4fb0c67e74f35914e19' + \
         'f839a9a7ce3b62f7d8a669a4355cf4c791ad31c535ec993df4cef92af6f555bf' + \
         '3c4b206f7474bb1048d831ebaf50e0c203ef432832a0aea3d6b46d87a5aa07f1' + \
         'f13a04bd502fe0ce222b95cebbbcf3b8fa5efd52b76d2e139a8e47aa298d3a12' + \
         '70002301dd95d9075b112851903150233a1ea8de4496bfd0d0a6bc0a2d1997e9' + \
         '6196f8966c5f500bce817b481852e16a04dcc0126cedd96f4acf2e5568378582' + \
         '474cdb9d4e3dc9d32bcf83c35785da2d44f96dd0e10bebb1138476208e3d8ecd' + \
         '7f95607b36a927dc4ab5002ea98d5607f193dfe9e16f85a4ac778318ac3f415a' + \
         'cf9e3b3a9fabc77742062c94e0ab6528ceb75d18f38426c2e80ceceff6721118' + \
         '17fec4d34097685c44b9270b0cf2c0b5dbea2b82fdb68b42002daaeda50c1d88' + \
         'caaaee74ba62718102c1cbe8e169c5c5a7e74cefadbc630323481a24c705a4eb' + \
         '535c4147fa22294f2e6c4ee3856616c10ba0c8f7488e47b68713aa04941c640d' + \
         '258a0d8be934837076dabbec404b71f7dd28b70991e20cc3e6baa640668dbc9d' + \
         '3862da9506d0ab4599d8070e023433d0ebe525fd692ce133ad83fd476d9337b4' + \
         'e5851acbc9a93e3ddd8467429285feea625f02edd65f12b6d4be69fbf953dc08' + \
         'cdc6a719db84b8c3ec1a210cd525f6731a54bd67e272b2cac72faa6e59f0bd75' + \
         'b723143ee6314b2c1cf3137dbb66f56b411b41a0eee7efb0f1a2133c67ac65ac' + \
         '228bf684a948e00b09eabca1c1902d042690c1fec3666f79c79b245a505070c8' + \
         '25d2551e4dea555010903675ae84206da5b175ca7b7af95f11daa1c68b38923b' + \
         '3c9ae64d43f3ff6f2a1ee3634f8cdc18360eb0dd5a4789ed69b1d6967c4317e9' + \
         '05123c80288ad51b79b28a689b7439d1969ca89673c098e3a63ebf75d02abb38' + \
         'ee9db6505d956a2aaf9df8dbffae996ecb296efc0cd0bb255f05cd8f760ff166' + \
         'fa0c951c40b9151b11f3b90ab114353a1fad189b22e80b9620a8753414cbdb92' + \
         '937665952b08a4228a941f05eaa73eae51c4f64101ab26f8c591f31ee3790c2d' + \
         'e74c30f53c7c900b5624a092e3349a8556cf401b28d23c54454d4102ec085a8f' + \
         '199e97e09fda850dca3ef0004401cd74bbd7028840c658dd44a6988a41b958a2' + \
         '9d005c383fefcd1b7baec3d936580abfc683411f3c042658f0e12da7e0a48dfb' + \
         '60a2c99c3e68a53f22b81acf3263ac4ba0f2873d1fc1fd5b2bac330ad65c2109' + \
         'b7e800a63981f8e6ca65eeb8dbf87e581c7f085f10592a8d4ff66a0515826ab0' + \
         'fc28654d52f45da46e959b8590ce769d5ef0db88762ae394b415b6271f25f269' + \
         'c11d4f90bf8c87feb7caa609795a787319ac09f6c17823c38111644e793b8470' + \
         'e2ca5ebcc7a0f53cd2a14f0800c132fd66b41a55eeda396de4f4a07725a6d47f' + \
         'a2c2969fc9d52166863aae48d30be4a4131ada20a9591ca4621b45c96efb4f8d' + \
         '836a88f06fec5b05979d37ef273827a976f5454159c3fd71a52a6809821c8688' + \
         '2ddc2171ae428ed45934e661dae81faad6d3da8e3e4c1fbc097f2e3c8ee026a6' + \
         'c324c4a179b9a61570592401dc7091485166613bb73465600ffb6dac16317bc2' + \
         'a216bb2d5f1dd958ebbdcf728a86e79066b606c9231725669c69760a6684081c' + \
         'fcbd89350b87475fba236dc3cb002a90cbbce100f324503ca690595ae669b0ce' + \
         '18edeaaa987d5a54b7e99992e8ff7bce09ebc23d1a2a4e9954dd3f8a05c89a79' + \
         '2c4374b7759f4cf35c7c18d3906f9cf3197488749b2682549a97cb8601bf51c8' + \
         '499e10e83869af0262570078bc59028e9256c95ba78c42827d6479b5f1b77eb7' + \
         '5fcb9d4c0c5114ef6133e50fb444da14350259a72d37d760328930ecc6825d9f' + \
         '054f0bb110966b892d7840475be34410802bb05cee1dcb4d7c0554c1b3724aa0' + \
         'ed079341570fceb29d7f99b5571a5b26032d184d5dee04cb862f4b3780699f91' + \
         'd4ce3cc4fc1dc61d17f01dbcfc0b14e9b4245a3e2ce97796ff34dfd2b0c6d31f' + \
         '2fb91dbc985d408a9614f6e18872f17b553416e662566c1e0edc5da2b93554f3' + \
         '448ae0b2ee07240fc11d2794e39ff6c1a25b3dd66415a89781566498f26d690a' + \
         '9d59b29355134f646bf2a6e2923017fb0a4034fcbb92af06435482b8ecda3743' + \
         '2122415c9b568bb6627bb99c71c6e72e49df9485293606c895375558564e248e' + \
         'e57bf3b4d8224b886c39ea08503e79978f2fe99cf3d8ed25f8b15bbb411c0ffe' + \
         'f2219c5f64b5e8ff65fbe7f5149c9a011aa4a47d07a644ee83e000f4bb0f179c' + \
         'df1ee5b5b67c8895d0124500baae4770089d8f9603f67fd73a04e05e9ff4cfad' + \
         '785976dd6dd575da50f9e44f1570903c6152da8ab0a6cbbef351394fa797148f' + \
         '72ab65019ecd4b5ec2c312f805b82522c61cf169ae0d00000005775f2a16b768' + \
         '321031dd84511c09394c1c6b883048fa6cd31e1cbe9b854647995efa572c9473' + \
         '5b79569ec0a526ed9c41f292c84d2890e6080c36e9d79b9fc32164c62ea576a7' + \
         '2a5db7fccdbeceda27f8daf670868a767f0679eb1f123cfb8dd378a93d31d2d0' + \
         '998d3cf0115cdd1d5eadb4f9a1e9c83c002213e7ada51033f475bf20afd7dceb' + \
         '018861b0ab6aaed9598195aee500f79f7447fbf8e3483134699b')
        pub = pyhsslms.HssPublicKey.deserialize(pubbuffer)
        self.assertTrue(pub.prettyPrint())
        sig = pyhsslms.HssSignature.deserialize(sigbuffer)
        self.assertTrue(sig.prettyPrint())
        self.assertTrue(pub.verify(msg, sigbuffer))
        self.assertFalse(pub.verify(msg, mangle(sigbuffer)))
        self.assertFalse(pub.verify(msg[1:], sigbuffer))

    def testVerifyRFC8554Example(self):
        msg = fromHex('54686520706f77657273206e6f742064656c656761' + \
         '74656420746f2074686520556e69746564205374617465732062792074686520' + \
         '436f6e737469747574696f6e2c206e6f722070726f6869626974656420627920' + \
         '697420746f20746865205374617465732c206172652072657365727665642074' + \
         '6f207468652053746174657320726573706563746976656c792c206f7220746f' + \
         '207468652070656f706c652e0a')
        pubbuffer = fromHex('000000020000000500000004' + \
         '61a5d57d37f5e46bfb7520806b07a1b850650e3b31fe4a773ea29a07f09cf2ea' + \
         '30e579f0df58ef8e298da0434cb2b878')
        sigbuffer = fromHex('000000010000000500000004' + \
         'd32b56671d7eb98833c49b433c272586bc4a1c8a8970528ffa04b966f9426eb9' + \
         '965a25bfd37f196b9073f3d4a232feb69128ec45146f86292f9dff9610a7bf95' + \
         'a64c7f60f6261a62043f86c70324b7707f5b4a8a6e19c114c7be866d488778a0' + \
         'e05fd5c6509a6e61d559cf1a77a970de927d60c70d3de31a7fa0100994e162a2' + \
         '582e8ff1b10cd99d4e8e413ef469559f7d7ed12c838342f9b9c96b83a4943d16' + \
         '81d84b15357ff48ca579f19f5e71f18466f2bbef4bf660c2518eb20de2f66e3b' + \
         '14784269d7d876f5d35d3fbfc7039a462c716bb9f6891a7f41ad133e9e1f6d95' + \
         '60b960e7777c52f060492f2d7c660e1471e07e72655562035abc9a701b473ecb' + \
         'c3943c6b9c4f2405a3cb8bf8a691ca51d3f6ad2f428bab6f3a30f55dd9625563' + \
         'f0a75ee390e385e3ae0b906961ecf41ae073a0590c2eb6204f44831c26dd768c' + \
         '35b167b28ce8dc988a3748255230cef99ebf14e730632f27414489808afab1d1' + \
         'e783ed04516de012498682212b07810579b250365941bcc98142da13609e9768' + \
         'aaf65de7620dabec29eb82a17fde35af15ad238c73f81bdb8dec2fc0e7f93270' + \
         '1099762b37f43c4a3c20010a3d72e2f606be108d310e639f09ce7286800d9ef8' + \
         'a1a40281cc5a7ea98d2adc7c7400c2fe5a101552df4e3cccfd0cbf2ddf5dc677' + \
         '9cbbc68fee0c3efe4ec22b83a2caa3e48e0809a0a750b73ccdcf3c79e6580c15' + \
         '4f8a58f7f24335eec5c5eb5e0cf01dcf4439424095fceb077f66ded5bec73b27' + \
         'c5b9f64a2a9af2f07c05e99e5cf80f00252e39db32f6c19674f190c9fbc506d8' + \
         '26857713afd2ca6bb85cd8c107347552f30575a5417816ab4db3f603f2df56fb' + \
         'c413e7d0acd8bdd81352b2471fc1bc4f1ef296fea1220403466b1afe78b94f7e' + \
         'cf7cc62fb92be14f18c2192384ebceaf8801afdf947f698ce9c6ceb696ed70e9' + \
         'e87b0144417e8d7baf25eb5f70f09f016fc925b4db048ab8d8cb2a661ce3b57a' + \
         'da67571f5dd546fc22cb1f97e0ebd1a65926b1234fd04f171cf469c76b884cf3' + \
         '115cce6f792cc84e36da58960c5f1d760f32c12faef477e94c92eb75625b6a37' + \
         '1efc72d60ca5e908b3a7dd69fef0249150e3eebdfed39cbdc3ce9704882a2072' + \
         'c75e13527b7a581a556168783dc1e97545e31865ddc46b3c957835da252bb732' + \
         '8d3ee2062445dfb85ef8c35f8e1f3371af34023cef626e0af1e0bc017351aae2' + \
         'ab8f5c612ead0b729a1d059d02bfe18efa971b7300e882360a93b025ff97e9e0' + \
         'eec0f3f3f13039a17f88b0cf808f488431606cb13f9241f40f44e537d302c64a' + \
         '4f1f4ab949b9feefadcb71ab50ef27d6d6ca8510f150c85fb525bf25703df720' + \
         '9b6066f09c37280d59128d2f0f637c7d7d7fad4ed1c1ea04e628d221e3d8db77' + \
         'b7c878c9411cafc5071a34a00f4cf07738912753dfce48f07576f0d4f94f42c6' + \
         'd76f7ce973e9367095ba7e9a3649b7f461d9f9ac1332a4d1044c96aefee67676' + \
         '401b64457c54d65fef6500c59cdfb69af7b6dddfcb0f086278dd8ad0686078df' + \
         'b0f3f79cd893d314168648499898fbc0ced5f95b74e8ff14d735cdea968bee74' + \
         '00000005d8b8112f9200a5e50c4a262165bd342cd800b8496810bc716277435a' + \
         'c376728d129ac6eda839a6f357b5a04387c5ce97382a78f2a4372917eefcbf93' + \
         'f63bb59112f5dbe400bd49e4501e859f885bf0736e90a509b30a26bfac8c17b5' + \
         '991c157eb5971115aa39efd8d564a6b90282c3168af2d30ef89d51bf14654510' + \
         'a12b8a144cca1848cf7da59cc2b3d9d0692dd2a20ba3863480e25b1b85ee860c' + \
         '62bf51360000000500000004d2f14ff6346af964569f7d6cb880a1b66c500491' + \
         '7da6eafe4d9ef6c6407b3db0e5485b122d9ebe15cda93cfec582d7ab0000000a' + \
         '000000040703c491e7558b35011ece3592eaa5da4d918786771233e8353bc4f6' + \
         '2323185c95cae05b899e35dffd717054706209988ebfdf6e37960bb5c38d7657' + \
         'e8bffeef9bc042da4b4525650485c66d0ce19b317587c6ba4bffcc428e25d089' + \
         '31e72dfb6a120c5612344258b85efdb7db1db9e1865a73caf96557eb39ed3e3f' + \
         '426933ac9eeddb03a1d2374af7bf77185577456237f9de2d60113c23f846df26' + \
         'fa942008a698994c0827d90e86d43e0df7f4bfcdb09b86a373b98288b7094ad8' + \
         '1a0185ac100e4f2c5fc38c003c1ab6fea479eb2f5ebe48f584d7159b8ada0358' + \
         '6e65ad9c969f6aecbfe44cf356888a7b15a3ff074f771760b26f9c04884ee1fa' + \
         'a329fbf4e61af23aee7fa5d4d9a5dfcf43c4c26ce8aea2ce8a2990d7ba7b5710' + \
         '8b47dabfbeadb2b25b3cacc1ac0cef346cbb90fb044beee4fac2603a442bdf7e' + \
         '507243b7319c9944b1586e899d431c7f91bcccc8690dbf59b28386b2315f3d36' + \
         'ef2eaa3cf30b2b51f48b71b003dfb08249484201043f65f5a3ef6bbd61ddfee8' + \
         '1aca9ce60081262a00000480dcbc9a3da6fbef5c1c0a55e48a0e729f9184fcb1' + \
         '407c31529db268f6fe50032a363c9801306837fafabdf957fd97eafc80dbd165' + \
         'e435d0e2dfd836a28b354023924b6fb7e48bc0b3ed95eea64c2d402f4d734c8d' + \
         'c26f3ac591825daef01eae3c38e3328d00a77dc657034f287ccb0f0e1c9a7cbd' + \
         'c828f627205e4737b84b58376551d44c12c3c215c812a0970789c83de51d6ad7' + \
         '87271963327f0a5fbb6b5907dec02c9a90934af5a1c63b72c82653605d1dcce5' + \
         '1596b3c2b45696689f2eb382007497557692caac4d57b5de9f5569bc2ad0137f' + \
         'd47fb47e664fcb6db4971f5b3e07aceda9ac130e9f38182de994cff192ec0e82' + \
         'fd6d4cb7f3fe00812589b7a7ce515440456433016b84a59bec6619a1c6c0b37d' + \
         'd1450ed4f2d8b584410ceda8025f5d2d8dd0d2176fc1cf2cc06fa8c82bed4d94' + \
         '4e71339ece780fd025bd41ec34ebff9d4270a3224e019fcb444474d482fd2dbe' + \
         '75efb20389cc10cd600abb54c47ede93e08c114edb04117d714dc1d525e11bed' + \
         '8756192f929d15462b939ff3f52f2252da2ed64d8fae88818b1efa2c7b08c879' + \
         '4fb1b214aa233db3162833141ea4383f1a6f120be1db82ce3630b34291144631' + \
         '57a64e91234d475e2f79cbf05e4db6a9407d72c6bff7d1198b5c4d6aad2831db' + \
         '61274993715a0182c7dc8089e32c8531deed4f7431c07c02195eba2ef91efb56' + \
         '13c37af7ae0c066babc69369700e1dd26eddc0d216c781d56e4ce47e3303fa73' + \
         '007ff7b949ef23be2aa4dbf25206fe45c20dd888395b2526391a724996a44156' + \
         'beac808212858792bf8e74cba49dee5e8812e019da87454bff9e847ed83db07a' + \
         'f313743082f880a278f682c2bd0ad6887cb59f652e155987d61bbf6a88d36ee9' + \
         '3b6072e6656d9ccbaae3d655852e38deb3a2dcf8058dc9fb6f2ab3d3b3539eb7' + \
         '7b248a661091d05eb6e2f297774fe6053598457cc61908318de4b826f0fc86d4' + \
         'bb117d33e865aa805009cc2918d9c2f840c4da43a703ad9f5b5806163d716169' + \
         '6b5a0adc00000005d5c0d1bebb06048ed6fe2ef2c6cef305b3ed633941ebc8b3' + \
         'bec9738754cddd60e1920ada52f43d055b5031cee6192520d6a5115514851ce7' + \
         'fd448d4a39fae2ab2335b525f484e9b40d6a4a969394843bdcf6d14c48e8015e' + \
         '08ab92662c05c6e9f90b65a7a6201689999f32bfd368e5e3ec9cb70ac7b83990' + \
         '03f175c40885081a09ab3034911fe125631051df0408b3946b0bde790911e897' + \
         '8ba07dd56c73e7ee')
        pub = pyhsslms.HssPublicKey.deserialize(pubbuffer)
        self.assertTrue(pub.prettyPrint())
        sig = pyhsslms.HssSignature.deserialize(sigbuffer)
        self.assertTrue(sig.prettyPrint())
        self.assertTrue(pub.verify(msg, sigbuffer))
        self.assertFalse(pub.verify(msg, mangle(sigbuffer)))
        self.assertFalse(pub.verify(mangle(msg), sigbuffer))

class TestNewParamSets2021(unittest.TestCase):

    def testVerifySHA256192(self):
        msg = fromHex('54657374206d657361676520666f72205348413235362f3139320a')
        pubbuffer = fromHex('000000010000000a00000008' + \
         '202122232425262728292a2b2c2d2e2f2c571450aed99cfb' + \
         '4f4ac285da14882796618314508b12d2')
        sigbuffer = fromHex('000000000000000500000008' + \
         '0b5040a18c1b5cabcbc85b047402ec6294a30dd8da8fc3da' + \
         'dcc7fa8c8d2d2a8cb41b4fb080443d82302d75edf5e1ab2a' + \
         '6dfc604ac2510910dd8e289eb0b43986f44f72156c6f5829' + \
         '25a6220a0b38dc3e518afe5b1b9b2525e25364c02cea0298' + \
         '1a1136b7c7263f5c64babe117bf808e45299716d291b9cd7' + \
         '134667b731876d2b36170f4b4bf1dae8d68d46da97b4e68b' + \
         'd17d25948a09526225e1a40a55212facd8e9ddbef3efe9a0' + \
         '13f4edcb07e401ba4fd42625b573e2b15515769e6fc3511d' + \
         'ffbc1e12acfb9bf0c2fac322bbfaf29246254cfd4d497213' + \
         '1e9ad5bc6fac2e2f3c3dbd92a46c6187725f518b744cb9c6' + \
         'cfea0868d59cf329d0633ba5b5ae3202f12cedf224a656c1' + \
         'b8d9ec380b05f629ae878e6265de29bc171f2b0128b1da0c' + \
         '29ba727d4ec2e2fade202fc84737a9d8d97f52fb70dde6e2' + \
         '6eaccbfb4d5f2faacd4066aa93818533587e2eccedb42e41' + \
         'c9bfa602e3e973fe08c8ee35713d8580b10102170f207ca7' + \
         'e937f14d3ae25f6f99c307bb66d2b0da88ed13130bf2b89f' + \
         '696ed00415b5437628f76d11040b061f837c4b42900aff2f' + \
         '06d19d6870145e9b1a746673de15a02c74744f42db18c194' + \
         '9dccadd828483b74251d571ddec7158559036c5cf6709df4' + \
         '420641e1a7793544e48cab9818fb615689ae83b32468093b' + \
         'f1247ed1da9ee87da408fffa366b4f2c6b55b5787ed14e8f' + \
         'e9c9626aedebd1c3f8d6a2c5a9e514f7cbf2385bbc703af3' + \
         'ecae4ad57b9de6cc58df826552bdd9d86bda1e3d845786fd' + \
         'e7bb777d2cf0fedf0c31e7aee973fe1895ff74244193761b' + \
         'd41802eece0e8d583ab0ae1729913a1ad5c4837a564075ca' + \
         'd562dc2abcc212ab163bd29a2c13dae82f5e966f29963eb2' + \
         'b85121440c1a6993ee2396eff407e50e11a98fb723b1fda7' + \
         '0000000a' + \
         'e9ca10eaa811b22ae07fb195e3590a334ea64209942fbae3' + \
         '38d19f152182c807d3c40b189d3fcbea942f44682439b191' + \
         '332d33ae0b761a2a8f984b56b2ac2fd4ab08223a69ed1f77' + \
         '19c7aa7e9eee96504b0e60c6bb5c942d695f0493eb25f80a' + \
         '5871cffd131d0e04ffe5065bc7875e82d34b40b69dd9f3c1')
        pub = pyhsslms.HssPublicKey.deserialize(pubbuffer)
        self.assertTrue(pub.prettyPrint())
        sig = pyhsslms.HssSignature.deserialize(sigbuffer)
        self.assertTrue(sig.prettyPrint())
        self.assertTrue(pub.verify(msg, sigbuffer))
        self.assertFalse(pub.verify(msg, mangle(sigbuffer)))
        self.assertFalse(pub.verify(mangle(msg, offset=10), sigbuffer))

    def testSmallRandomPrivateKeySHA256192(self):
        msg = toBytes('The way to get started is to quit talking and ' + \
                      'begin doing.')
        prv = pyhsslms.HssPrivateKey(levels=1,
                  lms_type=lms_sha256_m24_h5,
                  lmots_type=lmots_sha256_n24_w8)
        sigbuffer = prv.sign(msg)
        sig = pyhsslms.HssSignature.deserialize(sigbuffer)
        pub = prv.publicKey()
        self.assertTrue(pub.verify(msg, sigbuffer))
        self.assertFalse(pub.verify(msg, mangle(sigbuffer)))
        self.assertFalse(pub.verify(mangle(msg), sigbuffer))
        self.assertTrue(sig.prettyPrint())
        self.assertTrue(prv.prettyPrint())
        self.assertTrue(pub.prettyPrint())

    def testVerifySHAKE256192(self):
        msg = fromHex(
         '54657374206d65737361676520666f72205348414b453235362d3139320a')
        pubbuffer = fromHex('000000010000001400000010' + \
         '505152535455565758595a5b5c5d5e5fdb54a4509901051c' +\
         '01e26d9990e550347986da87924ff0b1')
        sigbuffer = fromHex('000000000000000600000010' + \
         '84219da9ce9fffb16edb94527c6d10565587db28062deac4' + \
         '208e62fc4fbe9d85deb3c6bd2c01640accb387d8a6093d68' + \
         '511234a6a1a50108091c034cb1777e02b5df466149a66969' + \
         'a498e4200c0a0c1bf5d100cdb97d2dd40efd3cada278acc5' + \
         'a570071a043956112c6deebd1eb3a7b56f5f6791515a7b5f' + \
         'fddb0ec2d9094bfbc889ea15c3c7b9bea953efb75ed648f5' + \
         '35b9acab66a2e9631e426e4e99b733caa6c55963929b77fe' + \
         'c54a7e703d8162e736875cb6a455d4a9015c7a6d8fd5fe75' + \
         'e402b47036dc3770f4a1dd0a559cb478c7fb1726005321be' + \
         '9d1ac2de94d731ee4ca79cff454c811f46d11980909f047b' + \
         '2005e84b6e15378446b1ca691efe491ea98acc9d3c0f785c' + \
         'aba5e2eb3c306811c240ba22802923827d582639304a1e97' + \
         '83ba5bc9d69d999a7db8f749770c3c04a152856dc726d806' + \
         '7921465b61b3f847b13b2635a45379e5adc6ff58a99b00e6' + \
         '0ac767f7f30175f9f7a140257e218be307954b1250c9b419' + \
         '02c4fa7c90d8a592945c66e86a76defcb84500b55598a199' + \
         '0faaa10077c74c94895731585c8f900de1a1c675bd8b0c18' + \
         '0ebe2b5eb3ef8019ece3e1ea7223eb7906a2042b6262b4aa' + \
         '25c4b8a05f205c8befeef11ceff1282508d71bc2a8cfa0a9' + \
         '9f73f3e3a74bb4b3c0d8ca2abd0e1c2c17dafe18b4ee2298' + \
         'e87bcfb1305b3c069e6d385569a4067ed547486dd1a50d6f' + \
         '4a58aab96e2fa883a9a39e1bd45541eee94efc32faa9a94b' + \
         'e66dc8538b2dab05aee5efa6b3b2efb3fd020fe789477a93' + \
         'afff9a3e636dbba864a5bffa3e28d13d49bb597d94865bde' + \
         '88c4627f206ab2b465084d6b780666e952f8710efd748bd0' + \
         'f1ae8f1035087f5028f14affcc5fffe332121ae4f87ac5f1' + \
         'eac9062608c7d87708f1723f38b23237a4edf4b49a5cd3d7' + \
         '00000014' + \
         'dd4bdc8f928fb526f6fb7cdb944a7ebaa7fb05d995b5721a' + \
         '27096a5007d82f79d063acd434a04e97f61552f7f81a9317' + \
         'b4ec7c87a5ed10c881928fc6ebce6dfce9daae9cc9dba690' + \
         '7ca9a9dd5f9f573704d5e6cf22a43b04e64c1ffc7e1c442e' + \
         'cb495ba265f465c56291a902e62a461f6dfda232457fad14')
        pub = pyhsslms.HssPublicKey.deserialize(pubbuffer)
        self.assertTrue(pub.prettyPrint())
        sig = pyhsslms.HssSignature.deserialize(sigbuffer)
        self.assertTrue(sig.prettyPrint())
        self.assertTrue(pub.verify(msg, sigbuffer))
        self.assertFalse(pub.verify(msg, mangle(sigbuffer)))
        self.assertFalse(pub.verify(mangle(msg, offset=10), sigbuffer))

    def testSmallRandomPrivateKeySHAKE256256(self):
        msg = toBytes('The way to get started is to quit talking and ' + \
                      'begin doing.')
        prv = pyhsslms.HssPrivateKey(levels=1,
                  lms_type=lms_shake_m24_h5,
                  lmots_type=lmots_shake_n24_w8)
        sigbuffer = prv.sign(msg)
        sig = pyhsslms.HssSignature.deserialize(sigbuffer)
        pub = prv.publicKey()
        self.assertTrue(pub.verify(msg, sigbuffer))
        self.assertFalse(pub.verify(msg, mangle(sigbuffer)))
        self.assertFalse(pub.verify(mangle(msg), sigbuffer))
        self.assertTrue(sig.prettyPrint())
        self.assertTrue(prv.prettyPrint())
        self.assertTrue(pub.prettyPrint())

    def testVerifySHAKE256256(self):
        msg = fromHex(
         '54657374206d657361676520666f72205348414b453235362d3235360a')
        pubbuffer = fromHex('000000010000000f0000000c' + \
         '808182838485868788898a8b8c8d8e8f9bb7faee411cae806c16a466c3191a8b' +\
         '65d0ac31932bbf0c2d07c7a4a36379fe')
        sigbuffer = fromHex('00000000000000070000000c' + \
         'b82709f0f00e83759190996233d1ee4f4ec50534473c02ffa145e8ca2874e32b' + \
         '16b228118c62b96c9c77678b33183730debaade8fe607f05c6697bc971519a34' + \
         '1d69c00129680b67e75b3bd7d8aa5c8b71f02669d177a2a0eea896dcd1660f16' + \
         '864b302ff321f9c4b8354408d06760504f768ebd4e545a9b0ac058c575078e6c' + \
         '1403160fb45450d61a9c8c81f6bd69bdfa26a16e12a265baf79e9e233eb71af6' + \
         '34ecc66dc88e10c6e0142942d4843f70a0242727bc5a2aabf7b0ec12a99090d8' + \
         'caeef21303f8ac58b9f200371dc9e41ab956e1a3efed9d4bbb38975b46c28d5f' + \
         '5b3ed19d847bd0a737177263cbc1a2262d40e80815ee149b6cce2714384c9b7f' + \
         'ceb3bbcbd25228dda8306536376f8793ecadd6020265dab9075f64c773ef97d0' + \
         '7352919995b74404cc69a6f3b469445c9286a6b2c9f6dc839be76618f053de76' + \
         '3da3571ef70f805c9cc54b8e501a98b98c70785eeb61737eced78b0e380ded4f' + \
         '769a9d422786def59700eef3278017babbe5f9063b468ae0dd61d94f9f99d5cc' + \
         '36fbec4178d2bda3ad31e1644a2bcce208d72d50a7637851aa908b94dc437612' + \
         '0d5beab0fb805e1945c41834dd6085e6db1a3aa78fcb59f62bde68236a10618c' + \
         'ff123abe64dae8dabb2e84ca705309c2ab986d4f8326ba0642272cb3904eb96f' + \
         '6f5e3bb8813997881b6a33cac0714e4b5e7a882ad87e141931f97d612b84e903' + \
         'e773139ae377f5ba19ac86198d485fca97742568f6ff758120a89bf19059b8a6' + \
         'bfe2d86b12778164436ab2659ba866767fcc435584125fb7924201ee67b535da' + \
         'f72c5cb31f5a0b1d926324c26e67d4c3836e301aa09bae8fb3f91f1622b1818c' + \
         'cf440f52ca9b5b9b99aba8a6754aae2b967c4954fa85298ad9b1e74f27a46127' + \
         'c36131c8991f0cc2ba57a15d35c91cf8bc48e8e20d625af4e85d8f9402ec44af' + \
         'bd4792b924b839332a64788a7701a30094b9ec4b9f4b648f168bf457fbb3c959' + \
         '4fa87920b645e42aa2fecc9e21e000ca7d3ff914e15c40a8bc533129a7fd3952' + \
         '9376430f355aaf96a0a13d13f2419141b3cc25843e8c90d0e551a355dd90ad77' + \
         '0ea7255214ce11238605de2f000d200104d0c3a3e35ae64ea10a3eff37ac7e95' + \
         '49217cdf52f307172e2f6c7a2a4543e14314036525b1ad53eeaddf0e24b1f369' + \
         '14ed22483f2889f61e62b6fb78f5645bdbb02c9e5bf97db7a0004e87c2a55399' + \
         'b61958786c97bd52fa199c27f6bb4d68c4907933562755bfec5d4fb52f06c289' + \
         'd6e852cf6bc773ffd4c07ee2d6cc55f57edcfbc8e8692a49ad47a121fe3c1b16' + \
         'cab1cc285faf6793ffad7a8c341a49c5d2dce7069e464cb90a00b2903648b23c' + \
         '81a68e21d748a7e7b1df8a593f3894b2477e8316947ca725d141135202a9442e' + \
         '1db33bbd390d2c04401c39b253b78ce297b0e14755e46ec08a146d279c67af70' + \
         'de256890804d83d6ec5ca3286f1fca9c72abf6ef868e7f6eb0fddda1b040ecec' + \
         '9bbc69e2fd8618e9db3bdb0af13dda06c6617e95afa522d6a2552de15324d991' + \
         '19f55e9af11ae3d5614b564c642dbfec6c644198ce80d2433ac8ee738f9d825e' + \
         '0000000f' + \
         '71d585a35c3a908379f4072d070311db5d65b242b714bc5a756ba5e228abfa0d' + \
         '1329978a05d5e815cf4d74c1e547ec4aa3ca956ae927df8b29fb9fab3917a7a4' + \
         'ae61ba57e5342e9db12caf6f6dbc5253de5268d4b0c4ce4ebe6852f012b162fc' + \
         '1c12b9ffc3bcb1d3ac8589777655e22cd9b99ff1e4346fd0efeaa1da044692e7' + \
         'ad6bfc337db69849e54411df8920c228a2b7762c11e4b1c49efb74486d3931ea')
        pub = pyhsslms.HssPublicKey.deserialize(pubbuffer)
        self.assertTrue(pub.prettyPrint())
        sig = pyhsslms.HssSignature.deserialize(sigbuffer)
        self.assertTrue(sig.prettyPrint())
        self.assertTrue(pub.verify(msg, sigbuffer))
        self.assertFalse(pub.verify(msg, mangle(sigbuffer)))
        self.assertFalse(pub.verify(mangle(msg, offset=10), sigbuffer))

    def testSmallRandomPrivateKeySHAKE256256(self):
        msg = toBytes('The way to get started is to quit talking and ' + \
                      'begin doing.')
        prv = pyhsslms.HssPrivateKey(levels=1,
                  lms_type=lms_shake_m32_h5,
                  lmots_type=lmots_shake_n32_w8)
        sigbuffer = prv.sign(msg)
        sig = pyhsslms.HssSignature.deserialize(sigbuffer)
        pub = prv.publicKey()
        self.assertTrue(pub.verify(msg, sigbuffer))
        self.assertFalse(pub.verify(msg, mangle(sigbuffer)))
        self.assertFalse(pub.verify(mangle(msg), sigbuffer))
        self.assertTrue(sig.prettyPrint())
        self.assertTrue(prv.prettyPrint())
        self.assertTrue(pub.prettyPrint())

if __name__ == '__main__':
    unittest.main()
