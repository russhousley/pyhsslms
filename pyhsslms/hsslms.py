#!/usr/bin/env python

# hsslms.py
#
# This provides a command line interface for the pyhsslms.py
# implementation of HSS/LMS Hash-based Signatures as defined
# in RFC 8554.
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

import sys
import os.path
import argparse
import pyhsslms
from .__init__ import __version__ as VERSION


def usage(name):
    """
    Display usage information and then exit.
    """
    cmd_name = os.path.basename(name)
    print("commands:")
    print(cmd_name + " genkey <keyname> [<genparms>]")
    print("   creates <keyname>.prv and <keyname>.pub")
    print(" ")
    print(cmd_name + " sign <keyname> <filename>")
    print("   updates <keyname>.prv and makes the signature in <filename>.sig")
    print(" ")
    print(cmd_name + " verify <keyname> <filename>")
    print("   verifies the signature in <filename>.sig with <keyname>.pub")
    print(" ")
    print(cmd_name + " showprv <keyname>")
    print("   display <keyname>.prv")
    print(" ")
    print(cmd_name + " showpub <keyname>")
    print("   display <keyname>.pub")
    print(" ")
    print(cmd_name + " showsig <filename>")
    print("   display <filename>.sig")
    print(" ")
    print("optional <genparms> for the genkey command:")
    print("   -l LEVELS, --levels LEVELS")
    print("                           Number of levels in HSS heirarchy")
    print("   -s LMS_TYPE, --lms LMS_TYPE")
    print("                           Height of the LMS trees")
    print("   -w LMOTS_TYPE, --lmots LMOTS_TYPE")
    print("                           Winternitz number")
    print("   -a HASH_ALG, --alg HASH_ALG")
    print("                           Hash algorithm (sha256 or shake)")
    print("   -t TRUNC, --trunc TRUNC")
    print("                           Hash algorithm truncation size")
    print(" ")
    print("optional command arguments:")
    print("   -h, --help")
    print("                           Provides this information")
    print("   -v, --version")
    print("                           Provids the program version number")
    sys.exit(1)


def main():
    """
    Command line interface for pyhsslms.py.
    """
    cmds = ['genkey', 'keygen', 'sign', 'verify', \
            'showprv', 'showpub', 'showsig', \
            '--version', '-v', 'version', '--help', '-h', 'help']

    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        print("error: first argument must be a command")
        usage(sys.argv[0])
        sys.exit(1)

    if sys.argv[1] == 'help' or '--help' in sys.argv or '-h' in sys.argv:
        usage(sys.argv[0])
        sys.exit(1)

    if sys.argv[1] == 'version' or '--version' in sys.argv or '-v' in sys.argv:
        print(os.path.basename(sys.argv[0]) + " " + VERSION)
        sys.exit(1)

    if sys.argv[1] in ['genkey', 'keygen']:
        if len(sys.argv) < 3:
            print("error: second argument must be a keyname")
            usage(sys.argv[0])
            sys.exit(1)

        keyname = sys.argv[2]
        levels = 2
        lms_type = pyhsslms.lms_sha256_m32_h5
        lmots_type = pyhsslms.lmots_sha256_n32_w8
        if len(sys.argv) > 3:
            parser = argparse.ArgumentParser()
            parser.add_argument('-l', '--levels', dest='levels', default=2,
                type=int, choices=[1, 2, 3, 4, 5, 6, 7, 8],
                metavar='LEVELS', help='Number of levels in HSS heirarchy')
            parser.add_argument("-s", "--lms", dest='lms', default=5,
                type=int, choices=[5, 10, 15, 20, 25],
                metavar='LMS_TYPE', help='Height of the LMS trees')
            parser.add_argument('-w', '--lmots', dest='lmots', default=8,
                type=int, choices=[1, 2, 4, 8],
                metavar='LMOTS_TYPE', help='Winternitz number')
            parser.add_argument('-a', '--alg', dest='alg', default='sha256',
                type=str, choices=['sha256', 'shake'],
                metavar='HASH_ALG', help='Hash algorithm (sha256 or shake)')
            parser.add_argument('-t', '--trunc', dest='trunc', default='32',
                type=int, choices=[32, 24],
                metavar='TRUNC', help='Hash algorithm truncation size')
            args = parser.parse_args(sys.argv[3:])

            levels = args.levels
            if args.alg == 'sha256':
                if args.trunc == 32:
                     if args.lms ==  5: lms_type = pyhsslms.lms_sha256_m32_h5
                     if args.lms == 10: lms_type = pyhsslms.lms_sha256_m32_h10
                     if args.lms == 15: lms_type = pyhsslms.lms_sha256_m32_h15
                     if args.lms == 20: lms_type = pyhsslms.lms_sha256_m32_h20
                     if args.lms == 25: lms_type = pyhsslms.lms_sha256_m32_h25
                     if args.lmots == 1: lmots_type = pyhsslms.lmots_sha256_n32_w1
                     if args.lmots == 2: lmots_type = pyhsslms.lmots_sha256_n32_w2
                     if args.lmots == 4: lmots_type = pyhsslms.lmots_sha256_n32_w4
                     if args.lmots == 8: lmots_type = pyhsslms.lmots_sha256_n32_w8
                else: # args.trunc == 24
                     if args.lms ==  5: lms_type = pyhsslms.lms_sha256_m24_h5
                     if args.lms == 10: lms_type = pyhsslms.lms_sha256_m24_h10
                     if args.lms == 15: lms_type = pyhsslms.lms_sha256_m24_h15
                     if args.lms == 20: lms_type = pyhsslms.lms_sha256_m24_h20
                     if args.lms == 25: lms_type = pyhsslms.lms_sha256_m24_h25
                     if args.lmots == 1: lmots_type = pyhsslms.lmots_sha256_n24_w1
                     if args.lmots == 2: lmots_type = pyhsslms.lmots_sha256_n24_w2
                     if args.lmots == 4: lmots_type = pyhsslms.lmots_sha256_n24_w4
                     if args.lmots == 8: lmots_type = pyhsslms.lmots_sha256_n24_w8
            else: # args.alg == 'shake'
                if args.trunc == 32:
                     if args.lms ==  5: lms_type = pyhsslms.lms_shake_m32_h5
                     if args.lms == 10: lms_type = pyhsslms.lms_shake_m32_h10
                     if args.lms == 15: lms_type = pyhsslms.lms_shake_m32_h15
                     if args.lms == 20: lms_type = pyhsslms.lms_shake_m32_h20
                     if args.lms == 25: lms_type = pyhsslms.lms_shake_m32_h25
                     if args.lmots == 1: lmots_type = pyhsslms.lmots_shake_n32_w1
                     if args.lmots == 2: lmots_type = pyhsslms.lmots_shake_n32_w2
                     if args.lmots == 4: lmots_type = pyhsslms.lmots_shake_n32_w4
                     if args.lmots == 8: lmots_type = pyhsslms.lmots_shake_n32_w8
                else: # args.trunc == 24
                     if args.lms ==  5: lms_type = pyhsslms.lms_shake_m24_h5
                     if args.lms == 10: lms_type = pyhsslms.lms_shake_m24_h10
                     if args.lms == 15: lms_type = pyhsslms.lms_shake_m24_h15
                     if args.lms == 20: lms_type = pyhsslms.lms_shake_m24_h20
                     if args.lms == 25: lms_type = pyhsslms.lms_shake_m24_h25
                     if args.lmots == 1: lmots_type = pyhsslms.lmots_shake_n24_w1
                     if args.lmots == 2: lmots_type = pyhsslms.lmots_shake_n24_w2
                     if args.lmots == 4: lmots_type = pyhsslms.lmots_shake_n24_w4
                     if args.lmots == 8: lmots_type = pyhsslms.lmots_shake_n24_w8
        
        pyhsslms.HssLmsPrivateKey.genkey(keyname, levels=levels,
            lms_type=lms_type, lmots_type=lmots_type)

    if sys.argv[1] == 'sign':
        if len(sys.argv) < 3:
            print("error: second argument must be a keyname")
            usage(sys.argv[0])
            sys.exit(1)

        if len(sys.argv) < 4:
            print("error: third argument must be a file name")
            usage(sys.argv[0])
            sys.exit(1)

        keyname = sys.argv[2]
        filename = sys.argv[3]
        print("Signing " + filename + " ...")
        prv = pyhsslms.HssLmsPrivateKey(keyname)
        if prv.signFile(filename):
            print("   ... Success. Signature saved in " + filename + ".sig")
        else:
            print("   ... Failed!")

    if sys.argv[1] == 'verify':
        if len(sys.argv) < 3:
            print("error: second argument must be a keyname")
            usage(sys.argv[0])
            sys.exit(1)

        if len(sys.argv) < 4:
            print("error: third argument must be a file name")
            usage(sys.argv[0])
            sys.exit(1)

        keyname = sys.argv[2]
        filename = sys.argv[3]
        pub = pyhsslms.HssLmsPublicKey(keyname)
        if pub.verifyFile(filename):
            print("Signature in " + filename + ".sig is valid.")
        else:
            print("Signature verification failed!")
        

    if sys.argv[1] == 'showprv':
        if len(sys.argv) < 3:
            print("error: second argument must be a keyname")
            usage(sys.argv[0])
            sys.exit(1)

        keyname = sys.argv[2]
        prv = pyhsslms.HssLmsPrivateKey(keyname)
        print("Private Key: " + keyname + ".prv")
        print(prv.hss_prv.prettyPrint())

    if sys.argv[1] == 'showpub':
        if len(sys.argv) < 3:
            print("error: second argument must be a keyname")
            usage(sys.argv[0])
            sys.exit(1)

        keyname = sys.argv[2]
        pub = pyhsslms.HssLmsPublicKey(keyname)
        print("Public Key: " + keyname + ".pub")
        print(pub.hss_pub.prettyPrint())

    if sys.argv[1] == 'showsig':
        if len(sys.argv) < 3:
            print("error: second argument must be a file name")
            usage(sys.argv[0])
            sys.exit(1)

        filename = sys.argv[2]
        sig = pyhsslms.HssLmsSignature(filename)
        print("Signature: " + filename + ".sig")
        print(sig.hss_sig.prettyPrint())

if __name__ == "__main__":
    main()
