#!/usr/bin/env python

# setup.py
#
# For setup of the routines for HSS/LMS Hash-based Signatures as
# defined in RFC 8554.
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

import os
import sys
import unittest

classifiers = """\
Development Status :: 5 - Production/Stable
Environment :: Console
Intended Audience :: Developers
License :: OSI Approved :: MIT License
Natural Language :: English
Operating System :: OS Independent
Programming Language :: Python :: 2
Programming Language :: Python :: 2.7
Programming Language :: Python :: 3
Programming Language :: Python :: 3.5
Programming Language :: Python :: 3.6
Programming Language :: Python :: 3.7
Programming Language :: Python :: 3.8
Topic :: Security :: Cryptography
Topic :: Software Development :: Libraries :: Python Modules
"""


def howto_install_setuptools():
    print("""
    Error: You need setuptools Python package!

    It's very easy to install it, just type:

    wget https://bootstrap.pypa.io/ez_setup.py
    python ez_setup.py

    Then you can easily install the eggs in this package.""")


if sys.version_info[:2] < (2, 7):
    print("ERROR: this package requires Python 2.7 or later!")
    sys.exit(1)

try:
    from setuptools import setup, Command
    params = { 'zip_safe': True }

except ImportError:
    for arg in sys.argv:
        if 'egg' in arg:
            howto_install_setuptools()
            sys.exit(1)
    from distutils.core import setup, Command

    params = {}

params.update({
    'name': 'pyhsslms',
    'version': open(os.path.join('pyhsslms', '__init__.py')).read().split('\'')[1],
    'description': 'HSS/LMS Digital Signatures',
    'long_description': 'Pure-Python implementation of HSS/LMS Digital Signatures (RFC 8554)',
    'maintainer': 'Russ Housley',
    'author': 'Russ Housley',
    'author_email': 'housley@vigilsec.com',
    'url': 'https://github.com/russhousley/pyhsslms',
    'platforms': ['any'],
    'classifiers': [x for x in classifiers.split('\n') if x],
    'license': 'MIT',
    'packages': ['pyhsslms'],
    'python_requires': '>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*'})


class PyTest(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        suite = unittest.TestLoader().discover('tests')
        unittest.TextTestRunner(verbosity=2).run(suite)

params['cmdclass'] = {
    'test': PyTest,
    'tests': PyTest,
}

setup(**params)
