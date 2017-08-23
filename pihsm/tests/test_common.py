# pihsm: Turn your Raspberry Pi into a Hardware Security Module 
# Copyright (C) 2017 System76, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from unittest import TestCase
import os
import hashlib

from .. import common


# sha384 hexdigest of b'System76':
HEXDIGEST = \
'f504a78eb637969e8e7468e21c260ed510162808699c4e04953a29ce89b2cc6f5f28d4f71407a9df99c69ae4c398f628'


class TestConstants(TestCase):
    def test_sizes(self):
        pairs = (
            ('SIGNATURE', 64),
            ('PUBKEY', 32),
            ('COUNTER', 8),
            ('TIMESTAMP', 8),
        )
        for (name, expected) in pairs:
            with self.subTest(name=name):
                value = getattr(common, name)
                self.assertIs(type(value), int)
                self.assertGreater(value, 0)
                self.assertEqual(value, expected)

    def check_size(self, name, expected):
        self.assertEqual(name, name.upper())
        self.assertIs(type(expected), int)
        self.assertGreater(expected, 0)
        value = getattr(common, name)
        self.assertIs(type(value), int)
        self.assertEqual(value, expected)

    def test_SIGNATURE(self):
        self.check_size('SIGNATURE', 64)

    def test_PUBKEY(self):
        self.check_size('PUBKEY', 32)

    def test_COUNTER(self):
        self.check_size('COUNTER', 8)

    def test_TIMESTAMP(self):
        self.check_size('TIMESTAMP', 8)

    def test_GENESIS(self):
        self.check_size('GENESIS', 96)
        self.assertEqual(common.GENESIS,
            common.SIGNATURE + common.PUBKEY
        )

    def test_PREFIX(self):
        self.check_size('PREFIX', 176)
        self.assertEqual(common.PREFIX,
            common.GENESIS + common.SIGNATURE + common.COUNTER + common.TIMESTAMP
        )

    def test_DIGEST(self):
        self.check_size('DIGEST', 48)

    def test_REQUEST(self):
        self.check_size('REQUEST', 224)
        self.assertEqual(common.REQUEST,
            common.PREFIX + common.DIGEST
        )

    def test_RESPONSE(self):
        self.check_size('RESPONSE', 400)
        self.assertEqual(common.RESPONSE,
            common.PREFIX + common.REQUEST
        )


class TestFunctions(TestCase):
    def test_compute_digest(self):
        good = b'System76'

        # Bad data type:
        bad = good.decode()
        with self.assertRaises(TypeError) as cm:
            common.compute_digest(bad)
        self.assertEqual(str(cm.exception),
            'data: need a {!r}; got a {!r}'.format(bytes, str)
        )

        # Bad data value:
        bad = b''
        with self.assertRaises(ValueError) as cm:
            common.compute_digest(bad)
        self.assertEqual(str(cm.exception), 'data: cannot provide empty bytes')

        # Good static value test:
        d = common.compute_digest(good)
        self.assertIs(type(d), bytes)
        self.assertEqual(len(d), common.DIGEST)
        self.assertEqual(d, bytes.fromhex(HEXDIGEST))
        self.assertEqual(d, hashlib.sha384(good).digest())

        # Random test values of various sizes:
        for size in [1, 2, 76]:
            good = os.urandom(size)
            self.assertEqual(common.compute_digest(good),
                hashlib.sha384(good).digest()
            )

