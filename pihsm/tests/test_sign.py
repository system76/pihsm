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

import nacl.signing

from .helpers import random_u64
from  .. import sign


class TestFunctions(TestCase):
    def test_bulid_signing_form(self):
        previous = os.urandom(64)
        public = os.urandom(32)
        msg = os.urandom(48)
        self.assertEqual(
            sign.build_signing_form(public, previous, 0, 0, msg),
            public + previous + (b'\x00' * 16) + msg
        )
        self.assertEqual(
            sign.build_signing_form(public, previous, 0, 0, b''),
            public + previous + (b'\x00' * 16)
        )
        cnt = os.urandom(8)
        ts = os.urandom(8)
        counter = int.from_bytes(cnt, 'little')
        timestamp = int.from_bytes(ts, 'little')
        self.assertEqual(
            sign.build_signing_form(public, previous, counter, timestamp, msg),
            public + previous + cnt + ts + msg
        )
        self.assertEqual(
            sign.build_signing_form(public, previous, counter, timestamp, b''),
            public + previous + cnt + ts
        )


class TestSigner(TestCase):
    def test_init(self):
        s = sign.Signer()
        self.assertIsInstance(s.key, nacl.signing.SigningKey)
        self.assertEqual(s.public, bytes(s.key.verify_key))
        self.assertEqual(s.previous, s.key.sign(s.public).signature)
        self.assertEqual(s.counter, 0)

    def test_build_signing_form(self):
        s = sign.Signer()
        ts = random_u64()
        msg = os.urandom(48)
        self.assertEqual(
            s.build_signing_form(ts, msg),
            sign.build_signing_form(s.public, s.previous, 0, ts, msg)
        )

    def test_sign(self):
        s = sign.Signer()
        pub = s.public

        prev = s.previous
        ts = random_u64()
        msg = os.urandom(48)
        sf = sign.build_signing_form(pub, prev, 1, ts, msg)
        expected = bytes(s.key.sign(sf))
        self.assertEqual(s.sign(ts, msg), expected)
        self.assertNotEqual(s.previous, prev)
        self.assertEqual(s.previous, expected[:64])
        self.assertEqual(s.counter, 1)
        self.assertEqual(s.public, pub)

        prev = s.previous
        ts = random_u64()
        msg = os.urandom(48)
        sf = sign.build_signing_form(pub, prev, 2, ts, msg)
        expected = bytes(s.key.sign(sf))
        self.assertEqual(s.sign(ts, msg), expected)
        self.assertNotEqual(s.previous, prev)
        self.assertEqual(s.previous, expected[:64])
        self.assertEqual(s.counter, 2)
        self.assertEqual(s.public, pub)

