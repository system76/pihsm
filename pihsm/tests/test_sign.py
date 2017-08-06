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

from  .. import sign


class TestSigner(TestCase):
    def test_init(self):
        s = sign.Signer()
        self.assertIsInstance(s.key, nacl.signing.SigningKey)
        self.assertEqual(s.public, bytes(s.key.verify_key))
        self.assertEqual(s.previous, s.key.sign(s.public).signature)

    def test_build_signing_form(self):
        s = sign.Signer()
        msg = os.urandom(48)
        self.assertEqual(s.build_signing_form(msg),
            s.previous + s.public + msg
        )

    def test_sign(self):
        s = sign.Signer()
        prev = s.previous
        pub = s.public
        msg = os.urandom(48)
        expected = bytes(s.key.sign(prev + pub + msg))
        self.assertEqual(s.sign(msg), expected)
        self.assertNotEqual(s.previous, prev)
        self.assertEqual(s.previous, expected[:64])
        self.assertEqual(s.public, pub)

