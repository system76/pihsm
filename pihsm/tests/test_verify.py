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

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

from  .. import verify


def iter_permutations(data):
    for i in range(len(data)):
        orig = data[i]
        template = list(data)
        for j in range(256):
            if j != orig:
                template[i] = j
                yield bytes(template)


class TestFunctions(TestCase):
    def test_verify_signature(self):
        sk = SigningKey.generate()
        public = bytes(sk.verify_key)
        msg = os.urandom(48)
        signed = bytes(sk.sign(msg))
        self.assertIsNone(verify.verify_signature(signed, public))
        for permutation in iter_permutations(signed):
            with self.assertRaises(BadSignatureError) as cm:
                verify.verify_signature(permutation, public)
            self.assertEqual(str(cm.exception),
                'Signature was forged or corrupt'
            )

    def test_verify_and_unpack(self):
        sk = SigningKey.generate()
        previous = os.urandom(64)
        public = bytes(sk.verify_key)
        msg = os.urandom(48)
        signed = bytes(sk.sign(previous + public + msg))
        n = verify.verify_and_unpack(signed, public)
        self.assertIs(type(n), verify.Node)
        self.assertEqual(n.signature, signed[0:64])
        self.assertEqual(n.previous_signature, previous)
        self.assertEqual(n.public_key, public)
        self.assertEqual(n.public_key, verify.get_public_key(signed))
        self.assertEqual(n.message, msg)
        for permutation in iter_permutations(signed):
            with self.assertRaises(BadSignatureError) as cm:
                verify.verify_and_unpack(permutation, public)
            self.assertEqual(str(cm.exception),
                'Signature was forged or corrupt'
            )

        # Embedded public key doesn't match:
        for bad in iter_permutations(public):
            signed = bytes(sk.sign(previous + bad + msg))
            verify.verify_signature(signed, public)
            with self.assertRaises(ValueError) as cm:
                verify.verify_and_unpack(signed, public)
            self.assertEqual(str(cm.exception),
                'embebbed pubkey mismatch:\n  {}\n!=\n  {}'.format(
                    bad.hex(), public.hex()
                )
            )

