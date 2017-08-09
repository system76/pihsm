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

from .helpers import iter_permutations, random_u64
from ..sign import Signer, build_signing_form
from  .. import verify


class TestFunctions(TestCase):
    def test_verify_message(self):
        sk = SigningKey.generate()
        pubkey = bytes(sk.verify_key)
        for length in [0, 1, 2]:
            msg = os.urandom(length)
            signed = bytes(sk.sign(pubkey + msg))
            verify.verify_message(signed)
            for bad in iter_permutations(signed):
                with self.assertRaises(BadSignatureError) as cm:
                    verify.verify_message(bad)
                self.assertEqual(str(cm.exception),
                    'Signature was forged or corrupt'
                )

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

    def test_repack(self):
        s = Signer()
        ts = random_u64()
        msg = os.urandom(48)
        signed = s.sign(ts, msg)
        node = verify.verify_and_unpack(signed, s.public)
        self.assertEqual(verify.repack(node), signed)

    def test_verify_and_unpack(self):
        sk = SigningKey.generate()
        public = bytes(sk.verify_key)
        previous = os.urandom(64)
        cnt = random_u64()
        ts = random_u64()
        msg = os.urandom(48)
        signing_form = build_signing_form(public, previous, cnt, ts, msg)
        signed = bytes(sk.sign(signing_form))

        n = verify.verify_and_unpack(signed, public)
        self.assertIs(type(n), verify.Node)
        self.assertEqual(n.signature, signed[0:64])
        self.assertEqual(n.previous, previous)
        self.assertEqual(n.pubkey, public)
        self.assertEqual(n.pubkey, verify.get_pubkey(signed))
        self.assertEqual(n.counter, cnt)
        self.assertEqual(n.timestamp, ts)
        self.assertEqual(n.message, msg)
        for permutation in iter_permutations(signed):
            with self.assertRaises(BadSignatureError) as cm:
                verify.verify_and_unpack(permutation, public)
            self.assertEqual(str(cm.exception),
                'Signature was forged or corrupt'
            )

        # Embedded public key doesn't match:
        for bad in iter_permutations(public):
            signing_form = build_signing_form(bad, previous, cnt, ts, msg)
            signed = bytes(sk.sign(signing_form))
            verify.verify_signature(signed, public)
            with self.assertRaises(ValueError) as cm:
                verify.verify_and_unpack(signed, public)
            self.assertEqual(str(cm.exception),
                'embebbed pubkey mismatch:\n  {}\n!=\n  {}'.format(
                    bad.hex(), public.hex()
                )
            )

    def test_verify_genesis(self):
        s = Signer()
        sig = s.previous
        pub = s.public
        self.assertIsNone(verify.verify_genesis(sig, pub))
        for permutation in iter_permutations(sig):
            with self.assertRaises(BadSignatureError) as cm:
                verify.verify_genesis(permutation, pub)
            self.assertEqual(str(cm.exception),
                'Signature was forged or corrupt'
            )

