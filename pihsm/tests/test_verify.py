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
    def test_get_signature(self):
        sig = os.urandom(64)
        pub = os.urandom(32)
        msg = os.urandom(48)
        self.assertEqual(verify.get_signature(sig + pub), sig)
        self.assertEqual(verify.get_signature(sig + pub + msg), sig)

    def test_get_pubkey(self):
        sig = os.urandom(64)
        pub = os.urandom(32)
        msg = os.urandom(48)
        self.assertEqual(verify.get_pubkey(sig + pub), pub)
        self.assertEqual(verify.get_pubkey(sig + pub + msg), pub)

    def test_get_counter(self):
        prefix = os.urandom(160)
        counter = random_u64()
        suffix = os.urandom(8)
        msg = os.urandom(48)
        signed = prefix + counter.to_bytes(8, 'little') + suffix
        self.assertEqual(verify.get_counter(signed), counter)
        self.assertEqual(verify.get_counter(signed + msg), counter)

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

    def test_isvalid(self):
        sk = SigningKey.generate()
        pubkey = bytes(sk.verify_key)
        for length in [0, 1, 2]:
            msg = os.urandom(length)
            signed = bytes(sk.sign(pubkey + msg))
            self.assertIs(verify.isvalid(signed), True)
            for bad in iter_permutations(signed):
                self.assertIs(verify.isvalid(bad), False)

    def test_repack(self):
        s = Signer()
        msg = os.urandom(48)
        ts = random_u64()
        signed = s.sign(msg, ts)
        node = verify.verify_and_unpack(signed)
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

        n = verify.verify_and_unpack(signed)
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
                verify.verify_and_unpack(permutation)
            self.assertEqual(str(cm.exception),
                'Signature was forged or corrupt'
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
        for permutation in iter_permutations(pub):
            with self.assertRaises(BadSignatureError) as cm:
                verify.verify_genesis(sig, permutation)
            self.assertEqual(str(cm.exception),
                'Signature was forged or corrupt'
            )

    def test_verify_node(self):
        sk = SigningKey.generate()
        public = bytes(sk.verify_key)
        previous = os.urandom(64)
        cnt = random_u64()
        ts = random_u64()
        msg = os.urandom(48)
        signing_form = build_signing_form(public, previous, cnt, ts, msg)
        signed = bytes(sk.sign(signing_form))

        n = verify.verify_node(signed, public)
        self.assertIs(type(n), verify.Node)
        self.assertEqual(n.signature, signed[0:64])
        self.assertEqual(n.previous, previous)
        self.assertEqual(n.pubkey, public)
        self.assertEqual(n.pubkey, verify.get_pubkey(signed))
        self.assertEqual(n.counter, cnt)
        self.assertEqual(n.timestamp, ts)
        self.assertEqual(n.message, msg)
        self.assertEqual(verify.verify_node(signed, public, cnt + 1), n)

        # Embedded Public Key doesn't match:
        for bad in iter_permutations(public):
            with self.assertRaises(ValueError) as cm:
                verify.verify_node(signed, bad)
            self.assertEqual(str(cm.exception),
                'embebbed pubkey mismatch:\n  {}\n!=\n  {}'.format(
                    public.hex(), bad.hex()
                )
            )

        # Counter is too low or too high:
        for offset in [-1, 0, 2]:
            parent_cnt = cnt + offset
            with self.assertRaises(ValueError) as cm:
                verify.verify_node(signed, public, parent_cnt)
            self.assertEqual(str(cm.exception),
                'expected node.counter {}; got {}'.format(cnt, parent_cnt - 1)
            )

