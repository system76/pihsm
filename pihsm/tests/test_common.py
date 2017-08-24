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
from base64 import b32encode

from .helpers import random_u64
from .. import common


# sha384 hexdigest of b'System76':
HEXDIGEST = \
'f504a78eb637969e8e7468e21c260ed510162808699c4e04953a29ce89b2cc6f5f28d4f71407a9df99c69ae4c398f628'


class TestNamedTuples(TestCase):
    def test_Signed(self):
        args = tuple(os.urandom(16) for i in range(6))
        t = common.Signed(*args)
        self.assertIs(type(t), common.Signed)
        self.assertIsInstance(t, tuple)
        self.assertIs(args[0], t.signature)
        self.assertIs(args[1], t.pubkey)
        self.assertIs(args[2], t.previous)
        self.assertIs(args[3], t.counter)
        self.assertIs(args[4], t.timestamp)
        self.assertIs(args[5], t.message)
        self.assertEqual(t, args)


class TestConstants(TestCase):
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
    def test_get_signature(self):
        sig = os.urandom(64)
        pub = os.urandom(32)
        msg = os.urandom(48)
        self.assertEqual(common.get_signature(sig + pub), sig)
        self.assertEqual(common.get_signature(sig + pub + msg), sig)

    def test_get_pubkey(self):
        sig = os.urandom(64)
        pub = os.urandom(32)
        msg = os.urandom(48)
        self.assertEqual(common.get_pubkey(sig + pub), pub)
        self.assertEqual(common.get_pubkey(sig + pub + msg), pub)

    def test_get_previous(self):
        prefix = os.urandom(96)
        previous = os.urandom(64)
        suffix = os.urandom(16)
        signed = b''.join([prefix, previous, suffix])
        self.assertEqual(common.get_previous(signed), previous)
        signed += os.urandom(48)
        self.assertEqual(common.get_previous(signed), previous)

    def test_get_counter(self):
        prefix = os.urandom(160)
        counter = random_u64()
        suffix = os.urandom(8)
        msg = os.urandom(48)
        signed = prefix + counter.to_bytes(8, 'little') + suffix
        self.assertEqual(common.get_counter(signed), counter)
        self.assertEqual(common.get_counter(signed + msg), counter)

    def test_get_timestamp(self):
        prefix = os.urandom(168)
        timestamp = random_u64()
        msg = os.urandom(48)
        signed = prefix + timestamp.to_bytes(8, 'little')
        self.assertEqual(common.get_timestamp(signed), timestamp)
        self.assertEqual(common.get_timestamp(signed + msg), timestamp)

    def test_get_message(self):
        for size in range(49):
            prefix = os.urandom(common.PREFIX)
            msg = os.urandom(size)
            self.assertEqual(common.get_message(prefix), b'')
            self.assertEqual(common.get_message(prefix + msg), msg)

    def test_unpack_signed(self):
        for size in range(49):
            prefix = os.urandom(common.PREFIX)
            msg = os.urandom(size)
            p = prefix + msg
            u = common.unpack_signed(p)
            self.assertIs(type(u), common.Signed)
            self.assertEqual(u.signature, common.get_signature(p))
            self.assertEqual(u.pubkey, common.get_pubkey(p))
            self.assertEqual(u.previous, common.get_previous(p))
            self.assertEqual(u.counter, common.get_counter(p))
            self.assertEqual(u.timestamp, common.get_timestamp(p))
            self.assertEqual(u.message, common.get_message(p))
            self.assertEqual(common.pack_signed(u), p)

    def test_pack_signed(self):
        for size in [0, 48]:
            signature = os.urandom(64)
            pubkey = os.urandom(32)
            previous = os.urandom(64)
            counter = random_u64()
            timestamp = random_u64()
            message = os.urandom(size)
            u = common.Signed(
                signature,
                pubkey,
                previous,
                counter,
                timestamp,
                message,
            )
            self.assertEqual(common.pack_signed(u),
                b''.join([
                    signature,
                    pubkey,
                    previous,
                    counter.to_bytes(8, 'little'),
                    timestamp.to_bytes(8, 'little'),
                    message,
                ])
            )

    def test_encode_pubkey(self):
        # Static value test:
        pk = b'\x00\xff' * 16
        self.assertEqual(len(pk), common.PUBKEY)
        self.assertEqual(common.encode_pubkey(pk),
            'AD7QB7YA74AP6AH7AD7QB7YA74AP6AH7AD7QB7YA74AP6AH7AD7Q===='
            
        )

        # Random value test:
        b = os.urandom(common.PUBKEY)
        s = common.encode_pubkey(b)
        self.assertIs(type(s), str)
        self.assertEqual(len(s), 56)
        self.assertEqual(s, b32encode(b).decode())

    def test_encode_signature(self):
        # Static value test:
        sig = (b'\x00' * 32) + (b'\xff' * 32)
        t = common.encode_signature(sig)
        self.assertIs(type(t), tuple)
        self.assertEqual(len(t), 2)
        self.assertIs(type(t[0]), str)
        self.assertEqual(len(t[0]), 56)
        self.assertIs(type(t[1]), str)
        self.assertEqual(len(t[1]), 56)
        self.assertEqual(t,
            (
                'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA====',
                '777777777777777777777777777777777777777777777777777Q====',
            )
        )
    
        # Random value test:
        b0 = os.urandom(common.SIGNATURE // 2)
        b1 = os.urandom(common.SIGNATURE // 2)
        t = common.encode_signature(b0 + b1)
        self.assertIs(type(t), tuple)
        self.assertEqual(len(t), 2)

        self.assertIs(type(t[0]), str)
        self.assertEqual(len(t[0]), 56)
        self.assertEqual(t[0], b32encode(b0).decode())

        self.assertIs(type(t[1]), str)
        self.assertEqual(len(t[1]), 56)
        self.assertEqual(t[1], b32encode(b1).decode())

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

