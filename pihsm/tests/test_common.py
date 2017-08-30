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
from os import path
import hashlib
from base64 import b32encode

from .helpers import random_u64, TempDir
from ..common import b32enc
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

    def test_SIZES(self):
        self.assertIs(type(common.SIZES), tuple)
        for item in common.SIZES:
            self.assertIs(type(item), int)
            self.assertGreaterEqual(item, common.GENESIS)
        self.assertEqual(len(common.SIZES), len(set(common.SIZES)))
        self.assertEqual(common.SIZES,
            (common.GENESIS, common.REQUEST, common.RESPONSE)
        )

    def test_MAX_SIZE(self):
        self.assertIs(type(common.MAX_SIZE), int)
        self.assertEqual(common.MAX_SIZE, max(common.SIZES))


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

    def test_b32enc(self):
        self.assertEqual(
            common.b32enc(b'\x00'),
            'AA'
        )
        self.assertEqual(
            common.b32enc(b'\x00' * 2),
            'AAAA'
        )
        self.assertEqual(
            common.b32enc(b'\x00' * 3),
            'AAAAA'
        )
        self.assertEqual(
            common.b32enc(b'\x00' * 4),
            'AAAAAAA'
        )
        self.assertEqual(
            common.b32enc(b'\x00' * 5),
            'AAAAAAAA'
        )
        for size in range(1, 65):
            data = os.urandom(size)
            b32 = b32encode(data).decode()
            string = common.b32enc(data)
            self.assertTrue(b32.startswith(string))
            self.assertNotIn('=', string)
            self.assertEqual(len(b32) % 8, 0)
            self.assertLessEqual(len(string), len(b32))
            self.assertEqual(common.b32dec(string), data)

        # Round trip pubkey, signature:
        for i in range(500):
            pub = os.urandom(common.PUBKEY)
            b32_pub = common.b32enc(pub)
            self.assertEqual(len(b32_pub), 52)
            self.assertEqual(common.b32dec(b32_pub), pub)

            sig = os.urandom(common.SIGNATURE)
            b32_sig = common.b32enc(sig)
            self.assertEqual(len(b32_sig), 103)
            self.assertEqual(common.b32dec(b32_sig), sig)

    def test_b32dec(self):
        self.assertEqual(
            common.b32dec('AA'),
            b'\x00'
        )
        self.assertEqual(
            common.b32dec('AAAA'),
            b'\x00' * 2
        )
        self.assertEqual(
            common.b32dec('AAAAA'),
            b'\x00' * 3
        )
        self.assertEqual(
            common.b32dec('AAAAAAA'),
            b'\x00' * 4
        )
        self.assertEqual(
            common.b32dec('AAAAAAAA'),
            b'\x00' * 5
        )

    def test_log_genesis(self):
        genesis = os.urandom(common.GENESIS)
        self.assertIsNone(common.log_genesis(genesis))

    def test_log_request(self):
        request = os.urandom(common.REQUEST)
        self.assertIsNone(common.log_request(request))

    def test_log_response(self):
        response = os.urandom(common.RESPONSE)
        self.assertIsNone(common.log_response(response))

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


class TestSignatureStore(TestCase):
    def test_init(self):
        tmp = TempDir()
        store = common.SignatureStore(tmp.dir)
        self.assertIs(store.basedir, tmp.dir)
        self.assertEqual(tmp.listdir(), [])

    def test_build_dirname(self):
        tmp = TempDir()
        store = common.SignatureStore(tmp.dir)
        pubkey = os.urandom(common.PUBKEY)
        self.assertEqual(store.build_dirname(pubkey),
            tmp.join(b32enc(pubkey))
        )
        self.assertEqual(tmp.listdir(), [])

    def test_build_filename(self):
        tmp = TempDir()
        store = common.SignatureStore(tmp.dir)
        pubkey = os.urandom(common.PUBKEY)
        signature = os.urandom(common.SIGNATURE)
        filename = store.build_filename(pubkey, signature)
        self.assertEqual(filename,
            tmp.join(b32enc(pubkey), b32enc(signature))
        )
        self.assertEqual(filename,
            path.join(store.build_dirname(pubkey), b32enc(signature))
        )
        self.assertEqual(tmp.listdir(), [])

    def test_read(self):
        tmp = TempDir()
        store = common.SignatureStore(tmp.dir)
        pub = os.urandom(common.PUBKEY)
        sig = os.urandom(common.SIGNATURE)
        filename = store.build_filename(pub, sig)

        # Directory does not exist:
        with self.assertRaises(FileNotFoundError) as cm:            
            store.read(pub, sig)
        self.assertEqual(str(cm.exception),
            '[Errno 2] No such file or directory: {!r}'.format(filename)
        )
        self.assertEqual(tmp.listdir(), [])

        # File does not exist:
        tmp.mkdir(b32enc(pub))
        with self.assertRaises(FileNotFoundError) as cm:            
            store.read(pub, sig)
        self.assertEqual(str(cm.exception),
            '[Errno 2] No such file or directory: {!r}'.format(filename)
        )
        self.assertEqual(tmp.listdir(), [b32enc(pub)])
        self.assertEqual(tmp.listdir(b32enc(pub)), [])

        # File exists, but remember content is not checked!
        content = os.urandom(16)
        tmp.write(content, b32enc(pub), b32enc(sig))
        self.assertEqual(store.read(pub, sig), content)
        self.assertEqual(tmp.listdir(), [b32enc(pub)])
        self.assertEqual(tmp.listdir(b32enc(pub)), [b32enc(sig)])

    def test_write(self):
        for size in common.SIZES:
            tmp = TempDir()
            store = common.SignatureStore(tmp.dir)
            pub = os.urandom(common.PUBKEY)
            sig = os.urandom(common.SIGNATURE)
            filename = tmp.join(b32enc(pub), b32enc(sig))   
            signed = sig + pub + os.urandom(size - common.GENESIS)
            self.assertIsNone(store.write(signed))
            self.assertEqual(tmp.listdir(), [b32enc(pub)])
            self.assertEqual(tmp.listdir(b32enc(pub)), [b32enc(sig)])
            self.assertEqual(store.read(pub, sig), signed)

            # Make sure file in opened in 'xb' mode:
            with self.assertRaises(FileExistsError) as cm:
                store.write(signed)
            self.assertEqual(str(cm.exception),
                '[Errno 17] File exists: {!r}'.format(filename)
            ) 
            self.assertEqual(tmp.listdir(), [b32enc(pub)])
            self.assertEqual(tmp.listdir(b32enc(pub)), [b32enc(sig)])
            self.assertEqual(store.read(pub, sig), signed)              

            # Should work if b32enc(pub) directory already exists:
            sig2 = os.urandom(common.SIGNATURE)
            signed2 = sig2 + pub + os.urandom(size - common.GENESIS)
            self.assertIsNone(store.write(signed2))
            self.assertEqual(tmp.listdir(), [b32enc(pub)])
            self.assertEqual(tmp.listdir(b32enc(pub)),
                sorted([b32enc(sig), b32enc(sig2)])
            )
            self.assertEqual(store.read(pub, sig), signed)
            self.assertEqual(store.read(pub, sig2), signed2)

