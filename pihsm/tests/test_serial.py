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

from .helpers import iter_permutations, random_id, random_digest
from ..sign import Signer
from .. import common, serial


class MockSerialOpen:
    def __init__(self, *args, **kw):
        self._args = args
        self._kw = kw


class MockSerial:
    def __init__(self, *returns):
        self._returns = list(returns)
        self._calls = []

    def read(self, size):
        self._calls.append(('read', size))
        return self._returns.pop(0)

    def write(self, msg):
        self._calls.append(('write', msg))
        return len(msg)

    def flush(self):
        self._calls.append('flush')


class MockSerialFactory:
    def __init__(self, port, *returns):
        self._port = port
        self._returns = list(returns)
        self._calls = 0

    def __call__(self, *args, **kw):
        assert len(args) == 1
        assert type(args[0]) is str
        assert args[0] == self._port
        assert kw == {
            'baudrate': common.SERIAL_BAUDRATE,
            'timeout': common.SERIAL_TIMEOUT,
        }
        self._calls += 1
        return self._returns.pop(0)


class TestFunctions(TestCase):
    def test_open_serial(self):
        for port in ['/dev/ttyAMA0', '/dev/ttyUSB0', random_id()]:
            s = serial.open_serial(port, MockSerialOpen)
            self.assertIs(type(s), MockSerialOpen)
            self.assertEqual(s._args, (port,))
            self.assertEqual(s._kw, {
                'baudrate': common.SERIAL_BAUDRATE,
                'timeout': common.SERIAL_TIMEOUT,
            })

    def test_read_serial(self):
        for size in [224, 400]:

            # Size doesn't match (should return None):
            for d in [-1, 1]:
                msg = os.urandom(size + d)
                ttl = MockSerial(msg)
                self.assertIsNone(serial.read_serial(ttl, size))
                self.assertEqual(ttl._calls, [('read', size)])

            # Signature isn't good (should return None):
            msg = os.urandom(size)
            ttl = MockSerial(msg)
            self.assertIsNone(serial.read_serial(ttl, size))
            self.assertEqual(ttl._calls, [('read', size)])

            # Good signature:
            s = Signer()
            msg = os.urandom(size - 176)
            signed = s.sign(msg)
            self.assertEqual(len(signed), size)
            ttl = MockSerial(signed)
            self.assertEqual(serial.read_serial(ttl, size), signed)
            self.assertEqual(ttl._calls, [('read', size)])

            # Should fail on all 1-bit permutations:
            for p in iter_permutations(signed):
                ttl = MockSerial(p)
                self.assertEqual(len(p), size)
                self.assertIsNone(serial.read_serial(ttl, size))
                self.assertEqual(ttl._calls, [('read', size)])


class TestBaseSerial(TestCase):
    def test_init(self):
        port = random_id()
        base = serial.BaseSerial(port)
        self.assertIs(base.port, port)
        self.assertIsNone(base.SerialClass)
        sc = random_id()
        base = serial.BaseSerial(port, SerialClass=sc)
        self.assertIs(base.port, port)
        self.assertIs(base.SerialClass, sc)

    def test_open_serial(self):
        port = random_id()
        base = serial.BaseSerial(port, MockSerialOpen)
        self.assertIs(base.port, port)
        self.assertIs(base.SerialClass, MockSerialOpen)
        s = base.open_serial()
        self.assertIs(type(s), MockSerialOpen)
        self.assertEqual(s._args, (port,))
        self.assertEqual(s._kw, {
            'baudrate': common.SERIAL_BAUDRATE,
            'timeout': common.SERIAL_TIMEOUT,
        })


class TestSerialClient(TestCase):
    def test_make_request(self):
        s1 = Signer()
        s2 = Signer()
        request = s1.sign(random_digest())
        signed = s2.sign(request)

        port = random_id()
        ttl = MockSerial(signed)
        f = MockSerialFactory(port, ttl)
        client = serial.SerialClient(port, f)
        self.assertIs(client.make_request(request), signed)
        self.assertEqual(f._calls, 1)
        self.assertEqual(ttl._calls, [
            ('write', request),
            'flush',
            ('read', common.RESPONSE)
        ])

        for bad in iter_permutations(signed):
            ttl = MockSerial(bad, b'some junk', signed)
            f = MockSerialFactory(port, ttl)
            client = serial.SerialClient(port, f)
            self.assertIs(client.make_request(request), signed)
            self.assertEqual(f._calls, 1)
            self.assertEqual(ttl._calls, [
                ('write', request),
                'flush',
                ('read', common.RESPONSE),
                ('read', common.RESPONSE * 2),
                ('write', request),
                'flush',
                ('read', common.RESPONSE)
            ])

            ttl = MockSerial(bad, b'some junk', bad, b'stuff', signed)
            f = MockSerialFactory(port, ttl)
            client = serial.SerialClient(port, f)
            with self.assertRaises(Exception) as cm:
                client.make_request(request)
            self.assertEqual(str(cm.exception),
                'serial request failed {!r} tries'.format(common.SERIAL_RETRIES)
            )
            self.assertEqual(f._calls, 1)
            self.assertEqual(ttl._calls, [
                ('write', request),
                'flush',
                ('read', common.RESPONSE),
                ('read', common.RESPONSE * 2),
                ('write', request),
                'flush',
                ('read', common.RESPONSE),
                ('read', common.RESPONSE * 2),
            ])

