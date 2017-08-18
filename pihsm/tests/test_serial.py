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

from .helpers import random_u64, iter_permutations
from ..sign import Signer
from .. import serial


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


class TestFunctions(TestCase):
    def test_open_serial(self):
        for port in ['/dev/ttyAMA0', '/dev/ttyUSB0']:
            s = serial.open_serial(port, MockSerialOpen)
            self.assertIs(type(s), MockSerialOpen)
            self.assertEqual(s._args, (port,))
            self.assertEqual(s._kw, {'baudrate': 57600, 'timeout': 5})

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
            signed = s.sign(random_u64(), msg)
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

