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

import os
from os import path
import tempfile
import shutil
from unittest import TestCase


def random_u64():
    return int.from_bytes(os.urandom(8), 'little', signed=False)


def iter_bit_permutations(b):
    assert type(b) is int and 0 <= b <= 255
    for i in range(8):
        p = b ^ (1 << i)
        assert p != b
        yield p


def iter_permutations(data):
    for i in range(len(data)):
        template = list(data)
        for p in iter_bit_permutations(data[i]):
            template[i] = p
            yield bytes(template)


class MockStorage:
    def __init__(self):
        self._store = {}

    def store(self, signed):
        key = signed[0:64].hex()
        assert key not in self._store
        self._store[key] = signed

    def load(self, sig):
        return self._store[sig.hex()]


class TempDir:
    def __init__(self, prefix='unittest.'):
        self.dir = tempfile.mkdtemp(prefix=prefix)

    def __del__(self):
        shutil.rmtree(self.dir)

    def join(self, *parts):
        return path.join(self.dir, *parts)

    def listdir(self, *parts):
        return sorted(os.listdir(self.join(*parts)))

    def mkdir(self, *parts):
        dirname = self.join(*parts)
        os.mkdir(dirname)
        return dirname

    def makedirs(self, *parts):
        dirname = self.join(*parts)
        os.makedirs(dirname)
        return dirname

    def touch(self, *parts):
        filename = self.join(*parts)
        open(filename, 'xb').close()
        return filename

    def write(self, content, *parts):
        filename = self.join(*parts)
        open(filename, 'xb').write(content)
        return filename

    def remove(self, *parts):
        os.remove(self.join(*parts))


class TestFunctions(TestCase):
    def test_iter_bit_permutations(self):
        self.assertEqual(list(iter_bit_permutations(0)),
            [
                0b00000001,
                0b00000010,
                0b00000100,
                0b00001000,
                0b00010000,
                0b00100000,
                0b01000000,
                0b10000000,
            ]
        )
        self.assertEqual(list(iter_bit_permutations(255)),
            [
                0b11111110,
                0b11111101,
                0b11111011,
                0b11110111,
                0b11101111,
                0b11011111,
                0b10111111,
                0b01111111,
            ]
        )

    def test_iter_permutations(self):
        for size in (1, 2, 17, 96):
            data = os.urandom(size)
            perms = tuple(iter_permutations(data))
            self.assertEqual(len(perms), size * 8)
            for p in perms:
                self.assertNotEqual(p, data)

