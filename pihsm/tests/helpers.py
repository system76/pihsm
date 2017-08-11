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


def random_u64():
    return int.from_bytes(os.urandom(8), 'little', signed=False)


def iter_permutations(data):
    for i in range(len(data)):
        orig = data[i]
        template = list(data)
        for j in range(256):
            if j != orig:
                template[i] = j
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

