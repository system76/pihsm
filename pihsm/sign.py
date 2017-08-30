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


"""
Generic signed message format:

    signature + pubkey + message

Generic chained signed message format:

    signature + pubkey [+ previous + counter + timestamp] + message
"""

import logging
import time

from nacl.signing import SigningKey

from .common import get_signature, get_message, b32enc


log = logging.getLogger(__name__)


def get_time():
    return int(time.time())


def get_entropy_avail(filename='/proc/sys/kernel/random/entropy_avail'):
    with open(filename, 'rb', 0) as fp:
        return int(fp.read(20))


def build_signing_form(public, previous, counter, timestamp, message):
    assert type(public) is bytes and len(public) == 32
    assert type(previous) is bytes and len(previous) == 64
    assert type(counter) is int
    assert type(timestamp) is int
    assert type(message) is bytes
    return b''.join([
        public,
        previous,
        counter.to_bytes(8, 'little'),
        timestamp.to_bytes(8, 'little'),
        message,
    ])


class DummyStore:
    def write(self, signed):
        pass      


class Signer:
    __slots__ = ('key', 'public', 'genesis', 'tail', 'counter', 'store')

    def __init__(self, store=None):
        self.key = SigningKey.generate()
        self.public = bytes(self.key.verify_key)
        self.genesis = self.tail = bytes(self.key.sign(self.public))
        self.counter = 0
        self.store = (DummyStore() if store is None else store)
        self.store.write(self.genesis)
        log.info('PubKey: %s', b32enc(self.public))
        log.info('Genesis: %s', b32enc(self.previous))

    @property
    def previous(self):
        return get_signature(self.tail)

    @property
    def message(self):
        return get_message(self.tail)

    def build_signing_form(self, timestamp, message):
        return build_signing_form(
            self.public, self.previous, self.counter, timestamp, message
        )

    def sign(self, message, timestamp=None):
        if message == self.message:
            log.warning('Reusing signature %s', b32enc(self.previous))
            return self.tail
        timestamp = (get_time() if timestamp is None else timestamp)
        self.counter += 1
        signing_form = self.build_signing_form(timestamp, message)
        self.tail = bytes(self.key.sign(signing_form))
        self.store.write(self.tail)
        return self.tail

