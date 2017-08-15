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

from nacl.signing import SigningKey


log = logging.getLogger(__name__)


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


class Signer:
    def __init__(self):
        self.key = SigningKey.generate()
        self.public = bytes(self.key.verify_key)
        self.previous = self.key.sign(self.public).signature
        self.counter = 0
        log.info('Public Key: %s', self.public.hex())
        log.info('Genesis Node: %s', self.previous.hex())

    def build_signing_form(self, timestamp, message):
        return build_signing_form(
            self.public, self.previous, self.counter, timestamp, message
        )

    def sign(self, timestamp, message):
        self.counter += 1
        sm = self.key.sign(self.build_signing_form(timestamp, message))
        self.previous = sm.signature
        log.debug('tail: %s, counter: %s', sm.signature.hex(), self.counter)
        return bytes(sm)

