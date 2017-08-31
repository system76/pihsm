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

from collections import namedtuple
import logging
from hashlib import sha384
from base64 import b32encode, b32decode
import os
from os import path


Signed = namedtuple('Signed', 'signature pubkey previous counter timestamp message')
log = logging.getLogger(__name__)


SERIAL_TIMEOUT = 1
SERIAL_RETRIES = 3
IPC_TIMEOUT = SERIAL_TIMEOUT * SERIAL_RETRIES * 2

SIGNATURE = 64
PUBKEY = 32
COUNTER = 8
TIMESTAMP = 8

GENESIS = SIGNATURE + PUBKEY
PREFIX = GENESIS + SIGNATURE + COUNTER + TIMESTAMP

DIGEST = 48
REQUEST = PREFIX + DIGEST
RESPONSE = PREFIX + REQUEST

SIZES = (GENESIS, REQUEST, RESPONSE)
MAX_SIZE = max(SIZES)


def get_signature(signed):
    assert type(signed) is bytes and len(signed) >= GENESIS
    sig = signed[0:64]
    assert len(sig) == SIGNATURE
    return sig


def get_pubkey(signed):
    assert type(signed) is bytes and len(signed) >= GENESIS
    pubkey = signed[64:96]
    assert len(pubkey) == PUBKEY
    return pubkey


def get_previous(signed):
    assert type(signed) is bytes and len(signed) >= PREFIX
    previous = signed[96:160]
    assert len(previous) == SIGNATURE
    return previous


def get_counter(signed):
    assert type(signed) is bytes and len(signed) >= PREFIX
    counter = signed[160:168]
    assert len(counter) == COUNTER
    return int.from_bytes(counter, 'little')


def get_timestamp(signed):
    assert type(signed) is bytes and len(signed) >= PREFIX
    timestamp = signed[168:176]
    assert len(timestamp) == TIMESTAMP
    return int.from_bytes(timestamp, 'little')


def get_message(signed):
    #assert type(signed) is bytes and len(signed) >= PREFIX, signed
    return signed[PREFIX:]


def unpack_signed(d):
    return Signed(
        get_signature(d),
        get_pubkey(d),
        get_previous(d),
        get_counter(d),
        get_timestamp(d),
        get_message(d),
    )


def pack_signed(s):
    return b''.join([
        s.signature,
        s.pubkey,
        s.previous,
        s.counter.to_bytes(COUNTER, 'little'),
        s.timestamp.to_bytes(TIMESTAMP, 'little'),
        s.message,
    ])


def b32enc(data):
    return b32encode(data).decode().rstrip('=')


def b32dec(string):
    pad = (8 - (len(string) % 8)) % 8
    return b32decode(string + ('=' * pad))


LOG_SEP = '\n  '

GENESIS_TEMPLATE = LOG_SEP.join([
    '%s:',
    'Genesis.signature: %s',
    'Genesis.public: %s',
])


def log_genesis(genesis, label='Genesis'):
    sig = get_signature(genesis)
    pub = get_pubkey(genesis)
    log.info(GENESIS_TEMPLATE,
        label,
        b32enc(sig),
        b32enc(pub),
    )


REQUEST_TEMPLATE = LOG_SEP.join([
    '--> %s:',
    'Request.signature: %s',
    'Request.public: %s',
    'Request.previous: %s',
    'Request.counter: %s',
    'Request.timestamp: %s',
])


def log_request(request):
    r = unpack_signed(request)
    log.info(REQUEST_TEMPLATE,
        b32enc(r.message),
        b32enc(r.signature),
        b32enc(r.pubkey),
        b32enc(r.previous),
        r.counter,
        r.timestamp,
    )


REQUEST_ATTEMPT_TEMPLATE = LOG_SEP.join([
    '--> %s %d/%d:',
    'Request.signature: %s',
    'Request.public: %s',
    'Request.previous: %s',
    'Request.counter: %s',
    'Request.timestamp: %s',
])


def log_request_attempt(request, i, stop):
    assert 0 <= i < stop
    r = unpack_signed(request)
    method = (log.info if i == 0 else log.warning)
    method(REQUEST_ATTEMPT_TEMPLATE,
        b32enc(r.message),
        i + 1,
        stop,
        b32enc(r.signature),
        b32enc(r.pubkey),
        b32enc(r.previous),
        r.counter,
        r.timestamp,
    )


RESPONSE_TEMPLATE = LOG_SEP.join([
    '<-- %s:',
    'Signed.signature: %s',
    'Signed.public: %s',
    'Signed.previous: %s',
    'Signed.counter: %s',
    'Signed.timestamp: %s',
    'Signed.Request.signature: %s',
    'Signed.Request.public: %s',
    'Signed.Request.previous: %s',
    'Signed.Request.counter: %s',
    'Signed.Request.timestamp: %s',
])


def log_response(request):
    a = unpack_signed(request)
    b = unpack_signed(a.message)
    log.info(RESPONSE_TEMPLATE,
        b32enc(b.message),

        b32enc(a.signature),
        b32enc(a.pubkey),
        b32enc(a.previous),
        a.counter,
        a.timestamp,

        b32enc(b.signature),
        b32enc(b.pubkey),
        b32enc(b.previous),
        b.counter,
        b.timestamp,
    )


def compute_digest(data):
    if type(data) is not bytes:
        raise TypeError(
            'data: need a {!r}; got a {!r}'.format(bytes, type(data))
        )
    if len(data) < 1:
        raise ValueError(
            'data: cannot provide empty bytes'
        )
    return sha384(data).digest()


class SignatureStore:
    def __init__(self, basedir):
        self.basedir = basedir

    def build_dirname(self, pubkey):
        assert type(pubkey) is bytes and len(pubkey) == 32
        return path.join(self.basedir, b32enc(pubkey))

    def build_filename(self, pubkey, signature):
        assert type(pubkey) is bytes and len(pubkey) == 32
        assert type(signature) is bytes and len(signature) == 64
        return path.join(self.basedir, b32enc(pubkey), b32enc(signature))

    def read(self, pubkey, signature):
        filename = self.build_filename(pubkey, signature)
        with open(filename, 'rb', 0) as fp:
            return fp.read(MAX_SIZE)

    def write(self, signed):
        pubkey = get_pubkey(signed)
        dirname = self.build_dirname(pubkey)
        try:
            os.mkdir(dirname)
        except FileExistsError:
            pass
        signature = get_signature(signed)
        filename = self.build_filename(pubkey, signature)
        with open(filename, 'xb', 0) as fp:
            fp.write(signed)
            fp.flush()
            os.fsync(fp.fileno())

