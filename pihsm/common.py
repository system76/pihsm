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
import json
import os
from os import path
from random import SystemRandom


Signed = namedtuple('Signed', 'signature pubkey previous counter timestamp message')
Config = namedtuple('Config', 'key types default')

log = logging.getLogger(__name__)
random = SystemRandom()

SERIAL_BAUDRATE = 57600
SERIAL_TIMEOUT = 2
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

MAX_CONFIG_FILE_SIZE = 4096
CONFIG_DEBUG = Config('debug', bool, False)


B32ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
B32NAMES = tuple(a + b for a in B32ALPHABET for b in B32ALPHABET)


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


def random_id():
    return b32enc(os.urandom(15))


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


def load_json(filename):
    try:
        with open(filename, 'rb', 0) as fp:
            data = fp.read(MAX_CONFIG_FILE_SIZE)
            config = json.loads(data.decode())
            if not type(config) is dict:
                raise TypeError(
                    'config: need a {!r}; got a {!r}'.format(dict, type(config))
                )
            return config
    except FileNotFoundError:
        log.warning('Not found: %r', filename)
        return {}


def merge_config(config, *schema):
    assert type(config) is dict
    for c in schema:
        assert type(c) is Config
        value = config.setdefault(c.key, c.default)
        if not isinstance(value, c.types):
            raise TypeError(
                'config[{!r}]: need a {!r}; got a {!r}'.format(
                    c.key, c.types, type(value)
                )
            )


def load_config(filename, *schema):
    obj = load_json(filename)
    merge_config(obj, *schema)
    log.info('Config: %s', json.dumps(obj, sort_keys=True, indent=4))
    return obj


def load_client_config(filename='/etc/pihsm/client.json'):
    return load_config(filename,
        Config('serial_port', str, '/dev/ttyUSB0'),
        CONFIG_DEBUG,
    )


def load_server_config(filename='/etc/pihsm/server.json'):
    return load_config(filename,
        Config('serial_port', str, '/dev/ttyAMA0'),
        CONFIG_DEBUG,
    )


def load_display_config(filename='/etc/pihsm/display.json'):
    return load_config(filename,
        Config('i2c_bus', int, 1),
        Config('i2c_address', int, 0x27),
        Config('use_hardware', bool, False),
        CONFIG_DEBUG,
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


def create_b32_subdirs(parentdir, name):
    basedir = path.join(parentdir, name)
    tmpdir = '.'.join([basedir, random_id()])
    os.mkdir(tmpdir)
    for n in B32NAMES:
        os.mkdir(path.join(tmpdir, n))
    os.rename(tmpdir, basedir)
    return basedir


class B32Store:
    def __init__(self, basedir):
        self.basedir = basedir

    def init_subdirs(self):
        create_b32_subdirs(self.basedir)

    def path(self, key):
        b32 = b32enc(key)
        return path.join(self.basedir, b32[0:2], b32[2:])


class ManifestStore(B32Store):
    pass


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


class RandomExit:
    __slots__ = ('out_of', 'count', 'debug')

    def __init__(self, out_of=1000, debug=True):
        assert type(out_of) is int and out_of > 0
        self.out_of = out_of
        self.debug = debug
        self.count = 0

    def tempt_fate(self):
        if self.debug is True:
            self.count += 1
            if random.randrange(0, self.out_of) == 0:
                status = random.randrange(0, 2)
                log.error(
                    '%d attemps, 1/%d failure probability: exiting with status %d',
                    self.count, self.out_of, status
                )
                raise SystemExit(status)

