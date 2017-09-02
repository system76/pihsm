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


import logging

from .common import (
    SERIAL_BAUDRATE,
    SERIAL_TIMEOUT,
    SERIAL_RETRIES,
    REQUEST,
    RESPONSE,
    b32enc,
    log_request_attempt,
    log_request,
    log_response,
    get_message,
    RandomExit,
)
from .verify import isvalid, get_pubkey


log = logging.getLogger(__name__)


def open_serial(port, SerialClass=None):
    if SerialClass is None:
        from serial import Serial as SerialClass
    return SerialClass(port,
        baudrate=SERIAL_BAUDRATE,
        timeout=SERIAL_TIMEOUT,
    )


def read_serial(ttl, size):
    assert type(size) is int and size > 0
    msg = ttl.read(size)
    if len(msg) == 0:
        return None
    if len(msg) != size:
        log.warning('serial read: expected %d bytes; got %d', size, len(msg))
        return None
    if isvalid(msg):
        return msg
    log.warning('bad signature from pubkey %s', b32enc(get_pubkey(msg)))
    return None


class BaseSerial:
    __slots__ = ('port', 'SerialClass')

    def __init__(self, port, SerialClass=None):
        self.port = port
        self.SerialClass = SerialClass

    def open_serial(self):
        return open_serial(self.port, self.SerialClass)


class SerialServer(BaseSerial):
    __slots__ = ('private_client', 'exit')

    def __init__(self, private_client, port, SerialClass=None, debug=False):
        super().__init__(port, SerialClass)
        self.private_client = private_client
        self.exit = RandomExit(debug=debug)

    def serve_forever(self):
        try:
            ttl = self.open_serial()
            while True:
                request = read_serial(ttl, REQUEST)
                self.exit.tempt_fate()
                if request is not None:
                    response = self.handle_request(request)
                    ttl.write(response)
                    ttl.flush()
        except:
            log.exception('Error in SerialServer:')
            raise

    def handle_request(self, request):
        log_request(request)
        response = self.private_client.make_request(request)
        log_response(response)
        return response


class SerialClient(BaseSerial):
    __slots__ = tuple()

    def make_request(self, request):
        ttl = self.open_serial()
        for i in range(SERIAL_RETRIES):
            log_request_attempt(request, i, SERIAL_RETRIES)
            ttl.write(request)
            ttl.flush()
            response = read_serial(ttl, RESPONSE)
            if response is not None:
                log_response(response)
                assert get_message(response) == request
                return response
            else:
                cruft = ttl.read(RESPONSE * 2)
                if len(cruft) > 0:
                    log.warning('%d extra bytes read from serial', len(cruft))
        raise Exception(
            'serial request failed {!r} tries'.format(SERIAL_RETRIES)
        )

