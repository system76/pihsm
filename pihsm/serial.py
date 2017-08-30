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
    SERIAL_TIMEOUT,
    SERIAL_RETRIES,
    REQUEST,
    RESPONSE,
    b32enc,
    log_request,
    log_response,
    get_message,
)
from .verify import isvalid, get_pubkey


log = logging.getLogger(__name__)


def open_serial(port, SerialClass):
    log.info('Opening serial device %r', port)
    return SerialClass(port,
        baudrate=115200,
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


class SerialServer:
    __slots__ = ('ttl', 'private_client')

    def __init__(self, ttl, private_client):
        self.ttl = ttl
        self.private_client = private_client

    def serve_forever(self):
        try:
            while True:
                request = read_serial(self.ttl, REQUEST)
                if request is not None:
                    response = self.handle_request(request)
                    self.ttl.write(response)
        except:
            log.exception('Error in SerialServer:')
            raise

    def handle_request(self, request):
        log_request(request)
        response = self.private_client.make_request(request)
        log_response(response)
        return response


class SerialClient:
    __slots__ = ('ttl')

    def __init__(self, ttl):
        self.ttl = ttl

    def make_request(self, request):
        b32 = b32enc(request[-48:])
        for i in range(SERIAL_RETRIES):
            log_request(request,
                '--> {} {}/{}'.format(b32, i + 1, SERIAL_RETRIES)
            )

            # First drain the read buffer:
            self.ttl.read(RESPONSE)

            # Write the request, attempt to read response:
            self.ttl.write(request)
            response = read_serial(self.ttl, RESPONSE)

            if response is not None:
                log_response(response, '<-- {}'.format(b32))
                assert get_message(response) == request
                return response
        raise Exception('failed to make serial request')

