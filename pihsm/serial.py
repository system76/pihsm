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
import time

from .common import b32enc, REQUEST, RESPONSE, log_request, log_response, get_message
from .verify import isvalid, get_pubkey


log = logging.getLogger(__name__)


def open_serial(port, SerialClass):
    return SerialClass(port,
        baudrate=57600,
        timeout=5
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
        while True:
            request = read_serial(self.ttl, REQUEST)
            if request is not None:
                response = self.handle_request(request)
                self.ttl.write(response)

    def handle_request(self, request):
        log_request(request, 'Signing Request')
        response = self.private_client.make_request(request)
        log_response(response, 'Signing Response')
        return response


class SerialClient:
    __slots__ = ('ttl')

    def __init__(self, ttl):
        self.ttl = ttl

    def make_request(self, request, retries=10):
        log_request(request, 'Signing Request')
        for i in range(retries):
            self.ttl.write(request)
            response = read_serial(self.ttl, RESPONSE)
            if response is not None:
                log_response(response, 'Signing Response')
                assert get_message(response) == request
                return response
            log.warning('Retry %d', i)
            time.sleep(7)
        assert False

