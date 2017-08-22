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
    if len(msg) != size:
        log.warning('serial read: expected %d bytes; got %d', size, len(msg))
        return None
    if isvalid(msg):
        return msg
    log.warning('bad signature from pubkey %s', get_pubkey(msg).hex())
    return None


class SerialServer:
    def __init__(self, ttl, private_client):
        self.ttl = ttl
        self.private_client = private_client

    def serve_forever(self):
        while True:
            request = read_serial(self.ttl, 224)
            if request is not None:
                response = self.private_client.make_request(request)
                self.ttl.write(response)

