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

import serial
import os
import time
import hashlib

from pihsm.sign import Signer
from pihsm.verify import isvalid


MESSAGE = 48
OVERHEAD = 176
REQUEST = OVERHEAD + MESSAGE
RESPONSE = OVERHEAD + REQUEST


def open_serial(port):
    return serial.Serial(port,
        baudrate=115200,
        timeout=2,
        #parity=serial.PARITY_EVEN,
    )


def get_digest(msg):
    return hashlib.md5(msg).hexdigest()


def run_client_once(s, ttl, i):
    ts = int(time.time())
    request = s.sign(ts, os.urandom(MESSAGE))
    digest = get_digest(request)
    r = 0
    while True:
        ttl.write(request)
        response = ttl.read(RESPONSE)
        if len(response) == RESPONSE and isvalid(response):
            print(digest, get_digest(response), i, r)
            return response
        print(digest, i, r)
        r += 1


def run_server_once(s, ttl, i):
    r = 0
    while True:
        request = ttl.read(REQUEST)
        if len(request) == REQUEST and isvalid(request):
            response = s.sign(int(time.time()), request)
            print(get_digest(request), get_digest(response), i, r)
            return ttl.write(response)
        print(len(request), i, r)
        r += 1


def run_client():
    s = Signer()
    ttl = open_serial('/dev/ttyUSB0')
    i = 0
    while True:
        run_client_once(s, ttl, i)
        i += 1


def run_server():
    s = Signer()
    ttl = open_serial('/dev/ttyAMA0')
    i = 0
    while True:
        run_server_once(s, ttl, i)
        i += 1


run_client()
