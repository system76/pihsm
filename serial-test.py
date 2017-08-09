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


def run_client_once(s, ttl, i):
    ts = int(time.time())
    request = s.sign(ts, os.urandom(MESSAGE))
    r = 0
    while True:
        print(s.public.hex(), i, r)
        ttl.write(request)
        response = ttl.read(RESPONSE)
        if len(response) == RESPONSE and isvalid(response):
            return response
        r += 1


def run_server_once(s, ttl, i):
    r = 0
    while True:
        msg = s.read(REQUEST)
        if len(msg) == REQUEST and isvalid(msg):
            return ttl.write(s.sign(msg))  
        print(len(msg), i, r)
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
