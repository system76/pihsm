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

import argparse
import serial
import os
import time
import hashlib

from pihsm.sign import Signer
from pihsm.verify import isvalid, verify_and_unpack

TIMEOUT = 5
MESSAGE = 48
OVERHEAD = 176
REQUEST = OVERHEAD + MESSAGE
RESPONSE = OVERHEAD + REQUEST


def open_serial(port):
    return serial.Serial(port,
        baudrate=115200,
        timeout=TIMEOUT,
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
        time.sleep(TIMEOUT * 1.5)


def run_server_once(s, ttl, i, lcd):
    r = 0
    while True:
        request = ttl.read(REQUEST)
        if len(request) == REQUEST and isvalid(request):
            response = s.sign(int(time.time()), request)
            print(get_digest(request), get_digest(response), i, r)
            n = verify_and_unpack(response)
            lcd.status_to_lines(n.timestamp, n.counter)
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
        time.sleep(0.7)


def run_server():
    import smbus
    from pihsm.display import LCD, pub_to_lines

    bus = smbus.SMBus(1)
    lcd = LCD(bus)
    lcd.lcd_init()

    s = Signer()
    lines = pub_to_lines('Public Key:'.center(20), s.public)
    lcd.lcd_text_lines(*lines)

    ttl = open_serial('/dev/ttyAMA0')
    i = 0
    while True:
        run_server_once(s, ttl, i, lcd)
        i += 1


parser = argparse.ArgumentParser()
parser.add_argument('--client', action='store_true', default=False,
    help='Run client (instead of server)'
)
args = parser.parse_args()

if args.client:
    run_client()
else:
    run_server()

