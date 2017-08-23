#!/usr/bin/python
#--------------------------------------
#    ___  ___  _ ____
#   / _ \/ _ \(_) __/__  __ __
#  / , _/ ___/ /\ \/ _ \/ // /
# /_/|_/_/  /_/___/ .__/\_, /
#                /_/   /___/
#
#  lcd_i2c.py
#  LCD test script using I2C backpack.
#  Supports 16x2 and 20x4 screens.
#
# Author : Matt Hawkins
# Date   : 20/09/2015
#
# http://www.raspberrypi-spy.co.uk/
#
# Copyright 2015 Matt Hawkins
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
#
#--------------------------------------

# System76 changes:
#   * Port to Python3, stop using ord()
#   * Rework into a class, make easier to reuse as a library
#

import time
import threading
from base64 import b32encode

from .verify import get_signature, get_pubkey, get_counter
from .sign import get_entropy_avail


LCD_LINES = (0x80, 0xC0, 0x94, 0xD4)
ENABLE = 0b00000100

E_PULSE = 0.0005
E_DELAY = 0.0005

LCD_CHR = 1 # Mode - Sending data
LCD_CMD = 0 # Mode - Sending command


class LCD:
    def __init__(self, bus, addr=0x27, backlight=0x08, cols=20, rows=4):
        self.bus = bus
        self.addr = addr
        self.backlight = backlight
        self.cols = cols
        self.rows = rows

    def write_byte(self, bits):
        self.bus.write_byte(self.addr, bits)

    def lcd_toggle(self, bits):
        time.sleep(E_DELAY)
        self.write_byte(bits | ENABLE)
        time.sleep(E_PULSE)
        self.write_byte(bits & ~ENABLE)
        time.sleep(E_DELAY)

    def lcd_byte(self, bits, mode=LCD_CMD):
        assert mode in (LCD_CMD, LCD_CHR)
        high = mode | (bits & 0xF0) | self.backlight
        low = mode | ((bits<<4) & 0xF0) | self.backlight
        self.write_byte(high)
        self.lcd_toggle(high)
        self.write_byte(low)
        self.lcd_toggle(low)

    def lcd_clear(self):
        self.lcd_byte(0x01)  # 000001 Clear display

    def lcd_init(self):
        self.lcd_byte(0x33) # 110011 Initialise
        self.lcd_byte(0x32) # 110010 Initialise
        self.lcd_byte(0x06) # 000110 Cursor move direction
        self.lcd_byte(0x0C) # 001100 Display On,Cursor Off, Blink Off 
        self.lcd_byte(0x28) # 101000 Data length, number of lines, font size
        self.lcd_clear()
        time.sleep(E_DELAY)

    def lcd_line(self, data, line=0):
        assert type(data) is bytes and len(data) == 20
        self.lcd_byte(LCD_LINES[line])
        for bits in data:
            self.lcd_byte(bits, LCD_CHR)

    def lcd_text_lines(self, *lines):
        #self.lcd_clear()
        for (i, text) in enumerate(lines):
            if callable(text):
                text = text()
            self.lcd_line(text.encode(), i)

    def lcd_screens(self, *screens):
        delay = (1 if len(screens) < 2 else 3)
        for lines in screens:
            self.lcd_text_lines(*lines)
            time.sleep(delay)


def _mk_u64_line(u64):
    assert type(u64) is int and u64 >= 0
    line = str(u64).rjust(20)
    assert len(line) == 20
    return line


def _mk_time_line():
    return _mk_u64_line(int(time.time()))


def _mk_entropy_line():
    return _mk_u64_line(get_entropy_avail())


def _mk_status_lines():
    return (
        'Unix Time:'.ljust(20),
        _mk_time_line,
        'Entropy Available:'.ljust(20),
        _mk_entropy_line,
    )


def _mk_time_and_counter_lines(counter):
    return (
        'Unix Time:'.ljust(20),
        _mk_time_line,
        'Counter:'.ljust(20),
        _mk_u64_line(counter),
    )


def _mk_pubkey_lines(pubkey):
    assert type(pubkey) is bytes and len(pubkey) == 32
    p = b32encode(pubkey).decode()
    return (
        'Public Key:'.center(20),
        p[0:20],
        p[20:40],
        p[40:56].ljust(20),
    )


def _mk_signature_lines(sig, i, template):
    assert type(sig) is bytes and len(sig) == 64
    assert type(i) is int and i in (0, 1)
    start = i * 32
    stop = start + 32
    half = sig[start:stop]
    s = b32encode(half).decode()
    return (
        template.format(i + 1).center(20),
        s[0:20],
        s[20:40],
        s[40:56].ljust(20),
    )


def _mk_signature_screens(sig, template='Tail.{:d}:'):
    assert type(sig) is bytes and len(sig) == 64
    return tuple(_mk_signature_lines(sig, i, template) for i in [0, 1])


def _mk_genesis_screens(sig):
    return _mk_signature_screens(sig, template='Genesis.{:d}:')


def _mk_screens_0():
    return (
        _mk_status_lines(),
    )


def _mk_screens_96(tail):
    assert type(tail) is bytes and len(tail) == 96
    return (
        _mk_status_lines(),
        _mk_pubkey_lines(get_pubkey(tail)),
    ) + _mk_genesis_screens(get_signature(tail))


def _mk_screens_400(tail):
    assert type(tail) is bytes and len(tail) == 400
    return (
        _mk_time_and_counter_lines(get_counter(tail)),
        _mk_pubkey_lines(get_pubkey(tail)),
    ) + _mk_signature_screens(get_signature(tail))


def tail_to_screens(tail):
    assert type(tail) is bytes
    if len(tail) == 96:
        return _mk_screens_96(tail)
    elif len(tail) == 400:
        return _mk_screens_400(tail)
    raise ValueError('bad tail length')


class Manager:
    __slots__ = ('lcd', 'thread', 'screens')

    def __init__(self, lcd):
        self.lcd = lcd
        self.thread = None
        self.screens = _mk_screens_0()
        self.lcd.lcd_init()

    def update_screens(self, tail):
        self.screens = tail_to_screens(tail)

    def start_worker_thread(self):
        assert self.thread is None
        self.thread = threading.Thread(
            target=self._worker,
            daemon=True,
        )
        self.thread.start()

    def _worker(self):
        while True:
            self.lcd.lcd_screens(*self.screens)

