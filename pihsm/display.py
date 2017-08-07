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
import base64

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
        self.lcd_clear()
        for (i, text) in enumerate(lines):
            data = text.ljust(self.cols).encode()[:self.cols]
            self.lcd_line(data, i)

    def lcd_screens(self, *screens, delay=3):
        for lines in screens:
            self.lcd_text_lines(*lines)
            time.sleep(delay)


def pub_to_lines(label, pub):
    p = base64.b32encode(pub).decode()
    return (
        label.center(20),
        p[0:20],
        p[20:40],
        p[40:56],
    )


def status_to_lines(ts, cnt):
    return (
        'Current Unix Time:'.ljust(20),
        str(ts).rjust(20),
        'Block Counter:'.ljust(20),
        str(cnt).rjust(20),
    )

