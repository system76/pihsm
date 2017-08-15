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

from unittest import TestCase
from base64 import b32encode
import os

from .helpers import random_u64
from  .. import display



class TestFunctions(TestCase):
    def test_mk_u64_line(self):
        self.assertEqual(display._mk_u64_line(0),
            '                   0'
        )
        self.assertEqual(display._mk_u64_line(2**64 - 1),
            '18446744073709551615'
        )
        u64 = random_u64()
        self.assertEqual(display._mk_u64_line(u64),
            str(u64).rjust(20)
        )

    def test_mk_pubkey_lines(self):
        pubkey = b'\x00' * 32
        self.assertEqual(display._mk_pubkey_lines(pubkey), (
            '    Public Key:     ',
            'AAAAAAAAAAAAAAAAAAAA',
            'AAAAAAAAAAAAAAAAAAAA',
            'AAAAAAAAAAAA====    ',
        ))
        pubkey = b'\xFF' * 32
        self.assertEqual(display._mk_pubkey_lines(pubkey), (
            '    Public Key:     ',
            '77777777777777777777',
            '77777777777777777777',
            '77777777777Q====    ',
        ))
        pubkey = os.urandom(32)
        b32 = b32encode(pubkey).decode()
        self.assertEqual(display._mk_pubkey_lines(pubkey), (
            '    Public Key:     ',
            b32[0:20],
            b32[20:40],
            b32[40:56] + '    ',
        ))

    def test_mk_signature_screens(self):
        s1 = b'\x00' * 32
        s2 = b'\xFF' * 32

        sig = s1 + s2
        self.assertEqual(display._mk_signature_screens(sig), (
            (
                '   Signature (1):   ',
                'AAAAAAAAAAAAAAAAAAAA',
                'AAAAAAAAAAAAAAAAAAAA',
                'AAAAAAAAAAAA====    ',
            ),
            (
                '   Signature (2):   ',
                '77777777777777777777',
                '77777777777777777777',
                '77777777777Q====    ',
            ),
        ))
        sig = s2 + s1
        self.assertEqual(display._mk_signature_screens(sig), (
            (
                '   Signature (1):   ',
                '77777777777777777777',
                '77777777777777777777',
                '77777777777Q====    ',
            ),
            (
                '   Signature (2):   ',
                'AAAAAAAAAAAAAAAAAAAA',
                'AAAAAAAAAAAAAAAAAAAA',
                'AAAAAAAAAAAA====    ',
            ),
        ))

        sig = os.urandom(64)
        b1 = b32encode(sig[:32]).decode()
        b2 = b32encode(sig[32:]).decode()
        self.assertEqual(display._mk_signature_screens(sig), (
            (
                '   Signature (1):   ',
                b1[0:20],
                b1[20:40],
                b1[40:] + '    ',
            ),
            (
                '   Signature (2):   ',
                b2[0:20],
                b2[20:40],
                b2[40:] + '    ',
            ),
        ))

    def test_mk_genesis_screens(self):
        s1 = b'\x00' * 32
        s2 = b'\xFF' * 32

        sig = s1 + s2
        self.assertEqual(display._mk_genesis_screens(sig), (
            (
                '    Genesis (1):    ',
                'AAAAAAAAAAAAAAAAAAAA',
                'AAAAAAAAAAAAAAAAAAAA',
                'AAAAAAAAAAAA====    ',
            ),
            (
                '    Genesis (2):    ',
                '77777777777777777777',
                '77777777777777777777',
                '77777777777Q====    ',
            ),
        ))
        sig = s2 + s1
        self.assertEqual(display._mk_genesis_screens(sig), (
            (
                '    Genesis (1):    ',
                '77777777777777777777',
                '77777777777777777777',
                '77777777777Q====    ',
            ),
            (
                '    Genesis (2):    ',
                'AAAAAAAAAAAAAAAAAAAA',
                'AAAAAAAAAAAAAAAAAAAA',
                'AAAAAAAAAAAA====    ',
            ),
        ))

        sig = os.urandom(64)
        b1 = b32encode(sig[:32]).decode()
        b2 = b32encode(sig[32:]).decode()
        self.assertEqual(display._mk_genesis_screens(sig), (
            (
                '    Genesis (1):    ',
                b1[0:20],
                b1[20:40],
                b1[40:] + '    ',
            ),
            (
                '    Genesis (2):    ',
                b2[0:20],
                b2[20:40],
                b2[40:] + '    ',
            ),
        ))

    def test_mk_screens_96(self):
        tail = os.urandom(96)
        screens = display._mk_screens_96(tail)
        self.assertIsInstance(screens, tuple)
        self.assertEqual(len(screens), 4)

    def test_mk_screens_400(self):
        tail = os.urandom(400)
        screens = display._mk_screens_400(tail)
        self.assertIsInstance(screens, tuple)
        self.assertEqual(len(screens), 4)


class MockBus:
    def __init__(self):
        self._calls = []

    def write_byte(self, addr, bits):
        self._calls.append((addr, bits))


class TestLCD(TestCase):
    def test_init(self):
        bus = MockBus()
        lcd = display.LCD(bus)
        self.assertIs(lcd.bus, bus)
        self.assertEqual(lcd.addr, 0x27)
        self.assertEqual(lcd.backlight, 0x08)
        self.assertEqual(lcd.cols, 20)
        self.assertEqual(lcd.rows, 4)
        self.assertEqual(bus._calls, [])

    def test_write_byte(self):
        bus = MockBus()
        lcd = display.LCD(bus)
        self.assertIsNone(lcd.write_byte(17))
        self.assertEqual(bus._calls, [(0x27, 17)])

    def test_lcd_toggle(self):
        bus = MockBus()
        lcd = display.LCD(bus)
        self.assertIsNone(lcd.lcd_toggle(0x38))
        self.assertEqual(bus._calls, [(39, 60), (39, 56)])
        self.assertIsNone(lcd.lcd_toggle(0x28))
        self.assertEqual(bus._calls, [(39, 60), (39, 56), (39, 44), (39, 40)])

    def test_lcd_byte(self):
        bus = MockBus()
        lcd = display.LCD(bus)
        self.assertIsNone(lcd.lcd_byte(0x33))
        self.assertEqual(bus._calls,
            [(39, 56), (39, 60), (39, 56), (39, 56), (39, 60), (39, 56)]
        )
        bus = MockBus()
        lcd = display.LCD(bus)
        self.assertIsNone(lcd.lcd_byte(76, mode=display.LCD_CHR))
        self.assertEqual(bus._calls,
            [(39, 73), (39, 77), (39, 73), (39, 201), (39, 205), (39, 201)]
        )

    def test_lcd_clear(self):
        bus = MockBus()
        lcd = display.LCD(bus)
        self.assertIsNone(lcd.lcd_clear())
        self.assertEqual(bus._calls,
            [(39, 8), (39, 12), (39, 8), (39, 24), (39, 28), (39, 24)]
        )


class MockLCD:
    def __init__(self):
        self._calls = []

    def lcd_init(self):
        self._calls.append('lcd_init')

    def lcd_screens(self, *screens):
        self._calls.append(('lcd_screens', screens))


class TestManager(TestCase):
    def test_init(self):
        lcd = MockLCD()
        manager = display.Manager(lcd)
        self.assertIs(manager.lcd, lcd)
        self.assertIsNone(manager.thread)
        self.assertEqual(manager.screens, display._mk_screens_0())

