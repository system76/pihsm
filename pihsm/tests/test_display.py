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
import os

from .helpers import random_u64, MockBus
from ..common import b32enc
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
            'Public Key:'.center(20),
            'AAAAAAAAAAAAAAAAAAAA',
            'AAAAAAAAAAAAAAAAAAAA',
            'AAAAAAAAAAAA        ',
        ))
        pubkey = b'\xFF' * 32
        self.assertEqual(display._mk_pubkey_lines(pubkey), (
            'Public Key:'.center(20),
            '77777777777777777777',
            '77777777777777777777',
            '77777777777Q        ',
        ))
        pubkey = os.urandom(32)
        b32 = b32enc(pubkey)
        self.assertEqual(display._mk_pubkey_lines(pubkey), (
            'Public Key:'.center(20),
            b32[0:20],
            b32[20:40],
            b32[40:52] + (' ' * 8),
        ))

    def test_mk_signature_screens(self):
        s1 = b'\x00' * 32
        s2 = b'\xFF' * 32

        sig = s1 + s2
        self.assertEqual(display._mk_signature_screens(sig), (
            (
                'Tail.0:'.center(20),
                'AAAAAAAAAAAAAAAAAAAA',
                'AAAAAAAAAAAAAAAAAAAA',
                'AAAAAAAAAAAP77777777',
            ),
            (
                'Tail.1:'.center(20),
                '77777777777777777777',
                '77777777777777777777',
                '77Y                 ',
            ),
        ))
        sig = s2 + s1
        self.assertEqual(display._mk_signature_screens(sig), (
            (
                'Tail.0:'.center(20),
                '77777777777777777777',
                '77777777777777777777',
                '77777777777QAAAAAAAA',
            ),
            (
                'Tail.1:'.center(20),
                'AAAAAAAAAAAAAAAAAAAA',
                'AAAAAAAAAAAAAAAAAAAA',
                'AAA                 ',
            ),
        ))

        sig = os.urandom(64)
        s =  b32enc(sig)
        self.assertEqual(display._mk_signature_screens(sig), (
            (
                'Tail.0:'.center(20),
                s[0:20],
                s[20:40],
                s[40:60],
            ),
            (
                'Tail.1:'.center(20),
                s[60:80],
                s[80:100],
                s[100:103] + (' ' * 17),
            ),
        ))

    def test_mk_genesis_screens(self):
        s1 = b'\x00' * 32
        s2 = b'\xFF' * 32

        sig = s1 + s2
        self.assertEqual(display._mk_genesis_screens(sig), (
            (
                'Genesis.0:'.center(20),
                'AAAAAAAAAAAAAAAAAAAA',
                'AAAAAAAAAAAAAAAAAAAA',
                'AAAAAAAAAAAP77777777',
            ),
            (
                'Genesis.1:'.center(20),
                '77777777777777777777',
                '77777777777777777777',
                '77Y                 ',
            ),
        ))
        sig = s2 + s1
        self.assertEqual(display._mk_genesis_screens(sig), (
            (
                'Genesis.0:'.center(20),
                '77777777777777777777',
                '77777777777777777777',
                '77777777777QAAAAAAAA',
            ),
            (
                'Genesis.1:'.center(20),
                'AAAAAAAAAAAAAAAAAAAA',
                'AAAAAAAAAAAAAAAAAAAA',
                'AAA                 ',
            ),
        ))

        sig = os.urandom(64)
        s = b32enc(sig)
        self.assertEqual(display._mk_genesis_screens(sig), (
            (
                'Genesis.0:'.center(20),
                s[0:20],
                s[20:40],
                s[40:60],
            ),
            (
                'Genesis.1:'.center(20),
                s[60:80],
                s[80:100],
                s[100:103] + (' ' * 17),
            ),
        ))

    def test_mk_status_lines(self):
        lines = display._mk_status_lines()
        self.assertIs(type(lines), tuple)
        self.assertEqual(len(lines), 4)
        self.assertEqual(lines,
            (
                'Unix Time:'.ljust(20),
                display._mk_time_line,
                'Entropy Available:'.ljust(20),
                display._mk_entropy_line,
            )
        )

    def test_mk_error_lines(self):
        lines = display._mk_error_lines()
        self.assertIs(type(lines), tuple)
        self.assertEqual(len(lines), 4)
        self.assertEqual(lines,
            (
                'ERROR!'.center(20),
                'pihsm-private crash?'.center(20),
                'Unix Time:'.ljust(20),
                display._mk_time_line,
            )
        )

    def test_mk_init_screens(self):
        screens = display._mk_init_screens()
        self.assertIs(type(screens), tuple)
        self.assertEqual(len(screens), 1)
        s0 = screens[0]
        self.assertIs(type(s0), tuple)
        self.assertEqual(len(s0), 4)
        self.assertEqual(screens,
            (display._mk_status_lines(),)
        )

    def test_mk_screens_0(self):
        screens = display._mk_screens_0()
        self.assertIs(type(screens), tuple)
        self.assertEqual(len(screens), 1)
        s0 = screens[0]
        self.assertIs(type(s0), tuple)
        self.assertEqual(len(s0), 4)
        self.assertEqual(screens,
            (display._mk_error_lines(),)
        )

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


class TestDisplayLoop(TestCase):
    def test_init(self):
        lcd = MockLCD()
        dloop = display.DisplayLoop(lcd)
        self.assertIs(dloop.lcd, lcd)
        self.assertEqual(dloop.filename, '/run/pihsm-private/tail')
        self.assertIsNone(dloop.last)
        self.assertEqual(dloop.screens, display._mk_init_screens())
        self.assertEqual(lcd._calls, [])

    def test_run_first(self):
        lcd = MockLCD()
        dloop = display.DisplayLoop(lcd)
        screens = dloop.screens
        self.assertIsNone(dloop.run_first())
        self.assertEqual(lcd._calls, [
            'lcd_init',
            ('lcd_screens', screens),
        ])
        self.assertIs(dloop.screens, screens)

    def test_play_screens(self):
        lcd = MockLCD()
        dloop = display.DisplayLoop(lcd)
        screens = dloop.screens
        self.assertIsNone(dloop.play_screens())
        self.assertEqual(lcd._calls, [
            ('lcd_screens', screens),
        ])
        self.assertIs(dloop.screens, screens)

