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

from  .. import display


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

