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

from .. import provision


class TestPiImager(TestCase):
    def test_init(self):
        img = '/home/user/artful-preinstalled-server-armhf+raspi2.img.xz'
        dev = '/dev/mmcblk0'
        pi = provision.PiImager(img, dev)
        self.assertIs(pi.img, img)
        self.assertIs(pi.dev, dev)
        self.assertEqual(pi.p1, '/dev/mmcblk0p1')
        self.assertEqual(pi.p2, '/dev/mmcblk0p2')
