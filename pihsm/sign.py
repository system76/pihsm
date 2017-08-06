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


from nacl.signing import SigningKey


class Signer:
    def __init__(self):
        self.key = SigningKey.generate()
        self.public = bytes(self.key.verify_key)
        self.previous = self.key.sign(self.public).signature

    def build_signing_form(self, message):
        return b''.join([
            self.previous,
            self.public,
            message,
        ])

    def sign(self, message):
        sm = self.key.sign(self.build_signing_form(message))
        self.previous = sm.signature
        return bytes(sm)

