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

from collections import namedtuple

from nacl.signing import VerifyKey


Node = namedtuple('Node', 'signature previous_signature public_key message')


def get_public_key(signed_message):
    return signed_message[128:160]


def verify_signature(signed_message, public_key):
    VerifyKey(public_key).verify(signed_message)


def verify_and_unpack(signed_message, public_key):
    verify_signature(signed_message, public_key)
    node = Node(
        signed_message[0:64],     # signature
        signed_message[64:128],   # previous_signature
        signed_message[128:160],  # public_key
        signed_message[160:],     # message
    )
    if node.public_key != public_key:
        raise ValueError(
            'embebbed pubkey mismatch:\n  {}\n!=\n  {}'.format(
                node.public_key.hex(), public_key.hex()
            )
        )
    return node
