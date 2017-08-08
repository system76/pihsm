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


Node = namedtuple('Node', 'signature pubkey previous message')


def get_pubkey(signed_message):
    return signed_message[64:96]


def verify_signature(signed_message, pubkey):
    VerifyKey(pubkey).verify(signed_message)


def repack(node):
    signed = b''.join([
        node.signature,
        node.pubkey,
        node.previous,
        node.counter.to_bytes(8, 'little'),
        node.timestamp.to_bytes(8, 'little'),
        node.message,
    ])
    verify_signature(signed)
    return signed


def verify_and_unpack(signed_message, pubkey):
    verify_signature(signed_message, pubkey)
    node = Node(
        signed_message[0:64],    # signature
        signed_message[64:96],   # pubkey
        signed_message[96:160],  # previous
        signed_message[160:],    # message
    )
    if node.pubkey != pubkey:
        raise ValueError(
            'embebbed pubkey mismatch:\n  {}\n!=\n  {}'.format(
                node.pubkey.hex(), pubkey.hex()
            )
        )
    return node
