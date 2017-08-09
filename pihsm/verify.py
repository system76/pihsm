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


Node = namedtuple('Node', 'signature pubkey previous counter timestamp message')


def get_pubkey(signed):
    assert type(signed) is bytes and len(signed) >= 96
    pubkey = signed[64:96]
    assert len(pubkey) == 32
    return pubkey


def verify_message(signed):
    VerifyKey(get_pubkey(signed)).verify(signed)


def verify_signature(signed, pubkey):
    VerifyKey(pubkey).verify(signed)


def repack(node):
    signed = b''.join([
        node.signature,
        node.pubkey,
        node.previous,
        node.counter.to_bytes(8, 'little'),
        node.timestamp.to_bytes(8, 'little'),
        node.message,
    ])
    verify_signature(signed, node.pubkey)
    return signed


def verify_and_unpack(signed, pubkey):
    verify_signature(signed, pubkey)
    node = Node(
        signed[0:64],    # signature
        signed[64:96],   # pubkey
        signed[96:160],  # previous
        int.from_bytes(signed[160:168], 'little'),
        int.from_bytes(signed[168:176], 'little'),
        signed[176:],    # message
    )
    if node.pubkey != pubkey:
        raise ValueError(
            'embebbed pubkey mismatch:\n  {}\n!=\n  {}'.format(
                node.pubkey.hex(), pubkey.hex()
            )
        )
    return node


def verify_genesis(signature, pubkey):
    verify_signature(signature + pubkey, pubkey)


def verify_node(signed, pubkey, parent_counter=None):
    node = verify_and_unpack(signed, pubkey)
    if parent_counter is not None:
        if node.counter != parent_counter - 1:
            raise ValueError('expected node.counter {}, got {}'.format(
                    node.counter, parent_counter - 1)
            )


def verify_chain(tail, pubkey, callback):
    parent_counter = None
    while tail is not None:
        signed = callback(tail)
        node = verify_node(signed, pubkey, parent_counter)
        parent_counter = node.counter
        tail = (node.previous if node.counter > 0 else None)




