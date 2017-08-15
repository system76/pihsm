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
from nacl.exceptions import BadSignatureError


Node = namedtuple('Node', 'signature pubkey previous counter timestamp message')


def get_signature(signed):
    assert type(signed) is bytes and len(signed) >= 96
    sig = signed[0:64]
    assert len(sig) == 64
    return sig


def get_pubkey(signed):
    assert type(signed) is bytes and len(signed) >= 96
    pubkey = signed[64:96]
    assert len(pubkey) == 32
    return pubkey


def get_counter(signed):
    assert type(signed) is bytes and len(signed) >= 176
    cnt = signed[160:168]
    assert len(cnt) == 8
    return int.from_bytes(cnt, 'little')


def verify_message(signed):
    VerifyKey(get_pubkey(signed)).verify(signed)


def isvalid(signed):
    try:
        verify_message(signed)
        return True
    except BadSignatureError:
        return False


def check_node(node):
    assert isinstance(node, Node)
    assert isinstance(node.counter, int)
    if node.counter < 1:
        raise ValueError(
            'Invalid node.counter, possible overflow: {!r}'.format(node.counter)
        )


def repack(node):
    check_node(node)
    signed = b''.join([
        node.signature,
        node.pubkey,
        node.previous,
        node.counter.to_bytes(8, 'little'),
        node.timestamp.to_bytes(8, 'little'),
        node.message,
    ])
    verify_message(signed)
    return signed


def verify_and_unpack(signed):
    verify_message(signed)
    node = Node(
        signed[0:64],                               # signature
        get_pubkey(signed),                         # pubkey
        signed[96:160],                             # previous
        int.from_bytes(signed[160:168], 'little'),  # counter
        int.from_bytes(signed[168:176], 'little'),  # timestamp
        signed[176:],                               # message
    )
    check_node(node)
    return node


def verify_genesis(signature, pubkey):
    verify_message(signature + pubkey)


def verify_node(signed, pubkey, parent_counter=None):
    node = verify_and_unpack(signed)
    if node.pubkey != pubkey:
        raise ValueError(
            'embebbed pubkey mismatch:\n  {}\n!=\n  {}'.format(
                node.pubkey.hex(), pubkey.hex()
            )
        )
    if parent_counter is not None:
        if node.counter != parent_counter - 1:
            raise ValueError('expected node.counter {}; got {}'.format(
                node.counter, parent_counter - 1)
            )
    return node


"""
What if tail is missing in storage?

Two possibilities exist:

    1.  Tail is the signature for the genesis node, and the key has not yet been
        used, which means there's no way for the genesis node (implied through
        first signing event) to have yet been communicated to any online
        storage; we can construct the content of the genesis message (the public
        key) and test whether tail is the valid signature for this implied
        content

    2.  Tail is valid for either a genesis node or a normal node, but for
        whatever reason we don't have the node stored.   This means the chain is
        broken and should not be trusted as it cannot be traversed.  This could
        have occurred easily through non-malicious events (e.g., the build
        server experiences a hardware failure immediately after the signing
        server makes a new signature).

        When the online chain is broken, we must rotate the key.  However, when
        doing so we must first inspect the offline chain stored on the signing
        server because we must narrow down the cause to either:

        A.  Valid use of the key where the block never reached any online
            storage (via the build server or publishing server), but was stored
            in offline storage (the micro SD card in the signing Pi)

        B.  Invalid use of the key, meaning either the private key was stolen
            (somehow) and used outside of the signing server, or that the
            signing server was somehow induced into making a new signature
            without modifying the block chain



Internally validate-able aspects:

    1.  Length (at least 64 + 32 bytes)

    2.  Signature using embedded public key

    3.  Valid header+message length

    4.  Valid counter (not 0, used for overflow detection)

Externally validate-able aspects:

    1.  Embedded public key matches public key (should probably check by
        re-validating signing message rather than comparing keys, as the later
        leaks timing information)

    2.  Counter is parent counter minus one

    3.  Previous signature is for a block when have in storage (online, offline,
        or both), or if counter is at 1, previous signature should be for
        genesis block (the content of which is implied based on the public key)


Things we don't validate:

    1.  Timestamps - they are assumed a best effort indication of Unix time of
        a signing event, but we don't try to enforce any monotonic ordering,
        etc.


"""

def verify_chain(tail, pubkey, callback):
    parent_counter = None
    while tail is not None:
        signed = callback(tail)
        if len(signed) == 96:
            verify_genesis(signed[0:64], pubkey)
            tail = None
        else:
            node = verify_node(signed, pubkey, parent_counter)
            tail = node.previous
            parent_counter = node.counter

