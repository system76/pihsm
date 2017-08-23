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
import socket
import hashlib
import logging

from nacl.exceptions import BadSignatureError

from .helpers import random_u64, iter_permutations, TempDir
from ..sign import Signer
from .. import verify
from  .. import ipc


log = logging.getLogger(__name__)


class UserInt(int):
    pass


class MockSocket:
    def __init__(self, *returns):
        self._returns = list(returns)
        self._calls = []

    def recv(self, size):
        self._calls.append(('recv', size))
        return self._returns.pop(0)

    def recv_into(self, dst):
        self._calls.append(('recv_into', len(dst)))
        ret = self._returns.pop(0)
        if type(ret) is bytes:
            size = len(ret)
            dst[0:size] = ret
            return size
        return ret

    def send(self, src):
        self._calls.append(('send', src.tobytes()))
        return self._returns.pop(0)


class TestServer(TestCase):
    def test_init(self):
        sock = MockSocket()
        server = ipc.Server(sock, 96, 400)
        self.assertIs(server.sock, sock)
        self.assertEqual(server.sizes, (96, 400))
        self.assertEqual(server.max_size, 400)

    def test_read_request(self):
        server = ipc.Server(None, 96, 224, 400)

        # Bad request size:
        for bad in [0, 1, 95, 97, 223, 225, 399]:
            sock = MockSocket(os.urandom(bad))
            with self.assertRaises(ValueError) as cm:
                server.read_request(sock)
            self.assertEqual(str(cm.exception),
                'bad request size {!r} not in (96, 224, 400)'.format(bad)
            )

        # Bad signature:
        for size in server.sizes:
            bad = os.urandom(size)
            sock = MockSocket(bad, 0)
            with self.assertRaises(BadSignatureError) as cm:
                server.read_request(sock)
            self.assertEqual(str(cm.exception),
                'Signature was forged or corrupt',
            )

        # Good signature:
        s = Signer()
        genesis = s.genesis
        signed1 = s.sign(random_u64(), os.urandom(224))
        signed2 = s.sign(random_u64(), os.urandom(48))
        for good in [genesis, signed1, signed2]:
            self.assertIn(len(good), server.sizes)
            sock = MockSocket(good, 0)
            self.assertEqual(server.read_request(sock), good)

            # But should still fail under any permutation:
            for permutation in iter_permutations(good):
                sock = MockSocket(permutation, 0)
                with self.assertRaises(BadSignatureError) as cm:
                    server.read_request(sock)
                self.assertEqual(str(cm.exception),
                    'Signature was forged or corrupt',
                )


def _run_server(queue, filename, build_func, *build_args):
    log.error('_run_server: %r', filename)
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(filename)
        sock.listen(5)
        server = build_func(sock, *build_args)
        queue.put(None)
        server.serve_forever()
    except Exception as e:
        queue.put(e)
        raise e


def _start_server(filename, build_func, *build_args):
    import multiprocessing
    queue = multiprocessing.Queue()
    process = multiprocessing.Process(
        target=_run_server,
        args=(queue, filename, build_func) + build_args,
        daemon=True,
    )
    process.start()
    status = queue.get()
    if isinstance(status, Exception):
        process.terminate()
        process.join()
        raise status
    return process


class TempServer:
    def __init__(self, build_func, *build_args):
        self.tmpdir = TempDir()
        self.filename = self.tmpdir.join('temp.socket')
        self.process = _start_server(self.filename, build_func, *build_args)

    def __del__(self):
        self.terminate()

    def terminate(self):
        if getattr(self, 'process', None) is not None:
            self.process.terminate()
            self.process.join()


class MockDisplayManager:
    def update_screens(self, request):
        pass


def _build_display_server(sock):
    return ipc.DisplayServer(sock, MockDisplayManager())


class MockClient:
    def make_request(self, request):
        pass


def _build_private_server(sock):
    return ipc.PrivateServer(sock, MockClient(), Signer())


class TestLiveIPC(TestCase):
    def test_display_ipc(self):
        server = TempServer(_build_display_server)
        client = ipc.DisplayClient(server.filename)
        s = Signer()
        signed1 = s.sign(random_u64(), os.urandom(224))
        signed2 = s.sign(random_u64(), os.urandom(224))
        for request in [s.genesis, signed1, signed2]:
            digest = hashlib.sha384(request).digest()
            self.assertEqual(client.make_request(request), digest)

    def test_private_ipc(self):
        server = TempServer(_build_private_server)        
        client = ipc.PrivateClient(server.filename)
        s = Signer()

        a1 = s.sign(random_u64(), os.urandom(48))
        b1 = client.make_request(a1)
        self.assertIs(type(b1), bytes)
        self.assertEqual(len(b1), 400)
        self.assertEqual(b1[176:], a1)
        self.assertEqual(verify.get_counter(b1), 1)

        a2 = s.sign(random_u64(), os.urandom(48))
        b2 = client.make_request(a2)
        self.assertIs(type(b2), bytes)
        self.assertEqual(len(b2), 400)
        self.assertEqual(b2[176:], a2)
        self.assertEqual(verify.get_counter(b2), 2)

        self.assertNotEqual(b1[:176], b2[:176])
        self.assertEqual(verify.get_pubkey(b1), verify.get_pubkey(b2))

