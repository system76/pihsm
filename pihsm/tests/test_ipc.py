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


class TestFunctions(TestCase):
    def test_validate_size(self):
        max_size = 76

        # Bad size type:
        for bad in [UserInt(17), 17.0]:
            with self.assertRaises(TypeError) as cm:
                ipc._validate_size(bad, max_size)
            self.assertEqual(str(cm.exception),
                'size: need a {!r}; got a {!r}'.format(int, type(bad))
            )

        # Bad size value:
        for bad in [-1, max_size + 1]:
            with self.assertRaises(ValueError) as cm:
                ipc._validate_size(bad, max_size)
            self.assertEqual(str(cm.exception),
                'need 0 <= size <= 76; got {}'.format(bad)
            )

        # Good size type/values, but at edges of value limits:
        for good in [0, max_size]:
            self.assertIs(ipc._validate_size(good, max_size), good)

        # Test with lowest max_size value:
        self.assertEqual(ipc._validate_size(0, 1), 0)
        self.assertEqual(ipc._validate_size(1, 1), 1)

    def test_recv_into_once(self):
        dst = memoryview(bytearray(400))

        sock = MockSocket(400)
        self.assertEqual(ipc._recv_into_once(sock, dst), 400)
        self.assertEqual(sock._calls, [('recv_into', 400)])

        sock = MockSocket(160)
        self.assertEqual(ipc._recv_into_once(sock, dst), 160)
        self.assertEqual(sock._calls, [('recv_into', 400)])

        # Bad size type:
        for bad in [UserInt(17), 17.0]:
            sock = MockSocket(bad)
            with self.assertRaises(TypeError) as cm:
                ipc._recv_into_once(sock, dst)
            self.assertEqual(str(cm.exception),
                'size: need a {!r}; got a {!r}'.format(int, type(bad))
            )
            self.assertEqual(sock._calls, [('recv_into', 400)])

        # Bad size value:
        for bad in [-1, len(dst) + 1]:
            sock = MockSocket(bad)
            with self.assertRaises(ValueError) as cm:
                ipc._recv_into_once(sock, dst)
            self.assertEqual(str(cm.exception),
                'need 0 <= size <= 400; got {}'.format(bad)
            )
            self.assertEqual(sock._calls, [('recv_into', 400)])

    def test_recv_into(self):
        dst = memoryview(bytearray(400))

        sock = MockSocket(400)
        self.assertEqual(ipc._recv_into(sock, dst), 400)
        self.assertEqual(sock._calls, [('recv_into', 400)])

        sock = MockSocket(160, 240)
        self.assertEqual(ipc._recv_into(sock, dst), 400)
        self.assertEqual(sock._calls, [('recv_into', 400), ('recv_into', 240)])

        sock = MockSocket(96, 0)
        self.assertEqual(ipc._recv_into(sock, dst), 96)
        self.assertEqual(sock._calls, [('recv_into', 400), ('recv_into', 304)])

        # Bad size type:
        for bad in [UserInt(17), 17.0]:
            sock = MockSocket(bad)
            with self.assertRaises(TypeError) as cm:
                ipc._recv_into(sock, dst)
            self.assertEqual(str(cm.exception),
                'size: need a {!r}; got a {!r}'.format(int, type(bad))
            )
            self.assertEqual(sock._calls, [('recv_into', 400)])

        # Bad size value:
        for bad in [-1, len(dst) + 1]:
            sock = MockSocket(bad)
            with self.assertRaises(ValueError) as cm:
                ipc._recv_into(sock, dst)
            self.assertEqual(str(cm.exception),
                'need 0 <= size <= 400; got {}'.format(bad)
            )
            self.assertEqual(sock._calls, [('recv_into', 400)])

    def test_send_once(self):
        src = os.urandom(400)
        view = memoryview(src)

        sock = MockSocket(400)
        self.assertEqual(ipc._send_once(sock, view), 400)
        self.assertEqual(sock._calls, [('send', src)])

        sock = MockSocket(160)
        self.assertEqual(ipc._send_once(sock, view), 160)
        self.assertEqual(sock._calls, [('send', src)])

        sock = MockSocket(0)
        self.assertEqual(ipc._send_once(sock, view), 0)
        self.assertEqual(sock._calls, [('send', src)])

        # Bad size type:
        for bad in [UserInt(17), 17.0]:
            sock = MockSocket(bad)
            with self.assertRaises(TypeError) as cm:
                ipc._send_once(sock, view)
            self.assertEqual(str(cm.exception),
                'size: need a {!r}; got a {!r}'.format(int, type(bad))
            )
            self.assertEqual(sock._calls, [('send', src)])

        # Bad size value:
        for bad in [-1, len(src) + 1]:
            sock = MockSocket(bad)
            with self.assertRaises(ValueError) as cm:
                ipc._send_once(sock, view)
            self.assertEqual(str(cm.exception),
                'need 0 <= size <= 400; got {}'.format(bad)
            )
            self.assertEqual(sock._calls, [('send', src)])

    def test_send(self):
        src = os.urandom(400)

        sock = MockSocket(400)
        self.assertEqual(ipc._send(sock, src), 400)
        self.assertEqual(sock._calls, [('send', src)])

        sock = MockSocket(160, 240)
        self.assertEqual(ipc._send(sock, src), 400)
        self.assertEqual(sock._calls,
            [('send', src), ('send', src[160:400])]
        )

        # Total size does not add up:
        sock = MockSocket(200, 199, 0)
        with self.assertRaises(ValueError) as cm:
            ipc._send(sock, src)
        self.assertEqual(str(cm.exception),
            'expected to send 400 bytes, but sent 399'
        )
        self.assertEqual(sock._calls,
            [('send', src), ('send', src[200:400]), ('send', src[399:400])]
        )

        # Bad size type:
        for bad in [UserInt(17), 17.0]:
            sock = MockSocket(bad)
            with self.assertRaises(TypeError) as cm:
                ipc._send(sock, src)
            self.assertEqual(str(cm.exception),
                'size: need a {!r}; got a {!r}'.format(int, type(bad))
            )
            self.assertEqual(sock._calls, [('send', src)])

        # Bad size value:
        for bad in [-1, len(src) + 1]:
            sock = MockSocket(bad)
            with self.assertRaises(ValueError) as cm:
                ipc._send(sock, src)
            self.assertEqual(str(cm.exception),
                'need 0 <= size <= 400; got {}'.format(bad)
            )
            self.assertEqual(sock._calls, [('send', src)])


class TestServer(TestCase):
    def test_init(self):
        sock = MockSocket()
        server = ipc.Server(sock, 96, 400)
        self.assertIs(server.sock, sock)
        self.assertEqual(server.sizes, (96, 400))
        self.assertIsInstance(server.dst, memoryview)

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
    return ipc.DisplayServer(MockDisplayManager(), sock)


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

