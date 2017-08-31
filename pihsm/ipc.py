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


import logging
import socket

from .common import (
    IPC_TIMEOUT,
    log_response,
    get_signature,
    b32enc,
)
from .verify import verify_message


log = logging.getLogger(__name__)


def open_activated_socket(fd=3):
    sock = socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM)
    log.info('opened %r', sock)
    return sock


class Server:
    __slots__ = ('sock', 'request_size')

    def __init__(self, sock, request_size):
        assert type(request_size) is int and request_size > 0
        self.sock = sock
        self.request_size = request_size

    def serve_forever(self):
        while True:
            (sock, address) = self.sock.accept()
            try:
                sock.settimeout(IPC_TIMEOUT)
                self.handle_connection(sock)
            except:
                log.exception('Error handling request:')
            finally:
                sock.close()

    def handle_connection(self, sock):
        request = sock.recv(self.request_size)
        size = len(request)
        if size != self.request_size:
            raise ValueError(
                'bad request: expected {} bytes; got {}'.format(
                    self.request_size, size
                )
            )
        response = self.handle_request(request)
        sock.send(response)

    def handle_request(self, request):
        raise NotImplementedError(
            '{}.handle_request(request)'.format(self.__class__.__name__)
        )


class PrivateServer(Server):
    __slots__ = ('display_client', 'signer')

    def __init__(self, sock, display_client, signer):
        super().__init__(sock, 224)
        self.signer = signer
        self.display_client = display_client

    def handle_request(self, request):
        verify_message(request)
        if self.signer.message == request:
            response = self.signer.tail
            log.warning('Reusing response %s', b32enc(get_signature(response)))
        else:
            response = self.signer.sign(request)
        log_response(response)
        self.display_client.make_request(response)
        return response


class ClientServer(Server):
    __slots__ = ('serial_client', 'signer')

    def __init__(self, sock, serial_client, signer):
        super().__init__(sock, 48)
        self.serial_client = serial_client
        self.signer = signer

    def handle_request(self, digest, timestamp=None):
        assert len(digest) == 48
        request = self.signer.sign(digest, timestamp)
        response = self.serial_client.make_request(request)
        verify_message(response)
        assert response.endswith(request)
        self.signer.store.write(response)
        return response


class Client:
    __slots__ = ('filename', 'response_size')

    def __init__(self, filename, response_size):
        self.filename = filename
        self.response_size = response_size

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(IPC_TIMEOUT)
        sock.connect(self.filename)
        return sock

    def _make_request(self, request):
        sock = self.connect()
        try:
            sock.send(request)
            response = sock.recv(self.response_size)
            if len(response) != self.response_size:
                raise ValueError(
                    'bad response size: expected {}; got {}'.format(
                        self.response_size, len(response)
                    )
                )
            return response
        finally:
            sock.close()


class PrivateClient(Client):
    __slots__ = tuple()

    def __init__(self, filename='/run/pihsm/private.socket'):
        super().__init__(filename, 400)

    def make_request(self, request):
        response = self._make_request(request)
        verify_message(response)
        assert response.endswith(request)
        return response


class ClientClient(Client):
    __slots__ = tuple()

    def __init__(self, filename='/run/pihsm/client.socket'):
        super().__init__(filename, 400)

    def make_request(self, request):
        response = self._make_request(request)
        verify_message(response)
        assert response.endswith(request)
        return response

