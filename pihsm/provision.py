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
import os
from os import path
import tempfile
import shutil
import subprocess


from .common import atomic_write


log = logging.getLogger(__name__)


CHUNK_SIZE = 8 * 1024 * 1024

RC_LOCAL = b"""#!/bin/sh -e

# Written by PiHSM:
echo ds1307 0x68 > /sys/class/i2c-adapter/i2c-1/new_device
sleep 1
hwclock -s

sleep 2
add-apt-repository -ys ppa:jderose/pihsm
apt-get update
apt-get install -y pihsm-server
"""

CONFIG_APPEND = b"""
# Written by PiHSM:
dtoverlay=i2c-rtc,ds1307
arm_freq=600
"""

def update_cmdline(basedir):
    filename = path.join(basedir, 'boot', 'firmware', 'cmdline.txt')
    old = open(filename, 'rb', 0).read()
    parts = []
    for p in old.split():
        if p.startswith(b'console='):
            log.info('Removing from cmdline: %r', p)
        else:
            parts.append(p)
    new = b' '.join(parts) + b'\n'
    if new == old:
        log.info('Already modified: %r', filename)
    else:
        atomic_write(0o644, new, filename) 


def update_config(basedir):
    filename = path.join(basedir, 'boot', 'firmware', 'config.txt')
    config = open(filename, 'rb', 0).read()
    if config.endswith(CONFIG_APPEND):
        log.info('Already modified: %r', filename)
    else:
        atomic_write(0o644, config + CONFIG_APPEND, filename)  


def configure_image(basedir, pubkey=None):
    update_cmdline(basedir)
    update_config(basedir)
    atomic_write(0o600, os.urandom(512),
        path.join(basedir, 'var', 'lib', 'systemd', 'random-seed')
    )
    atomic_write(0o755, RC_LOCAL,
        path.join(basedir, 'etc', 'rc.local')
    )
    if pubkey:
        ssh = path.join(basedir, 'root', '.ssh')
        os.mkdir(ssh, mode=0o700)
        atomic_write(0o600, pubkey, path.join(ssh, 'authorized_keys')) 


def open_image(filename):
    return subprocess.Popen(
        ['xzcat', filename],
        bufsize=0,
        stdout=subprocess.PIPE,
    )


def iter_image(filename, size=CHUNK_SIZE):
    p = open_image(filename)
    log.info('Image: %r', filename)
    try:
        while True:
            chunk = p.stdout.read(size)
            if chunk:
                yield chunk
            else:
                break
    except:
        p.terminate()
    finally:
        p.wait()
    assert p.returncode == 0


def sync_opener(path, flags):
    return os.open(path, flags | os.O_SYNC | os.O_NOFOLLOW)


def umount(target):
    try:
        subprocess.check_call(['umount', target])
        log.info('Unmounted %r', target)
    except subprocess.CalledProcessError:
        log.debug('Not mounted: %r', target)


def open_mmc(dev):
    subprocess.check_call(['blockdev', '--rereadpt', dev])
    return open(dev, 'wb', 0, opener=sync_opener)


def write_image_to_mmc(img, dev):
    total = 0
    mmc = open_mmc(dev)
    for chunk in iter_image(img):
        total += mmc.write(chunk)
    return total


def mmc_part(dev, n):
    assert type(n) is int and n > 0
    return '{}p{:d}'.format(dev, n)


class PiImager:
    def __init__(self, img, dev):
        self.img = img
        self.dev = dev
        self.p1 = mmc_part(dev, 1)
        self.p2 = mmc_part(dev, 2)

    def write_image(self):
        umount(self.p1)
        umount(self.p2)
        return write_image_to_mmc(self.img, self.dev)

    def configure(self, pubkey=None):
        tmp = tempfile.mkdtemp(prefix='pihsm.')
        try:
            print(tmp)
            root = path.join(tmp, 'root')
            firmware = path.join(root, 'boot', 'firmware')
            os.mkdir(root)
            subprocess.check_call(['mount', self.p2, root])
            subprocess.check_call(['mount', self.p1, firmware])
            configure_image(root, pubkey)
        finally:
            umount(self.p1)
            umount(self.p2)
            shutil.rmtree(tmp)

    def run(self, pubkey=None):
        self.write_image()
        self.configure(pubkey)        

