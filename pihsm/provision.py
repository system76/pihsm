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
import time
import tempfile
import shutil
import subprocess


from .common import atomic_write


log = logging.getLogger(__name__)


CHUNK_SIZE = 8 * 1024 * 1024

RC_LOCAL_1 = b"""#!/bin/sh -ex

# Written by PiHSM:
/etc/rc.local.2
mv /etc/rc.local.2 /etc/rc.local

sleep 2
ufw enable
sleep 10
apt-get purge -y openssh-server
add-apt-repository -ys ppa:jderose/pihsm
apt-get update
apt-get install -y pihsm-server
echo "HRNGDEVICE=/dev/hwrng" > /etc/default/rng-tools

# pollinate snapd mdadm
apt-get purge -y cloud-init cloud-guest-utils
deluser ubuntu --remove-home

systemctl disable apt-daily-upgrade.timer
systemctl disable apt-daily.timer
systemctl disable getty@.service
systemctl mask getty@.service
systemctl disable snapd.socket
systemctl disable snapd.service
systemctl disable snapd.refresh.timer
systemctl disable snapd.snap-repair.timer

systemctl disable lxd.socket
systemctl disable lxd-containers.service
systemctl disable lxcfs.service

systemctl disable ureadahead.service

systemctl disable lvm2-lvmetad.service
systemctl disable lvm2-lvmetad.socket

systemctl disable open-iscsi.service
systemctl disable iscsid.service

systemctl mask getty-static.service
systemctl mask systemd-rfkill.service
systemctl mask systemd-rfkill.socket

systemctl disable systemd-networkd.service
systemctl mask systemd-networkd.service

systemctl disable systemd-resolved.service
systemctl mask systemd-resolved.service

systemctl mask acpid.path
systemctl mask acpid.service
systemctl mask acpid.socket

sleep 3
pihsm-display-enable
sync
sleep 3
shutdown -h now
"""

RC_LOCAL_2 = b"""#!/bin/sh -ex

# Written by PiHSM:
sleep 1
echo ds1307 0x68 > /sys/class/i2c-adapter/i2c-1/new_device
sleep 5
hwclock -s --debug
"""

CONFIG_APPEND = b"""
# Added by PiHSM:
dtoverlay=i2c-rtc,ds1307
arm_freq=600
"""

JOURNALD_CONF_APPEND = b"""
# Added by PiHSM:
Storage=persistent
ForwardToSyslog=no
ForwardToWall=no
ForwardToConsole=yes
"""

RESOLVED_CONF_APPEND = b"""
# Added by PiHSM:
LLMNR=no
MulticastDNS=no
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


def _atomic_append(filename, append):
    current = open(filename, 'rb', 0).read()
    if current.endswith(append):
        log.info('Already modified: %r', filename)
    else:
        atomic_write(0o644, current + append, filename)  


def update_config(basedir):
    filename = path.join(basedir, 'boot', 'firmware', 'config.txt')
    _atomic_append(filename, CONFIG_APPEND)


def update_journald_conf(basedir):
    filename = path.join(basedir, 'etc', 'systemd', 'journald.conf')
    _atomic_append(filename, JOURNALD_CONF_APPEND)


def update_resolved_conf(basedir):
    filename = path.join(basedir, 'etc', 'systemd', 'resolved.conf')
    _atomic_append(filename, RESOLVED_CONF_APPEND)


def _mask_service(basedir, service):
    target = '/dev/null'
    link = path.join(basedir, 'etc', 'systemd', 'system', service)
    assert not path.exists(link)
    os.symlink(target, link)
    log.info('Symlinked %r --> %r', link, target)


def _disable_service(basedir, wanted_by, service):
    filename = path.join(basedir, 'etc', 'systemd', 'system', wanted_by, service)
    assert path.islink(filename)
    os.remove(filename)
    log.info('Removed symlink %r', filename)


def disable_services(basedir):
    pairs = [
        ('default.target.wants', 'ureadahead.service'),
        ('multi-user.target.wants', 'unattended-upgrades.service'),
    ]
    for (wanted_by, service) in pairs:
        _disable_service(basedir, wanted_by, service)
        _mask_service(basedir, service)


def configure_image(basedir):
    update_cmdline(basedir)
    update_config(basedir)
    update_journald_conf(basedir)
    update_resolved_conf(basedir)
    atomic_write(0o600, os.urandom(512),
        path.join(basedir, 'var', 'lib', 'systemd', 'random-seed')
    )
    atomic_write(0o755, RC_LOCAL_1,
        path.join(basedir, 'etc', 'rc.local')
    )
    atomic_write(0o755, RC_LOCAL_2,
        path.join(basedir, 'etc', 'rc.local.2')
    )
    disable_services(basedir)


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


def rereadpt(dev):
    os.sync()
    time.sleep(1)
    subprocess.check_call(['blockdev', '--rereadpt', dev])


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

    def umount_all(self):
        umount(self.p1)
        umount(self.p2)

    def write_image(self):
        self.umount_all()
        rereadpt(self.dev)
        try:
            total = write_image_to_mmc(self.img, self.dev)
            os.sync()
            time.sleep(1)
            return total
        finally:
            rereadpt(self.dev)

    def configure(self):
        tmp = tempfile.mkdtemp(prefix='pihsm.')
        try:
            log.info('Working directory: %r', tmp)
            root = path.join(tmp, 'root')
            os.mkdir(root)
            firmware = path.join(root, 'boot', 'firmware')
            subprocess.check_call(['mount', self.p2, root])
            subprocess.check_call(['mount', self.p1, firmware])
            configure_image(root)
            os.sync()
        finally:
            self.umount_all()
            shutil.rmtree(tmp)
            log.info('Removed directory %r', tmp)

    def run(self):
        self.write_image()
        self.configure()        

