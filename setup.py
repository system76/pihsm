#!/usr/bin/python3

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


"""
Install `pihsm`.
"""

import sys
if sys.version_info < (3, 4):
    sys.exit('ERROR: `pihsm` requires Python 3.4 or newer')

from distutils.core import setup
from distutils.cmd import Command

import pihsm
from pihsm.tests.run import run_tests


class Test(Command):
    description = 'run unit tests and doc tests'

    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        if not run_tests():
            raise SystemExit(2)


setup(
    name='pihsm',
    version=pihsm.__version__,
    description='Use Raspberry Pi as a Hardware Security Module',
    url='https://launchpad.net/pihsm',
    author='System76, Inc.',
    author_email='dev@system76.com',
    license='GPLv3+',
    cmdclass={'test': Test},
    packages=[
        'pihsm',
        'pihsm.tests'
    ],
)

