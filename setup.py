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
import os
from os import path
import subprocess

import pihsm
from pihsm.tests.run import run_tests


TREE = path.dirname(path.abspath(__file__))
SCRIPTS = [
    'pihsm-private',
    'pihsm-server',
    'pihsm-display',
]


def run_under_same_interpreter(opname, script, args):
    print('\n** running: {}...'.format(script), file=sys.stderr)
    if not os.access(script, os.R_OK | os.X_OK):
        print('ERROR: cannot read and execute: {!r}'.format(script),
            file=sys.stderr
        )
        print('Consider running `setup.py test --skip-{}`'.format(opname),
            file=sys.stderr
        )
        sys.exit(3)
    cmd = [sys.executable, script] + args
    print('check_call:', cmd, file=sys.stderr)
    subprocess.check_call(cmd)
    print('** PASSED: {}\n'.format(script), file=sys.stderr)


def run_sphinx_doctest():
    script = '/usr/share/sphinx/scripts/python3/sphinx-build'
    doc = path.join(TREE, 'doc')
    doctest = path.join(TREE, 'doc', '_build', 'doctest')
    args = ['-EW', '-b', 'doctest', doc, doctest]
    run_under_same_interpreter('sphinx', script, args)


def run_pyflakes3():
    script = '/usr/bin/pyflakes3'
    names = [
        'pihsm',
        'setup.py',
    ] + SCRIPTS
    args = [path.join(TREE, name) for name in names]
    run_under_same_interpreter('flakes', script, args)



class Test(Command):
    description = 'run unit tests and doc tests'

    user_options = [
        ('skip-sphinx', None, 'do not run Sphinx doctests'),
        ('skip-flakes', None, 'do not run pyflakes static checks'),
    ]

    def initialize_options(self):
        self.skip_sphinx = 0
        self.skip_flakes = 0

    def finalize_options(self):
        pass

    def run(self):
        if not run_tests():
            raise SystemExit(2)
        if not self.skip_sphinx:
            run_sphinx_doctest()
        if not self.skip_flakes:
            run_pyflakes3()


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
    scripts=SCRIPTS,
)

