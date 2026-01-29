# Copyright (C) 2026 Keith Allen Bare II
#
# This file is part of cert-propagation.
#
# cert-propagation is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# cert-propagation is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
# Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with cert-propagation. If not, see <https://www.gnu.org/licenses/>.

from contextlib import contextmanager
import errno
import io
import os
import re
import sys
from tempfile import TemporaryFile
from unittest.mock import patch

import pytest

import cert_receive as cr

@pytest.mark.usefixtures('noop_config_check', 'short_receive_timeout')
class TestProtocol:
    @staticmethod
    @contextmanager
    def simulated_stdin(lines, linesep='\n'):
        if not isinstance(lines, (bytes, str)):
            if isinstance(lines[0], bytes):
                lines = linesep.encode().join(lines)
            else:
                lines = linesep.join(lines)
        if not isinstance(lines, bytes):
            lines = lines.encode()
        with TemporaryFile() as f:
            f.write(lines)
            f.seek(0, io.SEEK_SET)
            with patch('sys.stdin', new=f):
                yield f

    foreach_linesep = pytest.mark.parametrize('linesep', ['\n', '\r\n'],
                                              ids=['unix', 'msdos'])

    @foreach_linesep
    def test_certificate_and_key(self, linesep):
        full_config = {'example': {}}
        lines = [
            'example',
            '-----BEGIN CERTIFICATE-----',
            'You got a gold star!',
            '-----END CERTIFICATE-----',
            '-----BEGIN PRIVATE KEY-----',
            'Better not to share',
            '-----END PRIVATE KEY-----',
            '',
        ]
        with self.simulated_stdin(lines, linesep=linesep):
            section, certs, key = cr.interact_with_sender(full_config)
        assert section is full_config['example']
        assert len(certs) == 1
        assert key is not None

        if linesep != '\n':
            certs = [cert.replace(linesep, '\n') for cert in certs]
            key = key.replace(linesep, '\n')
        cert_re = re.compile(r'^You got a gold star!$', re.MULTILINE)
        key_re = re.compile(r'^Better not to share$', re.MULTILINE)
        assert cert_re.search(certs[0])
        assert not key_re.search(certs[0])
        assert not cert_re.search(key)
        assert key_re.search(key)

    @foreach_linesep
    def test_certificate_only(self, linesep):
        full_config = {'lil': {}}
        lines = [
            'lil',
            '-----BEGIN CERTIFICATE-----',
            'Thats all folks',
            '-----END CERTIFICATE-----',
            '',
        ]
        with self.simulated_stdin(lines, linesep=linesep):
            section, certs, key = cr.interact_with_sender(full_config)
        assert section is full_config['lil']
        assert len(certs) == 1
        assert key is None

        if linesep != '\n':
            certs = [cert.replace(linesep, '\n') for cert in certs]
        assert re.search(r'^Thats all folks$', certs[0], re.MULTILINE)

    @foreach_linesep
    def test_non_ascii_config_name(self, linesep):
        full_config = {'Über': {}}
        lines = [
            'Über',
            '-----BEGIN X509 CERTIFICATE-----',
            ':-)',
            '-----END X509 CERTIFICATE-----',
            '',
        ]
        with self.simulated_stdin(lines, linesep=linesep):
            section, certs, key = cr.interact_with_sender(full_config)
        assert section is full_config['Über']
        assert len(certs) == 1
        assert key is None

        if linesep != '\n':
            certs = [cert.replace(linesep, '\n') for cert in certs]
        assert re.search(r'^:-\)$', certs[0], re.MULTILINE)

    @foreach_linesep
    def test_certificate_chain(self, linesep):
        full_config = {'link': {}}
        lines = [
            'link',
            '',
            '-----BEGIN TRUSTED CERTIFICATE-----',
            '2 Two 2 two',
            '-----END TRUSTED CERTIFICATE-----',
            '',
            '-----BEGIN CERTIFICATE-----',
            'one 1 One !',
            '-----END CERTIFICATE-----',
            '',
        ]
        with self.simulated_stdin(lines, linesep=linesep):
            section, certs, key = cr.interact_with_sender(full_config)
        assert section is full_config['link']
        assert len(certs) == 2
        assert key is None

        if linesep != '\n':
            certs = [cert.replace(linesep, '\n') for cert in certs]
        two_re = re.compile(r'^2 Two 2 two$', re.MULTILINE)
        one_re = re.compile(r'^one 1 One !$', re.MULTILINE)
        assert two_re.search(certs[0])
        assert not one_re.search(certs[0])
        assert not two_re.search(certs[1])
        assert one_re.search(certs[1])

    @foreach_linesep
    def test_key_only(self, linesep):
        full_config = {'bad': {}}
        lines = [
            'bad',
            '-----BEGIN RSA PRIVATE KEY-----',
            'Naughty naughty',
            '-----END RSA PRIVATE KEY-----',
            '',
        ]
        with self.simulated_stdin(lines, linesep=linesep), \
             pytest.raises(cr.BadSenderException,
                           match=r'\bnot?\b.*\bcertificates?\b'):
            cr.interact_with_sender(full_config)

    def test_no_input(self):
        with self.simulated_stdin(b''), \
             pytest.raises(cr.BadSenderException, match=r'\bEOF\b'):
            cr.interact_with_sender({})

    def test_config_name_only(self):
        full_config = {'dubious': {}}
        with self.simulated_stdin(b'dubious\n\n'), \
             pytest.raises(cr.BadSenderException,
                           match=r'\bnot?\b.*\bcertificates?\b'):
            cr.interact_with_sender(full_config)
