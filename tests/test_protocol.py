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

import re

import pytest

import cert_receive as cr

foreach_linesep = pytest.mark.parametrize(
    'linesep',
    ['\n', '\r\n'],
    ids=['unix', 'msdos'],
)

foreach_delay = pytest.mark.parametrize(
    'delay',
    [{}, {'byte_delay': 0.002}, {'line_delay': 0.04}],
    ids=['no_delay', 'byte_delay', 'line_delay'],
)

foreach_end_of_data = pytest.mark.parametrize(
    'end_of_data',
    [{'close_at_end_of_data': True}, {'close_at_end_of_data': False}],
    ids=['close', 'no_close'],
)

@pytest.mark.usefixtures('noop_config_check', 'short_receive_timeout',
                         'simulated_stdin')
class TestProtocolBasic:
    @foreach_delay
    @foreach_linesep
    def test_certificate_and_key(self, linesep, delay):
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
        with self.simulated_stdin(lines, linesep=linesep, **delay):
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

    @foreach_delay
    @foreach_linesep
    def test_certificate_only(self, linesep, delay):
        full_config = {'lil': {}}
        lines = [
            'lil',
            '-----BEGIN CERTIFICATE-----',
            'Thats all folks',
            '-----END CERTIFICATE-----',
            '',
        ]
        with self.simulated_stdin(lines, linesep=linesep, **delay):
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

    @foreach_delay
    @foreach_linesep
    def test_certificate_chain(self, linesep, delay):
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
        with self.simulated_stdin(lines, linesep=linesep, **delay):
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

    @foreach_end_of_data
    def test_no_input(self, end_of_data):
        if end_of_data['close_at_end_of_data']:
            match = r'\bEOF\b'
        else:
            match = r'\btimed?(-?|\s*)out\b'
        with self.simulated_stdin(b'', **end_of_data), \
             pytest.raises(cr.BadSenderException, match=match):
            cr.interact_with_sender({})

    @foreach_end_of_data
    def test_config_name_only(self, end_of_data):
        full_config = {'dubious': {}}
        if end_of_data['close_at_end_of_data']:
            match = r'\bnot?\b.*\bcertificates?\b'
        else:
            match = r'\btimed?(-?|\s*)out\b'
        with self.simulated_stdin(b'dubious\n\n', **end_of_data), \
             pytest.raises(cr.BadSenderException, match=match):
            cr.interact_with_sender(full_config)
