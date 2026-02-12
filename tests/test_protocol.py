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
    ['\n', '\r\n', '\r'],
    ids=['lf', 'crlf', 'cr'],
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

@pytest.mark.usefixtures('noop_config_check', 'short_receive_timeout',
                         'simulated_stdin')
class TestProtocolPemProcessing:
    '''
    Test cases verifying that several variations on the PEM format can be
    processed correctly.
    '''
    @foreach_linesep
    def test_certificate_no_final_linesep(self, linesep):
        full_config = {'runon': {}}
        lines = [
            'runon',
            '-----BEGIN X.509 CERTIFICATE-----',
            'It certifies',
            '-----END X.509 CERTIFICATE-----',
        ]
        with self.simulated_stdin(lines, linesep=linesep):
            section, certs, key = cr.interact_with_sender(full_config)
        assert section is full_config['runon']
        assert len(certs) == 1
        assert key is None

        if linesep != '\n':
            certs[0] = certs[0].replace(linesep, '\n')
        assert re.search(r'^It certifies$', certs[0], re.MULTILINE)
        assert certs[0].endswith('\n')

    @foreach_linesep
    def test_prepended_text(self, linesep):
        full_config = {'extras': {}}
        lines = [
            'extras',
            'Please be sure to copy the text below exactly! Any changes ',
            'to it will prevent your software from functioning correctly.',
            '-----BEGIN CERTIFICATE-----',
            'ABCDEFGHIJKL',
            '-----END CERTIFICATE-----',
            ''
        ]
        with self.simulated_stdin(lines, linesep=linesep):
            section, certs, key = cr.interact_with_sender(full_config)
        assert section is full_config['extras']
        assert len(certs) == 1
        assert key is None

        if linesep != '\n':
            certs[0] = certs[0].replace(linesep, '\n')
        assert re.search(r'^ABCDEFGHIJKL$', certs[0], re.MULTILINE)
        assert certs[0].startswith('-----BEGIN')

    @foreach_linesep
    def test_pem_initial_blank_lines(self, linesep):
        full_config = {'weird': {}}
        lines = [
            'weird',
            '-----BEGIN PRIVATE KEY-----',
            '',
            '1234ABCD',
            '-----END PRIVATE KEY-----',
            '-----BEGIN CERTIFICATE-----',
            '',
            'WXYZ7890',
            '-----END CERTIFICATE-----',
            ''
        ]
        with self.simulated_stdin(lines, linesep=linesep):
            section, certs, key = cr.interact_with_sender(full_config)
        assert section is full_config['weird']
        assert len(certs) == 1
        assert key is not None

        if linesep != '\n':
            certs[0] = certs[0].replace(linesep, '\n')
            key = key.replace(linesep, '\n')
        cert_re = re.compile(r'^WXYZ7890$', re.MULTILINE)
        key_re = re.compile(r'^1234ABCD$', re.MULTILINE)
        assert cert_re.search(certs[0])
        assert not key_re.search(certs[0])
        assert not cert_re.search(key)
        assert key_re.search(key)

    @pytest.mark.parametrize('whitespace',
                             ['', ' ', '\t', '\v', '\f'],
                             ids=['none', 'space', 'tab', 'vtab', 'formfeed'])
    def test_pem_lax_delimiter_whitespace(self, whitespace):
        full_config = {'lax': {}}
        pem_lines = [
            '-----BEGIN CERTIFICATE-----',
            '~~The Authority~~',
            '-----END CERTIFICATE-----',
            '-----BEGIN CERTIFICATE-----',
            '~~Certificate of Achievement~~',
            '-----END CERTIFICATE-----',
            ''
        ]
        lines = ['lax', whitespace.join(pem_lines)]
        with self.simulated_stdin(lines):
            section, certs, key = cr.interact_with_sender(full_config)
        assert section is full_config['lax']
        assert len(certs) == 2
        assert key is None

        auth_re = re.compile(r'-\s?~~The Authority~~\s?-')
        cert_re = re.compile(r'-\s?~~Certificate of Achievement~~\s?-')
        assert auth_re.search(certs[0])
        assert not cert_re.search(certs[0])
        assert not auth_re.search(certs[1])
        assert cert_re.search(certs[1])

    @pytest.mark.parametrize('whitespace',
                             ['', ' ', '\n', '\r\n', '\r'],
                             ids=['none', 'space', 'lf', 'crlf', 'cr'])
    def test_empty_pem(self, whitespace):
        full_config = {'gone': {}}
        pem_lines = [
            '-----BEGIN PRIVATE KEY----------END PRIVATE KEY-----',
            '-----BEGIN X.509 CERTIFICATE----------END X.509 CERTIFICATE-----',
            ''
        ]
        lines = ['gone', whitespace.join(pem_lines)]
        linesep = '\n'
        if whitespace in ('\r\n', '\r'):
            linesep = whitespace
        with self.simulated_stdin(lines, linesep=linesep):
            section, certs, key = cr.interact_with_sender(full_config)
        assert section is full_config['gone']
        assert len(certs) == 1
        assert key is not None

        empty_re = re.compile(r'-----\s*-----')
        assert empty_re.search(certs[0])
        assert empty_re.search(key)

    @foreach_end_of_data
    @pytest.mark.parametrize('what', ['certificate', 'key'])
    def test_unterminated_pem(self, what, end_of_data):
        full_config = {'malformed': {}}
        lines = [
            'malformed',
            '-----BEGIN CERTIFICATE-----',
            'the certificate',
        ]
        if what == 'certificate':
            match = r'\bno[nt]?\b.*\bEND\b.*\bPEM\b'
        else:
            lines.append('-----END CERTIFICATE-----')
        lines.extend([
            '-----BEGIN PRIVATE KEY-----',
            'the private key',
        ])
        if what == 'key':
            if end_of_data['close_at_end_of_data']:
                match = r'\bEOF\b'
            else:
                match = r'\btimed?(-?|\s*)out\b'
        else:
            lines.append('-----END PRIVATE KEY-----')
        lines.append('')
        with self.simulated_stdin(lines, linesep='\r\n', **end_of_data), \
             pytest.raises(cr.BadSenderException, match=match):
            cr.interact_with_sender(full_config)

    @pytest.mark.parametrize(
        'terminator',
        ['KEY', 'X509 CERTIFICATE'],
        ids=['key_not_certificate', 'mismatched_certificate']
    )
    def test_wrong_pem_terminator_1(self, terminator):
        full_config = {'junk': {}}
        lines = [
            'junk',
            '',
            '-----BEGIN CERTIFICATE-----',
            'of achievement',
            '-----END {}-----'.format(terminator),
            '',
            '',
            '',
        ]
        with self.simulated_stdin(lines), \
             pytest.raises(cr.BadSenderException,
                           match=r'\bEND\b.*\bPEM\b.*\bwrong\b'):
            cr.interact_with_sender(full_config)

    def test_wrong_pem_terminator_2(self):
        full_config = {'devious': {}}
        lines = [
            'devious',
            '-----BEGIN CERTIFICATE-----',
            '*cackles*',
            '-----END PRIVATE KEY-----',
            '-----BEGIN PRIVATE KEY-----',
            'so evil...',
            '-----END CERTIFICATE-----',
            '',
        ]
        with self.simulated_stdin(lines), \
             pytest.raises(cr.BadSenderException,
                           match=r'\bEND\b.*\bPEM\b.*\bwrong\b'):
            cr.interact_with_sender(full_config)

    def test_bad_pem_linesep_in_delimiter(self):
        full_config = {'bleh': {}}
        lines = [
            'bleh',
            '-----BEGIN CERTIFICATE-----',
            'whatever',
            '-----END CERT',
            'IFICATE-----',
            '',
        ]
        with self.simulated_stdin(lines, line_delay=0.04), \
             pytest.raises(cr.BadSenderException, match=r'\bEOF\b'):
            cr.interact_with_sender(full_config)

    @pytest.mark.parametrize('begin_end', ['begin', 'end'])
    @pytest.mark.parametrize('before_after', ['before', 'after'])
    @pytest.mark.parametrize('what', ['extra', 'missing'])
    def test_bad_pem_dashes(self, what, before_after, begin_end):
        full_config = {'bleh': {}}
        if what == 'extra':
            matchdash = '--'
        else:
            matchdash = ''
        where = (before_after, begin_end)
        lines = [
            'bleh',
            (matchdash if where == ('before', 'begin') else '-') +
            '----BEGIN CERTIFICATE----' +
            (matchdash if where == ('after', 'begin') else '-'),
            'whatever',
            (matchdash if where == ('before', 'end') else '-') +
            '----END CERTIFICATE----' +
            (matchdash if where == ('after', 'end') else '-'),
            '',
        ]
        match = r'\binvalid\b.*\b' + begin_end.upper() + r'\b.*\bdelimiter\b'
        if what == 'missing' and begin_end == 'end':
            match = r'\bEOF\b'
        with self.simulated_stdin(lines, byte_delay=0.002), \
             pytest.raises(cr.BadSenderException, match=match):
            cr.interact_with_sender(full_config)

    def test_bad_pem_unknown_label(self):
        full_config = {'bleh': {}}
        lines = [
            'bleh',
            '',
            '',
            '-----start of X.509 certificate-----',
            'a human would know what I meant',
            '-----END X.509 CERTIFICATE-----',
            '',
        ]
        with self.simulated_stdin(lines, line_delay=0.04), \
             pytest.raises(cr.BadSenderException,
                           match=r'\bno[nt]?\b.*\bBEGIN\b.*\bPEM\b'):
            cr.interact_with_sender(full_config)

    def test_bad_pem_backwards(self):
        full_config = {'bleh': {}}
        lines = [
            'bleh',
            '-----END X509 CERTIFICATE-----',
            'oopsie daisy, got it backwards',
            '-----BEGIN X509 CERTIFICATE-----',
            '',
        ]
        with self.simulated_stdin(lines, byte_delay=0.002), \
             pytest.raises(cr.BadSenderException,
                           match=r'\bno[nt]?\b.*\bBEGIN\b.*\bPEM\b'):
            cr.interact_with_sender(full_config)

    @pytest.mark.parametrize('double', ['--', '  '], ids=['2dash', '2space'])
    def test_bad_pem_sequence_in_label(self, double):
        full_config = {'bleh': {}}
        junk = double.join(['the magical', 'mystical', 'certified CERTIFICATE'])
        lines = [
            'bleh',
            '',
            '-----BEGIN ' + junk + '-----',
            'Not actually that special',
            '-----END ' + junk + '-----',
            '',
        ]
        with self.simulated_stdin(lines), \
             pytest.raises(cr.BadSenderException,
                           match=r'\binvalid\b.*\bBEGIN\b.*\bdelimiter\b'):
            cr.interact_with_sender(full_config)
