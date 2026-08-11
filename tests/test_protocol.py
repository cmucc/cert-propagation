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
import sys

import pytest

import cert_receive as cr

pytestmark = pytest.mark.usefixtures('noop_config_check', 'simulated_stdin')


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

@pytest.mark.usefixtures('short_receive_timeout')
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

        assert re.search(r'^Thats all folks$', certs[0], re.MULTILINE)

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


@pytest.mark.usefixtures('mock_g_args')
class TestProtocolEncoding:
    @pytest.mark.parametrize('encoding', ['utf8', 'latin1'])
    @foreach_linesep
    def test_non_ascii_config_name(self, linesep, encoding):
        full_config = {'Über': {}}
        lines = [
            'Über',
            '-----BEGIN X509 CERTIFICATE-----',
            ':-)',
            '-----END X509 CERTIFICATE-----',
            '',
        ]
        lines = [line.encode(encoding) for line in lines]
        with self.simulated_stdin(lines, linesep=linesep.encode(encoding)):
            if encoding != 'utf8':
                # The latin1 encoding is not valid UTF-8, because it will
                # include an isolated byte with the MSB set.
                with pytest.raises(cr.BadSenderException,
                                   match=r'\bnot\s+decode\s+config.*\bname\b'):
                    cr.interact_with_sender(full_config)
                return

            section, certs, key = cr.interact_with_sender(full_config)

        assert section is full_config['Über']
        assert len(certs) == 1
        assert key is None

        assert re.search(r'^:-\)$', certs[0], re.MULTILINE)

    @pytest.mark.parametrize('encoding', ['utf8', 'latin9', 'eucjp'])
    def test_non_ascii_comments(self, encoding):
        full_config = {'expensive': {}}
        lines = ['expensive']
        if encoding != 'latin9':
            lines.append('50万円もしたなんて信じられない！')
        lines.extend([
            '-----BEGIN PRIVATE KEY-----',
            'the key',
            '-----END PRIVATE KEY-----',
        ])
        if encoding != 'eucjp':
            lines.append('¿Debería haber comprado un certificado EV por 3000€?')
        lines.extend([
            '-----BEGIN CERTIFICATE-----',
            'the certificate',
            '-----END CERTIFICATE-----',
        ])
        lines.extend([
            "Does it look like I'm made of money?",
            '',
        ])
        lines = [line.encode(encoding) for line in lines]
        with self.simulated_stdin(lines, linesep=b'\n'):
            section, certs, key = cr.interact_with_sender(full_config)

        assert section is full_config['expensive']
        assert len(certs) == 1
        assert key is not None
        assert '\nthe certificate\n' in certs[0]
        assert '\nthe key\n' in key
        for char in ('万', 'い', '¿', '€', '?'):
            assert char not in certs[0]
            assert char not in key


@pytest.mark.usefixtures('short_receive_timeout')
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
        match = None
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


# For the data maximum tests, we use adaptive delays, where we begin with
# delays between lines or larger chunks of data and then switch to delays
# between every byte as we approach the data maximums.
foreach_delay = pytest.mark.parametrize(
    'delay',
    [{}, {'line_delay': 0.002}],
    ids=['no_delay', 'adaptive_delay'],
)

@pytest.mark.usefixtures('mock_g_args')
class TestProtocolDataMaximums:
    '''
    Test cases verifying that cr.interact_with_sender properly applies
    data limits to input provided by the sender.
    '''
    @staticmethod
    def adaptive_character_generator(total, terminator='', chunksize=100):
        # The following ensure we always generate at least a chunk worth
        # of non-terminator characters with byte delays.
        adaptive_threshold = 2 * chunksize
        assert chunksize > len(terminator)

        while total > adaptive_threshold:
            total = total - chunksize
            yield 'y' * chunksize

        while total > len(terminator):
            total = total - 1
            yield 'z'

        if terminator:
            yield from terminator

    @staticmethod
    def line_generator(total, linesep, linelength=1000):
        # The following ensures we can always generate a line with at least
        # one non-separator character.
        assert linelength > 2 + len(linesep)

        while total > 0:
            if total > linelength + len(linesep):
                line = ('0' * (linelength - len(linesep))) + linesep
            elif total > linelength:
                line = ('1' * (linelength - 2 - len(linesep))) + linesep
            else:
                line = ('2' * (total - len(linesep))) + linesep
            total = total - len(line)
            yield line

    @classmethod
    def block_generator(cls, what, total, linesep, adaptive_delay=False):
        begin_line = '-----BEGIN {}-----{}'.format(what, linesep)
        total = total - len(begin_line)

        end_line = '-----END {}-----{}'.format(what, linesep)
        # cr.interact_with_sender() does not match the final linesep of
        # PEM blocks and always appends a '\n'; adjust space consumption
        # accordingly.
        total = total - len(end_line) + len(linesep) - 1

        assert total > 0
        linelength = 1000
        data = cls.line_generator(total, linesep, linelength=linelength)

        if not adaptive_delay:
            yield begin_line
            yield from data
            yield end_line
            return

        assert linelength + len(end_line) >= 100
        prev_line = begin_line
        for line in data:
            if len(line) + len(end_line) >= 100:
                # There are at least 100 bytes in the current data line
                # and the END line; we don't need to emit anything from
                # the previous data line with byte delays.
                yield prev_line
            else:
                # There are fewer than 100 bytes in the current data line
                # (which therefore must be the last data line) and the END
                # line; emit up to 100 bytes from the previous data line
                # with byte delays.
                needed = 100 - len(end_line)
                yield prev_line[:-needed]
                yield from prev_line[-needed:]
                yield from line
                break
            prev_line = line
        else:
            if len(prev_line) + len(end_line) > 200:
                # There are more than 200 bytes in the last data line and the
                # END line.  Only emit the last 200 bytes with byte delays.
                needed = 200 - len(end_line)
                yield prev_line[:-needed]
                yield from prev_line[-needed:]
            else:
                # There are no more than 200 bytes in the last data line and
                # the END line.  Emit everything with byte delays.
                yield prev_line
        yield from end_line

    @foreach_delay
    @pytest.mark.parametrize('data_length', ['max', 'excess'])
    def test_configuration_name(self, data_length, delay):
        realsep = '\n'
        allowed_bytes = cr.PEM_BLOCK_MAXIMUM
        if data_length == 'max':
            expect_match = r'\bnot?\b.*\bcertificates?\b'
            data_length = allowed_bytes
        else:
            expect_match = r'\bexcess\s+data\b'
            data_length = allowed_bytes + 1
        def data():
            return self.adaptive_character_generator(data_length,
                                                     terminator=realsep)

        full_config = {''.join(data())[:-1]: {}}
        with self.simulated_stdin(data(), linesep='', **delay), \
             pytest.raises(cr.BadSenderException, match=expect_match):
            cr.interact_with_sender(full_config)

    @foreach_delay
    @pytest.mark.parametrize('data_length', ['max', 'excess'])
    def test_additional_line_length(self, data_length, delay):
        realsep = '\r\n'
        # For crlf line separators, the cr by itself is also a valid line
        # separator.  Hence we can handle additional lines up to a length
        # where the line separator begins within the maximum number of
        # bytes.
        allowed_bytes = cr.PEM_BLOCK_MAXIMUM - 1 + len(realsep)
        if data_length == 'max':
            expect_exc = False
            data = self.adaptive_character_generator(allowed_bytes,
                                                     terminator=realsep)
        else:
            expect_exc = True
            data = self.adaptive_character_generator(allowed_bytes + 1,
                                                     terminator=realsep)

        full_config = {'verbosely': {}}
        lines = ['verbosely' + realsep]
        lines.extend([
            '-----BEGIN CERTIFICATE-----' + realsep,
            'qwer' + realsep,
            '-----END CERTIFICATE-----' + realsep,
        ])
        lines.extend(data)
        lines.extend([
            '-----BEGIN PRIVATE KEY-----' + realsep,
            'asdf' + realsep,
            '-----END PRIVATE KEY-----' + realsep,
        ])

        with self.simulated_stdin(lines, linesep='', **delay):
            if expect_exc:
                with pytest.raises(cr.BadSenderException,
                                   match=r'\bexcess\s+data\b'):
                    cr.interact_with_sender(full_config)
                return

            section, certs, key = cr.interact_with_sender(full_config)

        assert section is full_config['verbosely']
        assert len(certs) == 1
        assert key is not None

    @foreach_delay
    @pytest.mark.parametrize(
        # Since cr.interact_with_sender uses an expect pattern to match
        # a singular additional line, expect only needs to buffer a
        # single additional line at a time.  Thus, we can handle an
        # arbitrary number of bytes in additional lines, as long as none
        # of the lines individually exceed cr.PEM_BLOCK_MAXIMUM.
        'data_length',
        [7001, cr.PEM_BLOCK_MAXIMUM + 2, cr.OVERALL_PEM_MAXIMUM + 7],
    )
    def test_additional_lines(self, data_length, delay):
        realsep = '\r'
        line_length = 1000
        if not delay:
            by_line_length = data_length
            adaptive_length = 0
        else:
            by_line_length = int((data_length - int(line_length / 2)) / line_length) * line_length
            assert by_line_length >= line_length
            adaptive_length = data_length - by_line_length
            assert adaptive_length >= int(line_length / 2)
        print("data_length={}, by_line_length={}, adaptive_length={}"
              .format(data_length, by_line_length, adaptive_length),
              file=sys.stderr)

        full_config = {'poetry': {}}
        lines = ['poetry' + realsep]
        lines.extend(self.line_generator(by_line_length, linesep=realsep, linelength=line_length))
        if adaptive_length:
            lines.extend(self.adaptive_character_generator(adaptive_length, terminator=realsep))
        lines.extend([
            '-----BEGIN X.509 CERTIFICATE-----' + realsep,
            'Finally something I can do something with!' + realsep,
            '-----END X.509 CERTIFICATE-----' + realsep,
        ])
        print("chunks={}".format(len(lines)), file=sys.stderr)

        with self.simulated_stdin(lines, linesep='', **delay):
            section, certs, key = cr.interact_with_sender(full_config)

        assert section is full_config['poetry']
        assert len(certs) == 1
        assert key is None

    @foreach_delay
    @pytest.mark.parametrize(
        # Since the BEGIN line and the remainder of a PEM block are
        # matched by separate expect calls, it's possible to process a
        # slightly oversize PEM block without hitting a BufferFull
        # condition.  Hence we perform two tests with blocks larger than
        # the maximum:  one with a block that is only a byte too large,
        # and one that's significantly too large.  The first verifies
        # explicit oversize block rejection in cr.interact_with_sender(),
        # while the latter verifies expect will not allow its buffer to
        # grow too large.
        'data_length',
        [
            (cr.PEM_BLOCK_MAXIMUM,        r'\bnot?\b.*\bcertificates?\b'),
            (cr.PEM_BLOCK_MAXIMUM + 1,    r'\bPEM\s+data\s+block\b.*\bmaximum\b'),
            (cr.PEM_BLOCK_MAXIMUM + 180,  r'\b\bexcess\s+data\b'),
        ],
        ids=['max', 'plus_1', 'plus_180'],
    )
    def test_pem_block(self, data_length, delay):
        realsep = '\n'
        data_length, expect_match = data_length

        full_config = {'duplo': {}}
        lines = ['duplo' + realsep]
        lines.extend(self.block_generator('PRIVATE KEY',
                                          data_length,
                                          linesep=realsep,
                                          adaptive_delay=bool(delay)))
        print("chunks={}".format(len(lines)), file=sys.stderr)

        with self.simulated_stdin(lines, linesep='', **delay), \
             pytest.raises(cr.BadSenderException, match=expect_match):
            cr.interact_with_sender(full_config)

    @pytest.mark.parametrize('data_length', ['max', 'excess_begin', 'excess_end'])
    def test_overall_pem(self, data_length):
        realsep = '\r\n'
        allowed_bytes = cr.OVERALL_PEM_MAXIMUM
        if data_length == 'max':
            expect_exc = False
            target_length = allowed_bytes
        else:
            expect_exc = True
            if data_length.endswith('_begin'):
                target_length = allowed_bytes
            else:
                target_length = allowed_bytes + 1

        full_config = {'gigantic': {}}
        lines = ['gigantic' + realsep]

        key_length = 12000
        assert key_length <= cr.PEM_BLOCK_MAXIMUM
        lines.extend(self.block_generator('PRIVATE KEY',
                                          key_length,
                                          linesep=realsep))
        target_length = target_length - key_length

        cert_count = 0
        cert_length = 5000
        assert cert_length <= cr.PEM_BLOCK_MAXIMUM
        while target_length > 0:
            lines.extend(self.block_generator('CERTIFICATE',
                                              min(cert_length, target_length),
                                              linesep=realsep))
            cert_count = cert_count + 1
            target_length = target_length - cert_length
        if data_length == 'excess_begin':
            lines.extend(self.block_generator('CERTIFICATE',
                                              cert_length,
                                              linesep=realsep))
            cert_count = cert_count + 1

        with self.simulated_stdin(lines, linesep=''):
            if expect_exc:
                with pytest.raises(cr.BadSenderException,
                                   match=r'\b[Oo]verall\s+PEM\b.*\bmaximum\b'):
                    cr.interact_with_sender(full_config)
                return

            section, certs, key = cr.interact_with_sender(full_config)

        assert section is full_config['gigantic']
        assert len(certs) == cert_count
        assert key is not None
