import errno
import itertools
import os
import re
from unittest.mock import Mock, patch

import pytest

import cert_receive.mini_expect as me

# Work around Python versions < 3.7, which do not provide a named class
# for regular expression match objects.
if hasattr(re, 'Match'):
    re_Match = re.Match
else:
    re_Match = type(re.search(br'.', b'x'))

@pytest.mark.usefixtures('simulated_input')
class TestMiniExpectAppendBuffer:
    foreach_read_style = pytest.mark.parametrize(
        'read_style',
        [
            pytest.param(me.MiniExpect._read_readinto,
                         id='readinto',
                         marks=pytest.mark.skipif(
                             not hasattr(os, 'readinto'),
                             reason='this Python does not have os.readinto')),
            pytest.param(me.MiniExpect._read_read,
                         id='read'),
        ]
    )

    AT_MAXBUFFER_ARGS = {'maxread': 50, 'maxbuffer': 100}

    @staticmethod
    def is_at_maxbuffer(exp):
        return len(exp._buffer) == exp.maxbuffer

    @foreach_read_style
    def test_empty_buffer(self, read_style):
        new_input = b'This is new!\r\n'
        with self.simulated_input(new_input) as fd, \
             patch.object(me.MiniExpect, '_read', read_style):
            exp = me.MiniExpect(fd, **self.AT_MAXBUFFER_ARGS)
            assert self.is_at_maxbuffer(exp)

            at_eof = exp._append_buffer()
            assert not at_eof
            assert exp._bstart == 0
            assert exp._buffer[exp._bstart:exp._bend] == new_input

    @pytest.mark.parametrize('existing_at', [0, 22])
    @foreach_read_style
    def test_append_buffer(self, read_style, existing_at):
        existing_input = b'Already there.\r\n'
        new_input = b'Some more?\r\n'
        with self.simulated_input(new_input) as fd, \
             patch.object(me.MiniExpect, '_read', read_style):
            exp = me.MiniExpect(fd, **self.AT_MAXBUFFER_ARGS)
            assert self.is_at_maxbuffer(exp)
            exp._bstart = existing_at
            exp._bend = existing_at + len(existing_input)
            exp._buffer[exp._bstart:exp._bend] = existing_input

            at_eof = exp._append_buffer()
            assert not at_eof
            assert exp._bstart == existing_at
            assert exp._buffer[exp._bstart:exp._bend] == existing_input + new_input

    @pytest.mark.parametrize('remaining', [0, 3])
    @foreach_read_style
    def test_shift_append_buffer(self, read_style, remaining):
        existing_input = b'In the way.\n'
        new_input = b'Excuse me!\n'
        with self.simulated_input(new_input) as fd, \
             patch.object(me.MiniExpect, '_read', read_style):
            exp = me.MiniExpect(fd, **self.AT_MAXBUFFER_ARGS)
            assert self.is_at_maxbuffer(exp)
            exp._bend = len(exp._buffer) - remaining
            exp._bstart = exp._bend - len(existing_input)
            exp._buffer[exp._bstart:exp._bend] = existing_input

            at_eof = exp._append_buffer()
            assert not at_eof
            assert exp._bstart == 0
            assert exp._buffer[exp._bstart:exp._bend] == existing_input + new_input

    @pytest.mark.parametrize('existing_at', [0, 3, 7])
    @foreach_read_style
    def test_short_read(self, read_style, existing_at):
        space = 7
        new_input = b'0123456789ABCDEF'
        with self.simulated_input(new_input) as fd, \
             patch.object(me.MiniExpect, '_read', read_style):
            exp = me.MiniExpect(fd, **self.AT_MAXBUFFER_ARGS)
            assert self.is_at_maxbuffer(exp)
            fill = b'q' * exp.maxbuffer
            exp._buffer[0:len(exp._buffer)] = fill
            exp._bstart = existing_at
            exp._bend = existing_at + len(exp._buffer) - space

            at_eof = exp._append_buffer()
            assert not at_eof
            assert exp._bstart == 0
            assert exp._bend == len(exp._buffer)
            assert exp._buffer == (fill + new_input[:space])[space:]

    def test_full_buffer(self):
        new_input = b'Lorem ipsum...'
        with self.simulated_input(new_input) as fd:
            exp = me.MiniExpect(fd, **self.AT_MAXBUFFER_ARGS)
            assert self.is_at_maxbuffer(exp)
            fill = b'Z' * exp.maxbuffer
            exp._buffer[0:len(exp._buffer)] = fill
            exp._bstart = 0
            exp._bend = len(exp._buffer)

            with pytest.raises(me.BufferFull):
                exp._append_buffer()

    GROW_BUFFER_ARGS = {'maxread': 10, 'maxbuffer': 100}

    @foreach_read_style
    def test_grow_from_empty_buffer(self, read_style):
        new_input = b'5 4 3 2 1... blast off!\n'
        with self.simulated_input(new_input) as fd, \
             patch.object(me.MiniExpect, '_read', read_style):
            exp = me.MiniExpect(fd, **self.GROW_BUFFER_ARGS)
            assert not self.is_at_maxbuffer(exp)
            init_len = len(exp._buffer)
            assert init_len < len(new_input)

            at_eof = False
            while not at_eof:
                at_eof = exp._append_buffer()
            assert exp._bstart == 0
            assert len(exp._buffer) > init_len
            assert len(exp._buffer) >= len(new_input)
            assert exp._buffer[exp._bstart:exp._bend] == new_input

    @foreach_read_style
    def test_grow_append_buffer(self, read_style):
        existing_input = b'Hello my name is'
        new_input = b'Joe.\r\n'
        with self.simulated_input(new_input) as fd, \
             patch.object(me.MiniExpect, '_read', read_style):
            exp = me.MiniExpect(fd, **self.GROW_BUFFER_ARGS)
            assert not self.is_at_maxbuffer(exp)
            init_len = len(exp._buffer)
            assert len(existing_input) <= init_len
            assert exp._bstart == 0
            exp._bend = len(existing_input)
            exp._buffer[exp._bstart:exp._bend] = existing_input

            at_eof = exp._append_buffer()
            assert not at_eof
            assert exp._bstart == 0
            assert len(exp._buffer) > init_len
            assert exp._buffer[exp._bstart:exp._bend] == existing_input + new_input

    @pytest.mark.parametrize('existing_at', [1, 4])
    @foreach_read_style
    def test_shift_grow_append_buffer(self, read_style, existing_at):
        existing_input = b'0123456789012345'
        new_input = b' FIGHT!\n'
        with self.simulated_input(new_input) as fd, \
             patch.object(me.MiniExpect, '_read', read_style):
            exp = me.MiniExpect(fd, **self.GROW_BUFFER_ARGS)
            assert not self.is_at_maxbuffer(exp)
            init_len = len(exp._buffer)
            assert existing_at + len(existing_input) <= init_len
            exp._bstart = existing_at
            exp._bend = exp._bstart + len(existing_input)
            exp._buffer[exp._bstart:exp._bend] = existing_input

            at_eof = exp._append_buffer()
            assert not at_eof
            assert exp._bstart == 0
            assert len(exp._buffer) > init_len
            assert exp._buffer[exp._bstart:exp._bend] == existing_input + new_input

    @foreach_read_style
    def test_grow_to_maxbuffer(self, read_style):
        greetings = itertools.cycle(['Howdy!'])
        with self.simulated_input(greetings, linesep=b'\n') as fd, \
             patch.object(me.MiniExpect, '_read', read_style):
            exp = me.MiniExpect(fd, **self.GROW_BUFFER_ARGS)
            assert not self.is_at_maxbuffer(exp)

            with pytest.raises(me.BufferFull):
                try:
                    at_eof = False
                    while not at_eof:
                        at_eof = exp._append_buffer()
                finally:
                    try:
                        os.close(fd)
                    except (IOError, OSError) as exc:
                        if exc.errno != errno.EBADF:
                            raise
            assert not at_eof
            assert self.is_at_maxbuffer(exp)
            assert exp._buffer.startswith(b'Howdy!\nHowdy!\nHowdy!\nHowdy!\n')

class TestMiniExpectCheckMatchers:
    @staticmethod
    def make_matchers(pattern):
        return [me._Matcher.from_expect_arg(x) for x in pattern]

    def test_regex_1(self):
        input_bytes = b'Hello, world!\r\n'
        exp = me.MiniExpect(-1)
        exp._bstart = 0
        exp._bend = len(input_bytes)
        exp._buffer[exp._bstart:exp._bend] = input_bytes

        idx, match = exp._check_matchers(
                            self.make_matchers([br'^Hello']),
                            False,
                            False)
        assert idx == 0
        assert isinstance(match, re_Match)
        assert match.group(0) == b'Hello'
        assert match.start() == 0

    def test_regex_2(self):
        input_bytes = b'Hello, world!\n'
        exp = me.MiniExpect(-1)
        exp._bstart = len(exp._buffer) - len(input_bytes)
        exp._bend = len(exp._buffer)
        exp._buffer[exp._bstart:exp._bend] = input_bytes

        idx, match = exp._check_matchers(
                            self.make_matchers([br'world']),
                            False,
                            False)
        assert idx == 0
        assert isinstance(match, re_Match)
        assert match.group(0) == b'world'
        assert match.start() == len(b'Hello, ')

    def test_no_match(self):
        input_bytes = b'Goodnight, moon.\r\n'
        exp = me.MiniExpect(-1)
        exp._bstart = 0
        exp._bend = len(input_bytes)
        exp._buffer[exp._bstart:exp._bend] = input_bytes

        idx, match = exp._check_matchers(
                            self.make_matchers([br'(?i)hello', br'(?i)world']),
                            False,
                            False)
        assert idx is None
        assert match is None

    @pytest.mark.parametrize('eofpattern', ['explicit', 'implicit'])
    def test_eof(self, eofpattern):
        exp = me.MiniExpect(-1)
        pattern = []
        if eofpattern == 'explicit':
            pattern.append(me.EOF)
        else:
            pattern.append(rb'.')

        idx, match = exp._check_matchers(
                            self.make_matchers(pattern),
                            True,
                            False)
        if pattern[0] is me.EOF:
            assert idx == 0
        else:
            assert idx is None
        assert match is me.EOF

    @pytest.mark.parametrize('timeoutpattern', ['explicit', 'implicit'])
    def test_timeout(self, timeoutpattern):
        input_bytes = b'Irrelevant!'
        exp = me.MiniExpect(-1)
        exp._bstart = 0
        exp._bend = len(input_bytes)
        exp._buffer[exp._bstart:exp._bend] = input_bytes
        pattern = []
        if timeoutpattern == 'explicit':
            pattern.append(me.TIMEOUT)
        else:
            pattern.append(rb'a penny for your thoughts\?')

        idx, match = exp._check_matchers(
                            self.make_matchers(pattern),
                            False,
                            True)
        if pattern[0] is me.TIMEOUT:
            assert idx == 0
        else:
            assert idx is None
        assert match is me.TIMEOUT

    def test_prefer_lowest_regex_start(self):
        input_bytes = b'abcdef'
        exp = me.MiniExpect(-1)
        exp._bstart = int(len(exp._buffer) / 5)
        exp._bend = exp._bstart + len(input_bytes)
        assert exp._bend <= len(exp._buffer)
        exp._buffer[exp._bstart:exp._bend] = input_bytes

        idx, match = exp._check_matchers(
                            self.make_matchers([br'cdef', br'b', br'def']),
                            False,
                            False)
        assert idx == 1
        assert isinstance(match, re_Match)
        assert match.group(0) == b'b'
        assert match.start() == len(b'a')

    def test_prefer_first_regex_at_lowest_start(self):
        input_bytes = b'Cool cats at the school\r\n'
        exp = me.MiniExpect(-1)
        exp._bstart = 3 * int(len(exp._buffer) / 5)
        exp._bend = exp._bstart + len(input_bytes)
        assert exp._bend <= len(exp._buffer)
        exp._buffer[exp._bstart:exp._bend] = input_bytes

        idx, match = exp._check_matchers(
                            self.make_matchers([br'.at', br'school', br'ca']),
                            False,
                            False)
        assert idx == 0
        assert isinstance(match, re_Match)
        assert match.group(0) == b'cat'
        assert match.start() == len(b'Cool ')

    @pytest.mark.parametrize(
        'preference',
        [
            pytest.param((re_Match, me.EOF), id='match_over_eof'),
            pytest.param((re_Match, me.TIMEOUT), id='match_over_timeout'),
            pytest.param((me.EOF, me.TIMEOUT), id='eof_over_timeout'),
        ]
    )
    def test_matcher_preference(self, preference):
        pattern = []
        pattern.append(br'never gonna give a match')
        if re_Match in preference:
            pattern.append(br'.')
        if me.EOF in preference:
            pattern.append(me.EOF)
        if me.TIMEOUT in preference:
            pattern.append(me.TIMEOUT)
        pattern.reverse()

        input_bytes = b'Sharks!\r\n'
        exp = me.MiniExpect(-1)
        exp._bstart = 0
        exp._bend = len(input_bytes)
        exp._buffer[exp._bstart:exp._bend] = input_bytes

        idx, match = exp._check_matchers(
                            self.make_matchers(pattern),
                            me.EOF in pattern,
                            me.TIMEOUT in pattern)
        assert idx is not None
        assert idx != 0
        assert idx != len(pattern) - 1
        assert match is preference[0] or isinstance(match, preference[0])

@pytest.mark.usefixtures('simulated_input')
class TestMiniExpectEndToEnd:
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

    @foreach_delay
    @foreach_end_of_data
    def test_basic(self, delay, end_of_data):
        input_kwargs = {'linesep': '\r\n'}
        input_kwargs.update(delay)
        input_kwargs.update(end_of_data)
        input_lines = ['One', 'Two', 'Three', 'Four']
        with self.simulated_input(input_lines, **input_kwargs) as fd:
            exp = me.MiniExpect(fd, timeout=1)

            idx = exp.expect([br'One\r?\n', br'Uno\r?\n'])
            assert idx == 0
            assert exp.before == b''
            assert exp.after == b'One\r\n'
            assert isinstance(exp.match, re_Match)
            assert exp.match.group(0) == b'One\r\n'

            idx = exp.expect([br'Tr', br'Thr'])
            assert idx == 1
            assert exp.before == b'Two\r\n'
            assert exp.after == b'Thr'
            assert isinstance(exp.match, re_Match)
            assert exp.match.group(0) == b'Thr'

            idx = exp.expect([br'(.*?)\r?\n', me.EOF, me.TIMEOUT])
            assert idx == 0
            assert exp.before == b''
            assert exp.after == b'ee\r\n'
            assert isinstance(exp.match, re_Match)
            assert exp.match.group(1) == b'ee'

            idx = exp.expect([me.TIMEOUT, me.EOF, br'Five\r?\n', br'Cinco\r?\n'])
            if end_of_data['close_at_end_of_data']:
                assert idx == 1
                assert exp.match is me.EOF
            else:
                assert idx == 0
                assert exp.match is me.TIMEOUT
            assert exp.before == b'Four'
            assert exp.after == b''

    @foreach_delay
    def test_multiple_lines_required(self, delay):
        input_kwargs = {'linesep': '\r\n'}
        input_kwargs.update(delay)
        input_lines = ['status: good', 'name: mickey', '', '>> ']
        with self.simulated_input(input_lines, **input_kwargs) as fd:
            exp = me.MiniExpect(fd, timeout=1)
            mock_read = Mock(wraps=exp._read)

            with patch.object(exp, '_read', new=mock_read):
                exp.expect(b'\r?\n>> ')

            assert exp.before == b'status: good\r\nname: mickey\r\n'
            assert exp.after == b'\r\n>> '
            assert isinstance(exp.match, re_Match)
            assert exp.match.group(0) == b'\r\n>> '

            if delay:
                assert mock_read.call_count > 1

    def test_compile_with_dotall(self):
        input_lines = ['junk-->Good', '-->evening', 'mister<--', '<--junk', '']
        with self.simulated_input(input_lines, linesep='\n') as fd:
            exp = me.MiniExpect(fd, timeout=1)

            exp.expect(br'\n-->(.*\n)<--')

            assert exp.before == b'junk-->Good'
            assert exp.after == b'\n-->evening\nmister<--\n<--'
            assert isinstance(exp.match, re_Match)
            assert exp.match.group(1) == b'evening\nmister<--\n'

    @foreach_end_of_data
    def test_no_match_exception(self, end_of_data):
        input_kwargs = {'linesep': '\n'}
        input_kwargs.update(end_of_data)
        input_lines = ['Just a haystack.', 'Nothing interesting,', 'only hay.']
        with self.simulated_input(input_lines, **input_kwargs) as fd:
            exp = me.MiniExpect(fd, timeout=1)
            etype = me.EOF if end_of_data['close_at_end_of_data'] else me.TIMEOUT

            with pytest.raises(etype):
                exp.expect([br'(?i)needle'])

            assert exp.before == '\n'.join(input_lines).encode()
            assert exp.after == b''
            assert exp.match is etype

    def test_io_exception(self):
        input_lines = ['Beep ', 'Boop ', 'Beepboop\r\n']
        with self.simulated_input(input_lines, linesep='', line_delay=0.3) as fd:
            exp = me.MiniExpect(fd, timeout=1)
            real_exp_read = exp._read
            with patch.object(exp, '_read') as mock_read, \
                 pytest.raises((OSError, IOError)):
                call_count = 0
                def side_effect(rend):
                    nonlocal call_count
                    call_count = call_count + 1
                    if call_count == 1:
                        return real_exp_read(rend)
                    else:
                        raise IOError(errno.EIO, os.strerror(errno.EIO))
                mock_read.side_effect = side_effect
                exp.expect(br'\r?\n')

            assert exp.before == b'Beep '
            assert exp.after == b''
            assert exp.match is None

    def test_buffer_full(self):
        input_lines = itertools.cycle(['pony', 'horse'])
        with self.simulated_input(input_lines, linesep='\r\n') as fd:
            exp = me.MiniExpect(fd, timeout=1, maxread=100, maxbuffer=1000)

            with pytest.raises(me.BufferFull):
                try:
                    exp.expect(br'\r?\nunicorn\r?\n')
                finally:
                    try:
                        exp.close()
                    except (IOError, OSError) as exc:
                        if exc.errno != errno.EBADF:
                            raise

            assert exp.before.startswith(b'pony\r\nhorse\r\npony\r\nhorse\r\n')
            assert exp.match is None
