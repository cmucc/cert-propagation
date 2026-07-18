import errno
import itertools
import os
from unittest.mock import patch

import pytest

import cert_receive.mini_expect as me

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
