'''
An input-matching module inspired by pexpect.

We use our own implementation so that we can bound memory use.  While pexpect
provides a maxread option, it only limits the size of a given read operation.
Pexpect can internally buffer the results of an arbitrary number of read
operations when no patterns are matching.  On the other hand, a MiniExpect
object can be constructed with a maxbuffer argument, and will raise a
BufferFull exception if, after buffering maxbuffer bytes, no patterns have
matched and input is still available from the file descriptor.
'''

import fcntl
import os
import re
import select
import time


# Work around Python versions < 3.7, which do not provide named classes
# for regular expression match and pattern objects.
if hasattr(re, 'Match'):
    re_Match = re.Match
    re_Pattern = re.Pattern
else:
    re_Match = type(re.search(br'.', b'x'))
    re_Pattern = type(re.compile(br'.'))


class MiniExpectException(Exception):
    pass

class EOF(MiniExpectException):
    pass

class TIMEOUT(MiniExpectException):
    pass

class BufferFull(MiniExpectException):
    pass


class _Matcher:
    @staticmethod
    def from_expect_arg(expect_arg):
        if expect_arg is EOF:
            return _EofMatcher()
        if expect_arg is TIMEOUT:
            return _TimeoutMatcher()
        pattern_text = expect_arg
        if isinstance(expect_arg, re_Pattern):
            pattern_text = expect_arg.pattern
        if not isinstance(pattern_text, (bytes, bytearray, memoryview)):
            raise TypeError('regular expression patterns must be bytes-based')
        return _RegexMatcher(expect_arg)

    def __call__(self, data, is_eof, is_timeout):
        raise NotImplementedError

class _EofMatcher(_Matcher):
    def __call__(self, data, is_eof, is_timeout):
        if is_eof:
            return EOF, len(data)
        return None, None

class _TimeoutMatcher(_Matcher):
    def __call__(self, data, is_eof, is_timeout):
        if is_timeout:
            return TIMEOUT, len(data) + 1
        return None, None

class _RegexMatcher(_Matcher):
    def __init__(self, pattern):
        if not isinstance(pattern, re_Pattern):
            pattern = re.compile(pattern, re.DOTALL)
        self.pattern = pattern

    def __call__(self, data, is_eof, is_timeout):
        match = self.pattern.search(data)
        if match is not None:
            return match, match.start()
        return None, None


class MiniExpect:
    def __init__(self, fileno, timeout=30, maxread=2000, maxbuffer=None):
        self.fileno = fileno
        self.timeout = timeout
        self.maxread = maxread
        self.maxbuffer = maxbuffer

        self.match = None
        self._before = b''
        self._after = b''

        initbuffer = 2 * maxread
        if maxbuffer is not None:
            if maxbuffer < maxread:
                raise ValueError('maxbuffer cannot be less than maxread')
            initbuffer = min(initbuffer, maxbuffer)
        self._buffer = bytearray(initbuffer)
        self._bstart = 0
        self._bend = 0

    @property
    def before(self):
        if isinstance(self._before, memoryview):
            copy = self._before.tobytes()
            self._before.release()
            self._before = copy
        return self._before

    @property
    def after(self):
        if isinstance(self._after, memoryview):
            copy = self._after.tobytes()
            self._after.release()
            self._after = copy
        return self._after

    def _release_views(self):
        if isinstance(self._before, memoryview):
            self._before.release()
            self._before = b''
        if isinstance(self._after, memoryview):
            self._after.release()
            self._after = b''

    def _update_match_before_after(self, match):
        self._release_views()
        self.match = match
        with memoryview(self._buffer) as bufferview:
            if isinstance(match, re_Match):
                mstart = self._bstart + match.start()
                mend = self._bstart + match.end()
                self._before = bufferview[self._bstart:mstart]
                self._after = bufferview[mstart:mend]
                self._bstart = mend
            else:
                self._before = bufferview[self._bstart:self._bend]
                self._after = b''
                self._bstart = self._bend

    def _read_readinto(self, rend):
        if self.fileno == -1:
            return 0
        with memoryview(self._buffer) as bufferview, \
             bufferview[self._bend:rend] as readdest:
            return os.readinto(self.fileno, readdest)

    def _read_read(self, rend):
        if self.fileno == -1:
            return 0
        newdata = os.read(self.fileno, rend - self._bend)
        nread = len(newdata)
        if nread:
            self._buffer[self._bend:self._bend + nread] = newdata
        return nread

    _read = _read_readinto if hasattr(os, 'readinto') else _read_read

    def _append_buffer(self):
        if len(self._buffer) - self._bend >= self.maxread:
            # no manipulation required; there's already enough room at the end
            # of the buffer
            need_shift = False
        elif len(self._buffer) - self._bend + self._bstart >= self.maxread:
            # there's enough room in the buffer, but not at the end; shift all
            # data to the beginning of the buffer
            need_shift = True
        else:
            # the buffer isn't big enough to add maxread bytes; try allocating
            # a bigger one
            newsize = 2 * len(self._buffer)
            if newsize > self.maxread * 16:
                newsize = len(self._buffer) + 4 * self.maxread
            if self.maxbuffer is not None:
                newsize = min(newsize, self.maxbuffer)
            if len(self._buffer) < newsize:
                newbuffer = bytearray(newsize)
                newbend = self._bend - self._bstart
                with memoryview(self._buffer) as bufferview, \
                     bufferview[self._bstart:self._bend] as sourceview:
                    newbuffer[0:newbend] = sourceview
                need_shift = False
                del self._buffer[:]
                self._buffer = newbuffer
                self._bstart = 0
                self._bend = newbend
            else:
                # we can't allocate a bigger buffer; shift all data to the
                # beginning of the buffer to maximize usable space
                need_shift = True

        if need_shift and self._bstart != 0:
            newbend = self._bend - self._bstart
            with memoryview(self._buffer) as bufferview, \
                 bufferview[self._bstart:self._bend] as sourceview:
                self._buffer[0:newbend] = sourceview
            self._bstart = 0
            self._bend = newbend

        if len(self._buffer) - self._bend == 0:
            raise BufferFull(
                'buffer has reached its maximum size ({}) but no '
                'match was found'.format(self.maxbuffer)
            )

        rend = min(self._bend + self.maxread, len(self._buffer))
        nread = self._read(rend)
        self._bend = self._bend + nread
        return nread == 0

    def _check_matchers(self, pattern, at_eof, at_timeout):
        # note the (idx, match, offset) for all successful matches
        matches = []
        if pattern:
            with memoryview(self._buffer) as bufferview, \
                 bufferview[self._bstart:self._bend] as searchview:
                for test_idx, test_pattern in enumerate(pattern):
                    test_match, offset = test_pattern(searchview,
                                                      at_eof,
                                                      at_timeout)
                    if test_match is not None:
                        matches.append((test_idx, test_match, offset))
                # matches is a list of (idx, match, offset) triples, so the
                # following returns the first triple at the minimum offset
                best_idx, best_match, _ = min(matches,
                                              key=lambda x: x[2],
                                              default=(None,) * 3)
                if isinstance(best_match, re_Match):
                    # re-calculate the Match object with a copy of the
                    # relevant bytes from searchview
                    with searchview[0:best_match.end()] as matchview:
                        matchbytes = matchview.tobytes()
                    best_match, _ = pattern[best_idx](matchbytes,
                                                      at_eof,
                                                      at_timeout)
                if best_idx is not None:
                    return best_idx, best_match

        # when no explicit patterns match, also check for EOF and TIMEOUT
        # conditions, which trigger exceptions when not explicitly tested
        match = None
        if at_eof:
            match = EOF
        elif at_timeout:
            match = TIMEOUT
        return None, match

    def _expect_loop(self, pattern, timeout):
        self._release_views()

        orig_ffl = None
        deadline = None
        idx, match = None, None
        have_timeout = False
        have_eof = False

        try:
            cur_ffl = fcntl.fcntl(self.fileno, fcntl.F_GETFL)
            if not (cur_ffl & os.O_NONBLOCK):
                fcntl.fcntl(self.fileno, fcntl.F_SETFL,
                            cur_ffl | os.O_NONBLOCK)
                orig_ffl = cur_ffl

            poll = select.poll()
            poll.register(self.fileno, select.POLLIN)

            while match is None:
                now = time.clock_gettime(time.CLOCK_MONOTONIC)
                if deadline is None:
                    if timeout is not None:
                        deadline = now + timeout
                else:
                    if now < deadline:
                        timeout = deadline - now
                    else:
                        timeout = 0
                        have_timeout = True

                if not have_timeout:
                    new_data = bool(poll.poll(timeout))
                    if new_data:
                        try:
                            have_eof = self._append_buffer()
                        except BlockingIOError:
                            new_data = False
                if new_data or have_timeout:
                    idx, match = self._check_matchers(pattern,
                                                      have_eof,
                                                      have_timeout)

            return idx, match

        finally:
            if orig_ffl is not None:
                fcntl.fcntl(self.fileno, fcntl.F_SETFL, orig_ffl)

    def expect(self, pattern, timeout=-1):
        if timeout == -1:
            timeout = self.timeout

        try:
            if isinstance(pattern, (bytes, bytearray, memoryview, re_Pattern)):
                pattern = [pattern]
            pattern = [_Matcher.from_expect_arg(x) for x in pattern]

            idx, match = None, None
            if self._bend > self._bstart:
                idx, match = self._check_matchers(pattern,
                                                  self.match is EOF,
                                                  False)

            if match is None:
                idx, match = self._expect_loop(pattern, timeout)

        except Exception:
            self._update_match_before_after(None)
            raise

        self._update_match_before_after(match)
        if idx is None:
            raise match()
        return idx

    def close(self):
        _ = self.before
        _ = self.after
        self._buffer[:] = b''
        if self.fileno != -1:
            os.close(self.fileno)
            self.fileno = -1
