# Copyright (C) 2024-2026 Keith Allen Bare II
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

from collections import namedtuple
from contextlib import contextmanager
import errno
from datetime import datetime, timedelta, timezone
import locale
import os
import os.path
from threading import Event, Thread
import sys
import time
from unittest.mock import patch

try:
    from importlib.metadata import version as pkg_version
except ImportError:
    try:
        from importlib_metadata import version as pkg_version
    except ImportError:
        def pkg_version(_):
            return '0.0.0'

import OpenSSL.crypto as ssl_crypto
import OpenSSL.SSL as ssl
import pytest

try:
    from cryptography import x509
    from cryptography.hazmat.primitives \
            import serialization as crypto_serdes, hashes as crypto_hashes
    from cryptography.x509.oid import NameOID
except ImportError:
    pass

import cert_receive as cr

@pytest.fixture(scope='session', autouse=True)
def setlocale():
    # Make sure cert_receive determines the system encoding based on the
    # locale configured by the system/user.  Needed because the tests do
    # not call cert_receive.main.
    locale.setlocale(locale.LC_ALL, '')

@pytest.fixture(name='certificate_helper_per_session', scope='session')
def certificate_helper_per_session_fixture():
    datadir = os.path.join(os.path.split(__file__)[0], 'data')
    keys = {}
    CertArgs = namedtuple('CertArgs', ['ca_num', 'intermediate_num', 'key_num'])
    certs = {}

    class CertParams:
        __slots__ = ('is_ca', 'subject', 'pubkey', 'issuer', 'signkey', 'serial')

        def __init__(self):
            self.is_ca = None
            self.subject = None
            self.pubkey = None
            self.issuer = None
            self.signkey = None
            self.serial = None

    def try_int(x):
        try:
            return int(x)
        except ValueError:
            return 0

    py_ssl_version = [try_int(x) for x in pkg_version('pyOpenSSL').split('.')]
    while len(py_ssl_version) < 2:
        py_ssl_version.append(0)
    use_cryptography = py_ssl_version >= [23, 0]

    class CertificateHelper:
        @staticmethod
        def datetime_to_asn1(dt):
            return dt.strftime('%Y%m%d%H%M%SZ').encode(cr.system_encoding())

        @staticmethod
        def get_config():
            if ssl.OPENSSL_VERSION_NUMBER >= 0x10100000:
                return {'openssl_ciphers': 'DEFAULT:@SECLEVEL=0'}
            return {}

        @staticmethod
        def get_key_object(key_num):
            if key_num not in keys:
                keyfile = os.path.join(datadir, 'key{}.pem'.format(key_num))
                with open(keyfile, 'rb') as fd:
                    keydata = fd.read()
                if use_cryptography:
                    key = crypto_serdes.load_pem_private_key(keydata, password=None)
                    key = ssl_crypto.PKey.from_cryptography_key(key)
                else:
                    key = ssl_crypto.load_privatekey(ssl_crypto.FILETYPE_PEM,
                                                     keydata)
                keys[key_num] = key
            return keys[key_num]

        @classmethod
        def _make_cert_ssl_crypto(cls, params):
            #pylint: disable=useless-suppression,no-member; newer versions of
            #        pyOpenSSL drop the X509 APIs, but we detect them and call
            #        _make_cert_cryptography instead
            is_ca = ('CA:TRUE' if params.is_ca else 'CA:FALSE') \
                    .encode(cr.system_encoding())
            cert = ssl_crypto.X509()
            cert.set_version(2) # the value 2 represents version 3
            cert.get_subject().commonName = params.subject.encode(cr.system_encoding())
            cert.get_issuer().commonName = params.issuer.encode(cr.system_encoding())
            now = datetime.now(timezone.utc)
            cert.set_notBefore(cls.datetime_to_asn1(now - timedelta(days=1)))
            cert.set_notAfter(cls.datetime_to_asn1(now + timedelta(days=30)))
            cert.add_extensions([
                ssl_crypto.X509Extension(b'basicConstraints', True, is_ca),
            ])
            cert.set_pubkey(params.pubkey)
            cert.set_serial_number(params.serial)
            cert.sign(params.signkey, 'sha256')
            return cert

        @classmethod
        def _make_cert_cryptography(cls, params):
            pubkey = params.pubkey.to_cryptography_key().public_key()
            signkey = params.signkey.to_cryptography_key()
            builder = x509.CertificateBuilder()
            builder = builder.subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, params.subject),
            ]))
            builder = builder.issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, params.issuer),
            ]))
            now = datetime.now(timezone.utc)
            builder = builder.not_valid_before(now - timedelta(days=1))
            builder = builder.not_valid_after(now + timedelta(days=30))
            builder = builder.add_extension(
                x509.BasicConstraints(ca=params.is_ca, path_length=None),
                critical=True,
            )
            builder = builder.public_key(pubkey)
            builder = builder.serial_number(params.serial)
            cert = builder.sign(private_key=signkey,
                                algorithm=crypto_hashes.SHA256())
            return cert

        @classmethod
        def get_cert_object(cls, ca_num=None, intermediate_num=None, key_num=None):
            cert_args = CertArgs(ca_num, intermediate_num, key_num)
            if cert_args not in certs:
                params = CertParams()
                params.is_ca = key_num is None
                bitvector = [1 if arg is not None else 0 for arg in cert_args]
                if bitvector == [1, 0, 0]:
                    params.subject = 'CA Certificate {}'.format(ca_num)
                    params.pubkey = cls.get_key_object(ca_num)
                    params.issuer = params.subject
                    params.signkey = params.pubkey
                elif bitvector == [1, 1, 0]:
                    params.subject = 'Intermediate Certificate {}'.format(intermediate_num)
                    params.pubkey = cls.get_key_object(intermediate_num)
                    params.issuer = 'CA Certificate {}'.format(ca_num)
                    params.signkey = cls.get_key_object(ca_num)
                elif bitvector == [1, 0, 1]:
                    params.subject = 'CA-signed Certificate {}'.format(key_num)
                    params.pubkey = cls.get_key_object(key_num)
                    params.issuer = 'CA Certificate {}'.format(ca_num)
                    params.signkey = cls.get_key_object(ca_num)
                elif bitvector == [0, 1, 0]:
                    try:
                        issuer_num, subject_num = intermediate_num
                    except ValueError as e:
                        raise ValueError(
                            'Inappropriate arguments. If an intermediate_num '
                            'is provided alone, it must be a sequence of length 2.'
                        ) from e
                    params.subject = 'Intermediate Certificate {}'.format(subject_num)
                    params.pubkey = cls.get_key_object(subject_num)
                    params.issuer = 'Intermediate Certificate {}'.format(issuer_num)
                    params.signkey = cls.get_key_object(issuer_num)
                elif bitvector == [0, 1, 1]:
                    params.subject = 'Intermediate-signed Certificate {}'.format(key_num)
                    params.pubkey = cls.get_key_object(key_num)
                    params.issuer = 'Intermediate Certificate {}'.format(intermediate_num)
                    params.signkey = cls.get_key_object(intermediate_num)
                elif bitvector == [0, 0, 1]:
                    params.subject = 'Self-signed Certificate {}'.format(key_num)
                    params.pubkey = cls.get_key_object(key_num)
                    params.issuer = params.subject
                    params.signkey = params.pubkey
                else:
                    raise ValueError(
                        'Inappropriate arguments. Values must be provided for '
                        'one or two of ca_num, intermediate_num, or key_num.'
                    )
                params.serial = 90000 + (hash(cert_args) % 10000)

                if use_cryptography:
                    cert = cls._make_cert_cryptography(params)
                    cert = ssl_crypto.X509.from_cryptography(cert)
                else:
                    cert = cls._make_cert_ssl_crypto(params)
                certs[cert_args] = cert
            return certs[cert_args]

        @classmethod
        def get_key(cls, key_num):
            return ssl_crypto.dump_privatekey(ssl_crypto.FILETYPE_PEM,
                                              cls.get_key_object(key_num)) \
                   .decode(cr.system_encoding())

        @classmethod
        def get_cert(cls, **kwargs):
            return ssl_crypto.dump_certificate(ssl_crypto.FILETYPE_PEM,
                                               cls.get_cert_object(**kwargs)) \
                   .decode(cr.system_encoding())

    return CertificateHelper

@pytest.fixture(scope='class')
def certificate_helper(request, certificate_helper_per_session):
    for attr_name in dir(certificate_helper_per_session):
        if not attr_name.startswith('_'):
            method = getattr(certificate_helper_per_session, attr_name)
            setattr(request.cls, attr_name, staticmethod(method))

@pytest.fixture(scope='function')
def clear_umask():
    old_umask = os.umask(0o000)
    yield
    os.umask(old_umask)

@pytest.fixture(scope='function')
def noop_privileges():
    with patch('cert_receive.drop_privileges'), \
         patch('cert_receive.reacquire_privileges'):
        yield

@pytest.fixture(scope='function')
def noop_config_check():
    with patch('cert_receive.check_configuration_section') as mock:
        mock.return_value = 'No error', None, None
        yield

@pytest.fixture(name='mock_g_args', scope='function')
def mock_g_args_fixture():
    with patch('cert_receive.g_args') as mock:
        mock.version = False
        mock.ca_file = None
        mock.ca_path = cr.DEFAULT_CA_PATH
        mock.check_config = False
        mock.config_file = cr.DEFAULT_CONFIG_FILE
        mock.receive_timeout = 10
        mock.set_effective_user = 'nobody'
        yield mock

@pytest.fixture(name='override_g_args', scope='function')
def override_g_args_fixture(request, mock_g_args):
    request.instance.override_g_args = mock_g_args
    yield mock_g_args
    del request.instance.override_g_args

@pytest.fixture(scope='function')
def short_receive_timeout(override_g_args):
    override_g_args.receive_timeout = 0.2
    yield override_g_args

def simulated_input_thread(fd, terminate, data, linesep,
                           byte_delay, line_delay, close_at_end_of_data):
    if isinstance(data, (bytes, str)):
        data = [data]

    def do_one_line(line, is_last=False):
        if isinstance(line, str):
            line = line.encode('utf-8')
        if not line and is_last:
            return
        if byte_delay is not None:
            for byte in (bytes((b,)) for b in line):
                written = os.write(fd, byte)
                if written == 0:
                    raise IOError(errno.EPIPE, os.strerror(errno.EPIPE))
                time.sleep(byte_delay)
                if terminate.is_set():
                    return
            if not is_last:
                for byte in (bytes((b,)) for b in linesep):
                    written = os.write(fd, byte)
                    if written == 0:
                        raise IOError(errno.EPIPE, os.strerror(errno.EPIPE))
                    if line_delay is None:
                        time.sleep(byte_delay)
                if line_delay is not None:
                    time.sleep(line_delay)
            return
        if not is_last:
            line = line + linesep
        while line:
            written = os.write(fd, line)
            if written == 0:
                raise IOError(errno.EPIPE, os.strerror(errno.EPIPE))
            line = line[written:]
        if not is_last and line_delay is not None:
            time.sleep(line_delay)

    try:
        itr = iter(data)
        this_line = next(itr)
        for next_line in itr:
            do_one_line(this_line)
            if terminate.is_set():
                break
            this_line = next_line
        else:
            do_one_line(this_line, is_last=True)
    except (IOError, OSError):
        os.close(fd)
    else:
        if close_at_end_of_data:
            os.close(fd)
        terminate.wait()
        if not close_at_end_of_data:
            os.close(fd)

@contextmanager
def simulated_input_manager(data, linesep=b'\n',
                            byte_delay=None, line_delay=None,
                            close_at_end_of_data=True):
    if not isinstance(linesep, bytes):
        linesep = linesep.encode('utf-8')
    pipe_read, pipe_write = os.pipe()
    terminate = Event()
    worker = Thread(target=simulated_input_thread,
                    args=(pipe_write, terminate, data),
                    kwargs={
                        'linesep': linesep,
                        'byte_delay': byte_delay,
                        'line_delay': line_delay,
                        'close_at_end_of_data': close_at_end_of_data
                    })
    try:
        worker.start()
        yield pipe_read
    finally:
        terminate.set()
        worker.join()
        try:
            os.close(pipe_read)
        except (IOError, OSError) as exc:
            if exc.errno != errno.EBADF:
                raise

@pytest.fixture(scope='class')
def simulated_input(request):
    request.cls.simulated_input = staticmethod(simulated_input_manager)
    yield simulated_input_manager
    del request.cls.simulated_input

@contextmanager
def simulated_stdin_manager(data, linesep=b'\n',
                            byte_delay=None, line_delay=None,
                            close_at_end_of_data=True):
    with simulated_input_manager(
            data, linesep=linesep,
            byte_delay=byte_delay, line_delay=line_delay,
            close_at_end_of_data=close_at_end_of_data) as input_fd, \
         patch.object(sys.stdin, 'fileno') as mock:
        mock.return_value = input_fd
        yield

@pytest.fixture(scope='class')
def simulated_stdin(request):
    request.cls.simulated_stdin = staticmethod(simulated_stdin_manager)
    yield simulated_stdin_manager
    del request.cls.simulated_stdin
