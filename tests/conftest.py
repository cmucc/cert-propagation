from collections import namedtuple
from datetime import datetime, timedelta, timezone
import os.path

try:
    from importlib.metadata import version as pkg_version
except ImportError:
    pass

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

if 'pkg_version' not in globals():
    try:
        from importlib_metadata import version as pkg_version
    except ImportError:
        pkg_version = lambda x: '0.0.0'

@pytest.fixture(scope='session')
def certificate_helper_per_session():
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
            return dt.strftime('%Y%m%d%H%M%SZ').encode()

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
            is_ca = ('CA:TRUE' if params.is_ca else 'CA:FALSE').encode()
            cert = ssl_crypto.X509()
            cert.set_version(2) # the value 2 represents version 3
            cert.get_subject().commonName = params.subject.encode()
            cert.get_issuer().commonName = params.issuer.encode()
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
                                              cls.get_key_object(key_num)).decode()

        @classmethod
        def get_cert(cls, **kwargs):
            return ssl_crypto.dump_certificate(ssl_crypto.FILETYPE_PEM,
                                               cls.get_cert_object(**kwargs)).decode()

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
