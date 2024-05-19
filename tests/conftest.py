from collections import namedtuple
from datetime import datetime, timedelta
import OpenSSL.crypto as ssl_crypto
import os.path
import pytest

@pytest.fixture(scope='session')
def certificate_helper_per_session():
    datadir = os.path.join(os.path.split(__file__)[0], 'data')
    keys = {}
    CertArgs = namedtuple('CertArgs', ['ca_num', 'intermediate_num', 'key_num'])
    certs = {}

    class CertificateHelper:
        @staticmethod
        def datetime_to_asn1(dt):
            return dt.strftime('%Y%m%d%H%M%SZ').encode()

        @staticmethod
        def get_config():
            return {'openssl_ciphers': 'DEFAULT:@SECLEVEL=0'}

        @staticmethod
        def get_key(key_num):
            if key_num not in keys:
                keyfile = os.path.join(datadir, 'key{}.pem'.format(key_num))
                with open(keyfile, 'rb') as fd:
                    keydata = fd.read()
                key = ssl_crypto.load_privatekey(ssl_crypto.FILETYPE_PEM,
                                                 keydata)
                keys[key_num] = key
            return keys[key_num]

        @classmethod
        def get_cert(cls, ca_num=None, intermediate_num=None, key_num=None):
            cert_args = CertArgs(ca_num, intermediate_num, key_num)
            if cert_args not in certs:
                bitvector = [1 if arg is not None else 0 for arg in cert_args]
                if bitvector == [1, 0, 0]:
                    is_ca = 'CA:TRUE'
                    subject = 'CA Certificate {}'.format(ca_num)
                    pubkey = cls.get_key(ca_num)
                    issuer = subject
                    signkey = pubkey
                elif bitvector == [1, 1, 0]:
                    is_ca = 'CA:FALSE'
                    subject = 'Intermediate Certificate {}'.format(intermediate_num)
                    pubkey = cls.get_key(intermediate_num)
                    issuer = 'CA Certificate {}'.format(ca_num)
                    signkey = cls.get_key(ca_num)
                elif bitvector == [1, 0, 1]:
                    is_ca = 'CA:FALSE'
                    subject = 'CA-signed Certificate {}'.format(key_num)
                    pubkey = cls.get_key(key_num)
                    issuer = 'CA Certificate {}'.format(ca_num)
                    signkey = cls.get_key(ca_num)
                elif bitvector == [0, 1, 0]:
                    try:
                        issuer_num, subject_num = intermediate_num
                    except ValueError as e:
                        raise ValueError(
                            'Inappropriate arguments. If an intermediate_num '
                            'is provided alone, it must be a sequence of length 2.'
                        ) from e
                    is_ca = 'CA:FALSE'
                    subject = 'Intermediate Certificate {}'.format(subject_num)
                    pubkey = cls.get_key(subject_num)
                    issuer = 'Intermediate Certificate {}'.format(issuer_num)
                    signkey = cls.get_key(issuer_num)
                elif bitvector == [0, 1, 1]:
                    is_ca = 'CA:FALSE'
                    subject = 'Intermediate-signed Certificate {}'.format(key_num)
                    pubkey = cls.get_key(key_num)
                    issuer = 'Intermediate Certificate {}'.format(intermediate_num)
                    signkey = cls.get_key(intermediate_num)
                elif bitvector == [0, 0, 1]:
                    is_ca = 'CA:FALSE'
                    subject = 'Self-signed Certificate {}'.format(key_num)
                    pubkey = cls.get_key(key_num)
                    issuer = subject
                    signkey = pubkey
                else:
                    raise ValueError(
                        'Inappropriate arguments. Values must be provided for '
                        'one or two of ca_num, intermediate_num, or key_num.'
                    )

                cert = ssl_crypto.X509()
                cert.set_version(2) # the value 2 represents version 3
                cert.get_subject().commonName = subject.encode()
                cert.get_issuer().commonName = issuer.encode()
                now = datetime.utcnow()
                cert.set_notBefore(cls.datetime_to_asn1(now - timedelta(days=1)))
                cert.set_notAfter(cls.datetime_to_asn1(now + timedelta(days=30)))
                cert.add_extensions([
                    ssl_crypto.X509Extension(b'basicConstraints',
                                             True,
                                             is_ca.encode()),
                ])
                cert.set_pubkey(pubkey)
                cert.set_serial_number(90000 + (hash(cert_args) % 10000))
                cert.sign(signkey, 'sha256')
                certs[cert_args] = cert
            return certs[cert_args]

    return CertificateHelper

@pytest.fixture(scope='class')
def certificate_helper(request, certificate_helper_per_session):
    for attr_name in dir(certificate_helper_per_session):
        if not attr_name.startswith('_'):
            method = getattr(certificate_helper_per_session, attr_name)
            setattr(request.cls, attr_name, staticmethod(method))
