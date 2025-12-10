from datetime import datetime, timedelta, timezone
import subprocess
from unittest.mock import Mock

from cryptography.hazmat.primitives import serialization as crypto_serdes
import OpenSSL.crypto as ssl_crypto
import pytest

import cert_receive as cr

@pytest.mark.usefixtures('certificate_helper')
class TestVerifications:
    def test_verify_certificate_chain_positive(self):
        chain = [Mock() for _ in range(0, 2)]
        chain[0].get_subject.return_value = 'fake app'
        chain[0].get_issuer.return_value = 'fake intermediate'
        chain[1].get_subject.return_value = 'fake intermediate'
        chain[1].get_issuer.return_value = 'fake CA'

        # Would raise an exception if the chain were considered invalid
        cr.verify_certificate_chain(chain)

    def test_verify_certificate_chain_negative_1(self):
        chain = [Mock() for _ in range(0, 2)]
        chain[0].get_subject.return_value = 'fake app'
        chain[0].get_issuer.return_value = 'bravo intermediate'
        chain[1].get_subject.return_value = 'alpha intermediate'
        chain[1].get_issuer.return_value = 'fake CA'

        with pytest.raises(cr.BadCertificateException):
            cr.verify_certificate_chain(chain)

    def test_verify_certificate_chain_negative_2(self):
        chain = [Mock() for _ in range(0, 3)]
        chain[0].get_subject.return_value = 'fake app'
        chain[0].get_issuer.return_value = 'echo intermediate'
        chain[1].get_subject.return_value = 'echo intermediate'
        chain[1].get_issuer.return_value = 'delta intermediate'
        chain[2].get_subject.return_value = 'charlie intermediate'
        chain[2].get_issuer.return_value = 'fake CA'

        with pytest.raises(cr.BadCertificateException):
            cr.verify_certificate_chain(chain)

    def test_verify_certificate_chain_negative_3(self):
        chain = [Mock() for _ in range(0, 3)]
        chain[0].get_subject.return_value = 'fake app'
        chain[0].get_issuer.return_value = 'hotel intermediate'
        chain[1].get_subject.return_value = 'golf intermediate'
        chain[1].get_issuer.return_value = 'foxtrot intermediate'
        chain[2].get_subject.return_value = 'foxtrot intermediate'
        chain[2].get_issuer.return_value = 'fake CA'

        with pytest.raises(cr.BadCertificateException):
            cr.verify_certificate_chain(chain)

    def test_verify_certificate_dates_positive(self):
        to_asn1 = self.datetime_to_asn1
        now = datetime.now(timezone.utc)
        certs = [Mock() for _ in range(0, 2)]
        certs[0].get_notBefore.return_value = to_asn1(now - timedelta(days=20))
        certs[0].get_notAfter.return_value = to_asn1(now + timedelta(days=70))
        certs[1].get_notBefore.return_value = to_asn1(now - timedelta(days=3*365))
        certs[1].get_notAfter.return_value = to_asn1(now + timedelta(days=1*365))

        # Would raise an exception if the chain were considered invalid
        cr.verify_certificate_dates(certs)

    def test_verify_certificate_dates_expired_app_cert(self):
        to_asn1 = self.datetime_to_asn1
        now = datetime.now(timezone.utc)
        certs = [Mock() for _ in range(0, 2)]
        certs[0].get_notBefore.return_value = b'20200717000000Z'
        certs[0].get_notAfter.return_value = b'20201014235959Z'
        certs[1].get_notBefore.return_value = to_asn1(now - timedelta(days=2*365))
        certs[1].get_notAfter.return_value = to_asn1(now + timedelta(days=6*365))

        with pytest.raises(cr.BadCertificateException):
            cr.verify_certificate_dates(certs)

    def test_verify_certificate_dates_future_app_cert(self):
        to_asn1 = self.datetime_to_asn1
        now = datetime.now(timezone.utc)
        certs = [Mock() for _ in range(0, 2)]
        certs[0].get_notBefore.return_value = to_asn1(now + timedelta(seconds=4*60*60))
        certs[0].get_notAfter.return_value = to_asn1(now + timedelta(days=90))
        certs[1].get_notBefore.return_value = to_asn1(now - timedelta(days=1*365))
        certs[1].get_notAfter.return_value = to_asn1(now + timedelta(days=7*365))

        with pytest.raises(cr.BadCertificateException):
            cr.verify_certificate_dates(certs)

    def test_verify_certificate_dates_expired_intermediate_cert(self):
        to_asn1 = self.datetime_to_asn1
        now = datetime.now(timezone.utc)
        certs = [Mock() for _ in range(0, 2)]
        certs[0].get_notBefore.return_value = to_asn1(now - timedelta(days=13))
        certs[0].get_notAfter.return_value = to_asn1(now + timedelta(days=77))
        certs[1].get_notBefore.return_value = b'20051002000000Z'
        certs[1].get_notAfter.return_value = b'20170928235959Z'

        with pytest.raises(cr.BadCertificateException):
            cr.verify_certificate_dates(certs)

    def test_verify_certificate_dates_future_intermediate_cert(self):
        to_asn1 = self.datetime_to_asn1
        now = datetime.now(timezone.utc)
        certs = [Mock() for _ in range(0, 2)]
        certs[0].get_notBefore.return_value = to_asn1(now - timedelta(days=88))
        certs[0].get_notAfter.return_value = to_asn1(now + timedelta(days=2))
        certs[1].get_notBefore.return_value = to_asn1(now + timedelta(days=11))
        certs[1].get_notAfter.return_value = to_asn1(now + timedelta(days=11+(8*365)))

        with pytest.raises(cr.BadCertificateException):
            cr.verify_certificate_dates(certs)

    def test_verify_certificate_subject_cn_positive(self):
        dn = [(b'C', b'US'), (b'ST', b'Pennsylvania'), (b'L', b'Cranberry Twp'),
              (b'O', 'Cranberry Melon College'), (b'OU', 'Confection Club'),
              (b'CN', b'candy.cranmel.college')]
        cert = Mock()
        cert.get_subject.return_value.get_components.return_value = dn

        # Would raise an exception if the CN was considered a mismatch
        cr.verify_certificate_subject_cn(cert, 'candy.cranmel.college')

    def test_verify_certificate_subject_cn_negative(self):
        dn = [(b'OU', 'Robot Fanclub'), (b'CN', b'Evil Robot')]
        cert = Mock()
        cert.get_subject.return_value.get_components.return_value = dn

        with pytest.raises(cr.BadCertificateException):
            cr.verify_certificate_subject_cn(cert, 'Friendly Robot')

    def test_verify_certificate_matches_key_positive_1(self):
        # Would raise an exception on mismatch
        cr.verify_certificate_matches_key(self.get_config(),
                                          self.get_cert(key_num=1),
                                          self.get_key(key_num=1))

    def test_verify_certificate_matches_key_positive_2(self):
        # Would raise an exception on mismatch
        cr.verify_certificate_matches_key(self.get_config(),
                                          self.get_cert(ca_num=1, key_num=2),
                                          self.get_key(key_num=2))

    def test_verify_certificate_matches_key_negative_1(self):
        with pytest.raises(cr.BadCertificateException):
            cr.verify_certificate_matches_key(self.get_config(),
                                              self.get_cert(ca_num=2),
                                              self.get_key(key_num=1))

    def test_verify_certificate_matches_key_negative_2(self):
        with pytest.raises(cr.BadCertificateException):
            cr.verify_certificate_matches_key(self.get_config(),
                                              self.get_cert(ca_num=2, key_num=1),
                                              self.get_key(key_num=2))

    foreach_verifier = pytest.mark.parametrize(
        'verifier',
        [
            pytest.param(lambda config, cert_objects:
                             cr._verify_trust_python(
                                 config,
                                 [ssl_crypto.X509.from_cryptography(cert_object)
                                  for cert_object in cert_objects]),
                         id='python',
                         marks=pytest.mark.skipif(
                             not hasattr(ssl_crypto.X509Store, 'load_locations'),
                             reason=('the available pyOpenSSL module does not '
                                     'allow CA store configuration'))),
            pytest.param(lambda config, cert_objects:
                             cr._verify_trust_openssl_subprocess(
                                 config,
                                 [cert_object.public_bytes(
                                      crypto_serdes.Encoding.PEM).decode()
                                  for cert_object in cert_objects]),
                        id='subprocess'),
        ]
    )

    def write_ca_file(self, ca_nums, path):
        path = path / 'CA_bundle.pem'
        cadata = b''.join([self.get_cert(ca_num=ca_num).
                           public_bytes(crypto_serdes.Encoding.PEM)
                           for ca_num in ca_nums])
        with open(str(path), 'wb') as fd:
            fd.write(cadata)
        return str(path)

    def write_ca_directory(self, ca_nums, path):
        for ca_num in ca_nums:
            filename = path / 'CA{}.pem'.format(ca_num)
            cadata = self.get_cert(ca_num=ca_num). \
                     public_bytes(crypto_serdes.Encoding.PEM)
            with open(str(filename), 'wb') as fd:
                fd.write(cadata)
        subprocess.check_call(['c_rehash', '-v', str(path)])
        return str(path)

    @foreach_verifier
    def test_verify_trust_cafile_ca_signed_positive(self, verifier, tmp_path):
        config = self.get_config()
        config['ca_file'] = self.write_ca_file([1, 2], tmp_path)
        # Would raise an exception if trust could not be verified
        verifier(config, [self.get_cert(ca_num=1, key_num=2)])
        verifier(config, [self.get_cert(ca_num=1, key_num=3)])
        verifier(config, [self.get_cert(ca_num=2, key_num=1)])

    @foreach_verifier
    def test_verify_trust_capath_ca_signed_positive(self, verifier, tmp_path):
        config = self.get_config()
        config['ca_path'] = self.write_ca_directory([2, 3], tmp_path)
        # Would raise an exception if trust could not be verified
        verifier(config, [self.get_cert(ca_num=2, key_num=1)])
        verifier(config, [self.get_cert(ca_num=3, key_num=1)])

    @foreach_verifier
    def test_verify_trust_cafile_negative(self, verifier, tmp_path):
        config = self.get_config()
        config['ca_file'] = self.write_ca_file([3], tmp_path)
        with pytest.raises(cr.BadCertificateException):
            verifier(config, [self.get_cert(ca_num=1, key_num=3)])
        with pytest.raises(cr.BadCertificateException):
            verifier(config, [self.get_cert(ca_num=2, key_num=1)])

    @foreach_verifier
    def test_verify_trust_capath_negative(self, verifier, tmp_path):
        config = self.get_config()
        config['ca_path'] = self.write_ca_directory([1, 2], tmp_path)
        with pytest.raises(cr.BadCertificateException):
            verifier(config, [self.get_cert(ca_num=3, key_num=1)])
        with pytest.raises(cr.BadCertificateException):
            verifier(config, [self.get_cert(ca_num=3, key_num=2)])

    @foreach_verifier
    def test_verify_trust_chain_positive_1(self, verifier, tmp_path):
        config = self.get_config()
        config['ca_file'] = self.write_ca_file([2], tmp_path)
        # Would raise an exception if trust could not be verified
        verifier(config,
                 [self.get_cert(intermediate_num=3, key_num=1),
                  self.get_cert(ca_num=2, intermediate_num=3)])

    @foreach_verifier
    def test_verify_trust_chain_positive_2(self, verifier, tmp_path):
        config = self.get_config()
        config['ca_path'] = self.write_ca_directory([1], tmp_path)
        # Would raise an exception if trust could not be verified
        verifier(config,
                 [self.get_cert(intermediate_num=2, key_num=3),
                  self.get_cert(intermediate_num=(4, 2)),
                  self.get_cert(ca_num=1, intermediate_num=4)])

    @foreach_verifier
    def test_verify_trust_chain_negative_1(self, verifier):
        with pytest.raises(cr.BadCertificateException):
            verifier(self.get_config(),
                     [self.get_cert(intermediate_num=1, key_num=3),
                      self.get_cert(ca_num=4, intermediate_num=1)])

    @foreach_verifier
    def test_verify_trust_chain_negative_2(self, verifier, tmp_path):
        # Same as test_verify_trust_chain_positive_2, but one of the
        # intermediate certificates is missing.
        config = self.get_config()
        config['ca_file'] = self.write_ca_file([1], tmp_path)
        with pytest.raises(cr.BadCertificateException):
            verifier(config,
                     [self.get_cert(intermediate_num=2, key_num=3),
                      self.get_cert(ca_num=1, intermediate_num=4)])

    @foreach_verifier
    def test_verify_trust_chain_negative_3(self, verifier, tmp_path):
        # As above, but the other intermediate certificate is missing.
        config = self.get_config()
        config['ca_file'] = self.write_ca_file([1], tmp_path)
        with pytest.raises(cr.BadCertificateException):
            verifier(config,
                     [self.get_cert(intermediate_num=2, key_num=3),
                      self.get_cert(intermediate_num=(4, 2))])
