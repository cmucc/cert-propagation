from datetime import datetime, timedelta
import pytest
from unittest.mock import Mock

import cert_receive as cr

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

    @staticmethod
    def datetime_to_asn1(dt):
        return dt.strftime('%Y%m%d%H%M%SZ').encode()

    def test_verify_certificate_dates_positive(self):
        to_asn1 = self.datetime_to_asn1
        now = datetime.utcnow()
        certs = [Mock() for _ in range(0, 2)]
        certs[0].get_notBefore.return_value = to_asn1(now - timedelta(days=20))
        certs[0].get_notAfter.return_value = to_asn1(now + timedelta(days=70))
        certs[1].get_notBefore.return_value = to_asn1(now - timedelta(days=3*365))
        certs[1].get_notAfter.return_value = to_asn1(now + timedelta(days=1*365))

        # Would raise an exception if the chain were considered invalid
        cr.verify_certificate_dates(certs)

    def test_verify_certificate_dates_expired_app_cert(self):
        to_asn1 = self.datetime_to_asn1
        now = datetime.utcnow()
        certs = [Mock() for _ in range(0, 2)]
        certs[0].get_notBefore.return_value = b'20200717000000Z'
        certs[0].get_notAfter.return_value = b'20201014235959Z'
        certs[1].get_notBefore.return_value = to_asn1(now - timedelta(days=2*365))
        certs[1].get_notAfter.return_value = to_asn1(now + timedelta(days=6*365))

        with pytest.raises(cr.BadCertificateException):
            cr.verify_certificate_dates(certs)

    def test_verify_certificate_dates_future_app_cert(self):
        to_asn1 = self.datetime_to_asn1
        now = datetime.utcnow()
        certs = [Mock() for _ in range(0, 2)]
        certs[0].get_notBefore.return_value = to_asn1(now + timedelta(seconds=4*60*60))
        certs[0].get_notAfter.return_value = to_asn1(now + timedelta(days=90))
        certs[1].get_notBefore.return_value = to_asn1(now - timedelta(days=1*365))
        certs[1].get_notAfter.return_value = to_asn1(now + timedelta(days=7*365))

        with pytest.raises(cr.BadCertificateException):
            cr.verify_certificate_dates(certs)

    def test_verify_certificate_dates_expired_intermediate_cert(self):
        to_asn1 = self.datetime_to_asn1
        now = datetime.utcnow()
        certs = [Mock() for _ in range(0, 2)]
        certs[0].get_notBefore.return_value = to_asn1(now - timedelta(days=13))
        certs[0].get_notAfter.return_value = to_asn1(now + timedelta(days=77))
        certs[1].get_notBefore.return_value = b'20051002000000Z'
        certs[1].get_notAfter.return_value = b'20170928235959Z'

        with pytest.raises(cr.BadCertificateException):
            cr.verify_certificate_dates(certs)

    def test_verify_certificate_dates_future_intermediate_cert(self):
        to_asn1 = self.datetime_to_asn1
        now = datetime.utcnow()
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
