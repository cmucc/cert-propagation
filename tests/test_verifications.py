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
