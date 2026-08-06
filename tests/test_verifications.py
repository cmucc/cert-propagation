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

from datetime import datetime, timedelta, timezone
import subprocess
from unittest.mock import Mock

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
                                          self.get_cert_object(key_num=1),
                                          self.get_key_object(key_num=1))

    def test_verify_certificate_matches_key_positive_2(self):
        # Would raise an exception on mismatch
        cr.verify_certificate_matches_key(self.get_config(),
                                          self.get_cert_object(ca_num=1, key_num=2),
                                          self.get_key_object(key_num=2))

    def test_verify_certificate_matches_key_negative_1(self):
        with pytest.raises(cr.BadCertificateException):
            cr.verify_certificate_matches_key(self.get_config(),
                                              self.get_cert_object(ca_num=2),
                                              self.get_key_object(key_num=1))

    def test_verify_certificate_matches_key_negative_2(self):
        with pytest.raises(cr.BadCertificateException):
            cr.verify_certificate_matches_key(self.get_config(),
                                              self.get_cert_object(ca_num=2, key_num=1),
                                              self.get_key_object(key_num=2))

    # We intentionally test both internal implementations of
    # cr.verify_certificate_issued_by_trusted_ca, so that we always
    # test the fallback that works when when the system has an old
    # pyOpenSSL module.
    foreach_verifier = pytest.mark.parametrize(
        'verifier',
        [
            pytest.param(cr._verify_trust_python, #pylint: disable=protected-access
                         id='python',
                         marks=pytest.mark.skipif(
                             not hasattr(ssl_crypto.X509Store, 'load_locations'),
                             reason=('the available pyOpenSSL module does not '
                                     'allow CA store configuration'))),
            pytest.param(lambda config, cert_objects:
                         #pylint: disable-next=protected-access
                         cr._verify_trust_openssl_subprocess(
                                 config,
                                 [ssl_crypto.dump_certificate(
                                      ssl_crypto.FILETYPE_PEM,
                                      cert_object).decode()
                                 for cert_object in cert_objects]),
                        id='subprocess'),
        ]
    )

    def write_ca_file(self, ca_nums, path):
        path = path / 'CA_bundle.pem'
        cadata = ''.join([self.get_cert(ca_num=ca_num) for ca_num in ca_nums])
        path.write_text(cadata)
        return str(path)

    def write_ca_directory(self, ca_nums, path):
        for ca_num in ca_nums:
            filename = path / 'CA{}.pem'.format(ca_num)
            cadata = self.get_cert(ca_num=ca_num)
            filename.write_text(cadata)
        subprocess.check_call(['c_rehash', '-v', str(path)])
        return str(path)

    @foreach_verifier
    def test_verify_trust_cafile_ca_signed_positive(self, verifier, tmp_path):
        config = self.get_config()
        config['ca_file'] = self.write_ca_file([1, 2], tmp_path)
        # Would raise an exception if trust could not be verified
        verifier(config, [self.get_cert_object(ca_num=1, key_num=2)])
        verifier(config, [self.get_cert_object(ca_num=1, key_num=3)])
        verifier(config, [self.get_cert_object(ca_num=2, key_num=1)])

    @foreach_verifier
    def test_verify_trust_capath_ca_signed_positive(self, verifier, tmp_path):
        config = self.get_config()
        config['ca_path'] = self.write_ca_directory([2, 3], tmp_path)
        # Would raise an exception if trust could not be verified
        verifier(config, [self.get_cert_object(ca_num=2, key_num=1)])
        verifier(config, [self.get_cert_object(ca_num=3, key_num=1)])

    @foreach_verifier
    def test_verify_trust_cafile_negative(self, verifier, tmp_path):
        config = self.get_config()
        config['ca_file'] = self.write_ca_file([3], tmp_path)
        with pytest.raises(cr.BadCertificateException):
            verifier(config, [self.get_cert_object(ca_num=1, key_num=3)])
        with pytest.raises(cr.BadCertificateException):
            verifier(config, [self.get_cert_object(ca_num=2, key_num=1)])

    @foreach_verifier
    def test_verify_trust_capath_negative(self, verifier, tmp_path):
        config = self.get_config()
        config['ca_path'] = self.write_ca_directory([1, 2], tmp_path)
        with pytest.raises(cr.BadCertificateException):
            verifier(config, [self.get_cert_object(ca_num=3, key_num=1)])
        with pytest.raises(cr.BadCertificateException):
            verifier(config, [self.get_cert_object(ca_num=3, key_num=2)])

    @foreach_verifier
    def test_verify_trust_chain_positive_1(self, verifier, tmp_path):
        config = self.get_config()
        config['ca_file'] = self.write_ca_file([2], tmp_path)
        # Would raise an exception if trust could not be verified
        verifier(config,
                 [self.get_cert_object(intermediate_num=3, key_num=1),
                  self.get_cert_object(ca_num=2, intermediate_num=3)])

    @foreach_verifier
    def test_verify_trust_chain_positive_2(self, verifier, tmp_path):
        config = self.get_config()
        config['ca_path'] = self.write_ca_directory([1], tmp_path)
        # Would raise an exception if trust could not be verified
        verifier(config,
                 [self.get_cert_object(intermediate_num=2, key_num=3),
                  self.get_cert_object(intermediate_num=(4, 2)),
                  self.get_cert_object(ca_num=1, intermediate_num=4)])

    @foreach_verifier
    def test_verify_trust_chain_negative_1(self, verifier):
        with pytest.raises(cr.BadCertificateException):
            verifier(self.get_config(),
                     [self.get_cert_object(intermediate_num=1, key_num=3),
                      self.get_cert_object(ca_num=4, intermediate_num=1)])

    @foreach_verifier
    def test_verify_trust_chain_negative_2(self, verifier, tmp_path):
        # Same as test_verify_trust_chain_positive_2, but one of the
        # intermediate certificates is missing.
        config = self.get_config()
        config['ca_file'] = self.write_ca_file([1], tmp_path)
        with pytest.raises(cr.BadCertificateException):
            verifier(config,
                     [self.get_cert_object(intermediate_num=2, key_num=3),
                      self.get_cert_object(ca_num=1, intermediate_num=4)])

    @foreach_verifier
    def test_verify_trust_chain_negative_3(self, verifier, tmp_path):
        # As above, but the other intermediate certificate is missing.
        config = self.get_config()
        config['ca_file'] = self.write_ca_file([1], tmp_path)
        with pytest.raises(cr.BadCertificateException):
            verifier(config,
                     [self.get_cert_object(intermediate_num=2, key_num=3),
                      self.get_cert_object(intermediate_num=(4, 2))])

    @classmethod
    def get_no_verify_config(cls):
        config = cls.get_config()
        for key in cr.CFG_VALID_SETTINGS:
            if key.startswith('verify_'):
                config[key] = False
        config['bundle_key'] = False
        config['bundle_intermediate'] = False
        config['intermediate_path'] = '/bogus1'
        config['key_path'] = '/bogus2'
        return config

    def test_verifications_disabled(self):
        config = self.get_no_verify_config()
        # Would raise an exception on failure
        cr.perform_verifications(config,
                                 ['whiskey tango foxtrot', 'oscar kilo'],
                                 'SNAFU')

    def test_verify_loadable_positive(self):
        config = self.get_no_verify_config()
        config['verify_loadable'] = True
        # Would raise an exception on failure
        cr.perform_verifications(config,
                                 [self.get_cert(key_num=3)],
                                 self.get_key(key_num=1))

    def test_verify_loadable_bad_certificate(self):
        config = self.get_no_verify_config()
        config['verify_loadable'] = True
        with pytest.raises(cr.BadCertificateException):
            cr.perform_verifications(config,
                                     ['Just some garbage!\n'],
                                     self.get_key(key_num=2))

    def test_verify_loadable_bad_key(self):
        config = self.get_no_verify_config()
        config['verify_loadable'] = True
        with pytest.raises(cr.BadKeyException):
            cr.perform_verifications(config,
                                     [self.get_cert(key_num=1)],
                                     'Could this unlock anything?\n')

    @pytest.mark.usefixtures('noop_privileges')
    def test_verify_existing_key_and_intermediates(self, tmp_path):
        config = self.get_config()
        config['if_no_intermediate'] = 'preserve'
        config['verify_subject_cn'] = False

        config['ca_file'] = self.write_ca_file([3], tmp_path)
        key_path = tmp_path / 'key.pem'
        key_path.write_text(self.get_key(key_num=4))
        config['key_path'] = str(key_path)
        chain_path = tmp_path / 'chain.pem'
        chain_path.write_text(self.get_cert(ca_num=3, intermediate_num=2))
        config['intermediate_path'] = str(chain_path)

        for setting, value in cr.CFG_DEFAULT_SETTINGS.items():
            config.setdefault(setting, value)
        cr.perform_verifications(config,
                                 [self.get_cert(intermediate_num=2, key_num=4)],
                                 None)

    @pytest.mark.usefixtures('noop_privileges')
    @pytest.mark.parametrize('nil_type', ['empty', 'missing'])
    def test_verify_existing_key_and_nil_intermediates(self, nil_type, tmp_path):
        config = self.get_config()
        config['if_no_intermediate'] = 'preserve'
        config['verify_subject_cn'] = False

        config['ca_path'] = self.write_ca_directory([2], tmp_path)
        key_path = tmp_path / 'privkey.pem'
        key_path.write_text(self.get_key(key_num=1))
        config['key_path'] = str(key_path)
        chain_path = tmp_path / 'chain.pem'
        if nil_type == 'empty':
            chain_path.write_text('')
        config['intermediate_path'] = str(chain_path)

        for setting, value in cr.CFG_DEFAULT_SETTINGS.items():
            config.setdefault(setting, value)
        cr.perform_verifications(config,
                                 [self.get_cert(ca_num=2, key_num=1)],
                                 None)

    @pytest.mark.usefixtures('noop_privileges')
    def test_verify_existing_key_negative(self, tmp_path):
        config = self.get_config()
        config['verify_subject_cn'] = False

        config['ca_file'] = self.write_ca_file([1], tmp_path)
        key_path = tmp_path / 'key.pem'
        key_path.write_text(self.get_key(key_num=2))
        config['key_path'] = str(key_path)

        for setting, value in cr.CFG_DEFAULT_SETTINGS.items():
            config.setdefault(setting, value)
        with pytest.raises(cr.BadCertificateException):
            cr.perform_verifications(config,
                                     [self.get_cert(ca_num=1, key_num=3)],
                                     None)

    @pytest.mark.usefixtures('noop_privileges')
    def test_verify_existing_chain_negative_wrong(self, tmp_path):
        config = self.get_config()
        config['if_no_intermediate'] = 'preserve'
        config['verify_subject_cn'] = False

        config['ca_path'] = self.write_ca_directory([2], tmp_path)
        config['key_path'] = str(tmp_path / 'key.pem')
        chain_path = tmp_path / 'chain.pem'
        chain_path.write_text(self.get_cert(ca_num=2, intermediate_num=4))
        config['intermediate_path'] = str(chain_path)

        for setting, value in cr.CFG_DEFAULT_SETTINGS.items():
            config.setdefault(setting, value)
        with pytest.raises(cr.BadCertificateException):
            cr.perform_verifications(config,
                                     [self.get_cert(intermediate_num=1, key_num=3)],
                                     self.get_key(key_num=2))

class TestFindPemBlock:
    foreach_whitespace = pytest.mark.parametrize(
        'whitespace',
        ['', '\n', '\r\n', '\r', ' ', '\t', '\v', '\f'],
        ids=['none', 'lf', 'crlf', 'cr', 'space', 'tab', 'vtab', 'formfeed'],
    )

    @foreach_whitespace
    @pytest.mark.parametrize('what', ['certificate', 'key'])
    def test_vanilla_1(self, what, whitespace):
        data = [
            '-----BEGIN CERTIFICATE-----',
            'alpha',
            '-----END CERTIFICATE-----',
            '-----BEGIN PRIVATE KEY-----',
            'bravo',
            '-----END PRIVATE KEY-----',
            '-----BEGIN CERTIFICATE-----',
            'charlie',
            '-----END CERTIFICATE-----',
        ]
        if whitespace in ('\n', '\r\n', '\r'):
            data.append('')
        data = whitespace.join(data)

        want_cert = what == 'certificate'
        if want_cert:
            labels = cr.CERTIFICATE_LABELS
        else:
            labels = cr.KEY_LABELS

        pos = 0
        items = []
        while pos != -1:
            item, pos = cr.find_pem_block(data, labels, pos=pos)
            if item is not None:
                items.append(item)

        assert [item.startswith('-----BEGIN ') for item in items] == [True] * len(items)
        assert [(whitespace + '-----END ') in item for item in items] == [True] * len(items)

        if want_cert:
            assert len(items) == 2
            assert ['alpha' in item for item in items] == [True, False]
            assert ['bravo' in item for item in items] == [False, False]
            assert ['charlie' in item for item in items] == [False, True]
        else:
            assert len(items) == 1
            assert 'alpha' not in items[0]
            assert 'bravo' in items[0]
            assert 'charlie' not in items[0]

        assert ['CERTIFICATE' in item for item in items] == [want_cert] * len(items)
        assert ['KEY' in item for item in items] == [not want_cert] * len(items)

    @foreach_whitespace
    def test_vanilla_2(self, whitespace):
        data = [
            '-----BEGIN X509 CERTIFICATE-----',
            'achievement',
            '-----END X509 CERTIFICATE-----',
            '-----BEGIN PRIVATE KEY-----',
            'skeleton',
            '-----END PRIVATE KEY-----',
            '-----BEGIN RSA PRIVATE KEY-----',
            'car',
            '-----END RSA PRIVATE KEY-----',
        ]
        if whitespace in ('\n', '\r\n', '\r'):
            data.append('')
        data = whitespace.join(data)

        item, pos = cr.find_pem_block(data, cr.KEY_LABELS)
        assert item is not None
        assert pos != -1
        assert item.startswith('-----BEGIN PRIVATE KEY-----')
        assert '-----END PRIVATE KEY-----' in item
        assert 'skeleton' in item
        assert [x in item for x in ['CERTIFICATE', 'RSA', 'achievement', 'car']] == [False] * 4

    def test_wrong_dashes(self):
        data = '\n'.join([
            '-------BEGIN PRIVATE KEY-------',
            'horrible',
            '-------END PRIVATE KEY-------',
            '-----BEGIN PRIVATE KEY-----',
            'excellent',
            '-----END PRIVATE KEY-----',
            '------BEGIN PRIVATE KEY-----',
            'terrible',
            '------END PRIVATE KEY-----',
            '----------BEGIN PRIVATE KEY----------',
            'no good',
            '----------END PRIVATE KEY----------',
            '',
        ])

        pos = 0
        items = []
        while pos != -1:
            item, pos = cr.find_pem_block(data, cr.KEY_LABELS, pos=pos)
            if item is not None:
                items.append(item)

        assert len(items) == 1
        item = items[0]
        assert item.startswith('-----BEGIN PRIVATE KEY-----\n')
        assert '\n-----END PRIVATE KEY-----' in item
        assert 'excellent' in item
        assert [x in item for x in ['horrible', 'terrible', 'no good']] == [False] * 3

    def test_spurious_delimiters(self):
        data = '\r\n'.join([
            '-----BEGIN PRIVATE KEY-----',
            'blah blah blah',
            '-----BEGIN CERTIFICATE-----',
            'blah blah blah',
            '-----BEGIN CERTIFICATE-----',
            'first',
            '-----END CERTIFICATE-----',
            'blah blah blah',
            '-----END PRIVATE KEY-----',
            'blah blah blah',
            '-----END CERTIFICATE-----',
            '-----BEGIN CERTIFICATE-----',
            'second',
            '-----END CERTIFICATE-----',
            ''
        ])

        pos = 0
        items = []
        while pos != -1:
            item, pos = cr.find_pem_block(data, cr.CERTIFICATE_LABELS, pos=pos)
            if item is not None:
                items.append(item)

        assert len(items) == 2
        assert [item.startswith('-----BEGIN CERTIFICATE-----\r\n') for item in items] == [True, True]
        assert ['\r\n-----END CERTIFICATE-----' in item for item in items] == [True, True]
        assert 'first' in items[0]
        assert 'second' in items[1]
        assert ['PRIVATE' in item for item in items] == [False, False]
        assert ['blah' in item for item in items] == [False, False]

    @pytest.mark.parametrize('what', ['wrong', 'variant'])
    def test_delimiter_mismatch(self, what):
        data = [
            '-----BEGIN X.509 CERTIFICATE-----',
            'HERE',
        ]
        if what == 'wrong':
            data.append('-----END PRIVATE KEY-----')
        else:
            data.append('-----END TRUSTED CERTIFICATE-----')
        data.append('')
        data = '\r'.join(data)

        item, pos = cr.find_pem_block(data, cr.CERTIFICATE_LABELS)
        assert item is None
        assert pos == -1

    def test_wrong_then_right_dashes(self):
        data = '\n'.join([
            '------BEGIN TRUSTED CERTIFICATE-----BEGIN CERTIFICATE-----',
            'tomfoolery!',
            '-----END CERTIFICATE-----',
            '',
        ])

        item, pos = cr.find_pem_block(data, cr.CERTIFICATE_LABELS)
        assert item is not None
        assert pos != -1
        assert item.startswith('-----BEGIN CERTIFICATE-----\n')
        assert '\n-----END CERTIFICATE-----' in item
        assert 'tomfoolery!' in item
        assert 'TRUSTED' not in item

    def test_right_then_wrong_dashes(self):
        data = '\r\n'.join([
            '-----BEGIN RSA PRIVATE KEY------BEGIN PRIVATE KEY-----',
            'no, no, no!',
            '-----END PRIVATE KEY-----',
            ''
        ])

        item, pos = cr.find_pem_block(data, cr.KEY_LABELS)
        assert item is None
        assert pos == -1
