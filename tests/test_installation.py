import os
import pytest
import stat
from unittest.mock import patch

import cert_receive as cr

class TestInstallation:
    @staticmethod
    def add_defaults_and_process_config(config):
        for key, value in cr.CFG_DEFAULT_SETTINGS.items():
            if key in config:
                continue
            if key.startswith('verify_'):
                config[key] = False
        with patch('cert_receive.g_args') as mock_args:
            mock_args.ca_file = None
            mock_args.ca_path = None
            mock_args.config_file = 'mock_config.json'
            header, errors, warnings = cr.check_configuration_section('test', config)
        if errors or warnings:
            assert False, '\n'.join(['Expected configuration check to pass without '
                                     'errors or warnings but it reported:\n',
                                     header] +
                                    errors + warnings)

    @pytest.mark.parametrize('what', ['certificate', 'key'])
    def test_write_one_file_basic(self, what, tmp_path):
        config = {
            'certificate_path': str(tmp_path / 'certificate'),
            'key_path': str(tmp_path / 'key'),
        }
        self.add_defaults_and_process_config(config)
        data = ' '.join(['the {}'.format(what)] * 5)
        cr.write_one_file(str(tmp_path / what), data, config, what + '_')
        for check in ['certificate', 'key']:
            path = tmp_path / check
            if check == what:
                assert path.exists()
            else:
                assert not path.exists()
        path = tmp_path / what
        st = path.lstat()
        assert stat.S_ISREG(st.st_mode)
        with open(str(path), 'rt') as fd:
            assert fd.read() == data

    @pytest.mark.usefixtures('clear_umask')
    @pytest.mark.parametrize('what', ['certificate', 'key'])
    def test_write_one_file_perms(self, what, tmp_path):
        config = {
            'certificate_path': str(tmp_path / 'certificate'),
            'certificate_perms': '0640',
            'key_path': str(tmp_path / 'key'),
            'key_perms': '0400',
        }
        self.add_defaults_and_process_config(config)
        path = tmp_path / what
        data = 'some {} data'.format(what)
        cr.write_one_file(str(path), data, config, what + '_')
        assert path.exists()
        st = path.lstat()
        desired_mode = 0o640 if what == 'certificate' else 0o400
        assert stat.S_IMODE(st.st_mode) == desired_mode

    @pytest.mark.usefixtures('clear_umask')
    def test_write_one_file_perms_ignore_umask(self, tmp_path):
        path = tmp_path / 'app.crt'
        config = {
            'certificate_path': str(path),
            'certificate_perms': '0664',
        }
        self.add_defaults_and_process_config(config)
        os.umask(0o077)
        data = 'some other certificate data'
        cr.write_one_file(str(path), data, config, 'certificate_')
        assert path.exists()
        st = path.lstat()
        assert stat.S_IMODE(st.st_mode) == 0o664

    require_root = pytest.mark.skipif(
        os.geteuid() != 0,
        reason='Tests verifying installation with a specific owner or group '
               'typically only work if run under fakeroot, which is preferred, '
               'or as root'
    )

    @require_root
    @pytest.mark.parametrize('what', ['certificate', 'key'])
    def test_write_one_file_uid(self, what, tmp_path):
        config = {
            'certificate_path': str(tmp_path / 'service.crt'),
            'certificate_owner': '#720',
            'key_path': str(tmp_path / 'service.key'),
            'key_owner': '#864',
        }
        self.add_defaults_and_process_config(config)
        path = tmp_path / what
        data = what + ' whatever'
        cr.write_one_file(str(path), data, config, what + '_')
        assert path.exists()
        st = path.lstat()
        desired_owner_uid = 720 if what == 'certificate' else 864
        assert st.st_uid == desired_owner_uid

    @require_root
    @pytest.mark.parametrize('what', ['certificate', 'key'])
    def test_write_one_file_gid(self, what, tmp_path):
        config = {
            'certificate_path': str(tmp_path / 'certificate.pem'),
            'certificate_group': '#40',
            'key_path': str(tmp_path / 'key.pem'),
            'key_group': '#17',
        }
        self.add_defaults_and_process_config(config)
        path = tmp_path / what
        data = 'in reality this would contain a ' + what
        cr.write_one_file(str(path), data, config, what + '_')
        assert path.exists()
        st = path.lstat()
        desired_gid = 40 if what == 'certificate' else 17
        assert st.st_gid == desired_gid
