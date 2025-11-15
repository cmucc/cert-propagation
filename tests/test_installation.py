import grp
import os
from pathlib import Path
import pwd
import pytest
import re
import stat
import time
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
        assert path.read_text() == data

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
    def test_write_one_file_user_name(self, tmp_path):
        # Hopefully one of these will exist on any system.
        for user_name in ['daemon', 'bin', 'man', 'games']:
            try:
                pwent = pwd.getpwnam(user_name)
                uid = pwent.pw_uid
            except KeyError:
                pass
        else:
            pytest.mark.xfail('Could not find a user name to test with')
        path = tmp_path / 'my_certificate.pem'
        config = {
            'certificate_path': str(path),
            'certificate_owner': user_name,
        }
        self.add_defaults_and_process_config(config)
        data = 'this would normally be a PEM-encoded certificate'
        cr.write_one_file(str(path), data, config, 'certificate_')
        assert path.exists()
        assert path.owner() == user_name
        st = path.lstat()
        assert st.st_uid == uid

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

    @require_root
    def test_write_one_file_group_name(self, tmp_path):
        # Hopefully one of these will exist on any system.
        for group_name in ['adm', 'staff', 'mail']:
            try:
                grent = grp.getgrnam(group_name)
                gid = grent.gr_gid
            except KeyError:
                pass
        else:
            pytest.mark.xfail('Could not find a group name to test with')
        path = tmp_path / 'my_private_key.pem'
        config = {
            'certificate_path': 'dummy',
            'key_path': str(path),
            'key_group': group_name,
        }
        self.add_defaults_and_process_config(config)
        data = 'not actually a PEM-encoded private key'
        cr.write_one_file(str(path), data, config, 'key_')
        assert path.exists()
        assert path.group() == group_name
        st = path.lstat()
        assert st.st_gid == gid

    def test_backup_one_file_no_existing(self, tmp_path):
        path = tmp_path / 'important'
        backup = path.with_name(path.name + '.bak')
        data = 'howdy, howdy, howdy!'
        result = cr.backup_one_file(str(path), data, str(backup))
        assert result is cr.BACKUP_NOEXIST
        assert not path.exists()
        assert not backup.exists()

    def test_backup_one_file_existing_same_data(self, tmp_path):
        path = tmp_path / 'stuff'
        backup = path.with_name(path.name + '~')
        data = 'To be or not to be, that is the question.\n'
        path.write_text(data)
        result = cr.backup_one_file(str(path), data, str(backup))
        assert result is cr.BACKUP_SAMEDATA
        assert path.exists()
        assert not backup.exists()

    @pytest.mark.usefixtures('clear_umask')
    def test_backup_one_file_basic(self, tmp_path):
        path = tmp_path / 'cert.pem'
        backup = path.with_name(path.name + '.old')
        old_data = 'Junk'
        data = 'Refreshed Junk'
        with open(str(path), 'wt') as fd:
            os.chmod(fd.fileno(), 0o604)
            fd.write(old_data)
            fd.flush()
            old_time = time.time() - 2
            os.utime(fd.fileno(), times=(old_time, old_time))
            old_time = os.stat(fd.fileno()).st_mtime_ns
        result = cr.backup_one_file(str(path), data, str(backup))
        assert result is cr.BACKUP_SUCCESS
        assert path.exists()
        assert backup.exists()
        st = backup.lstat()
        assert stat.S_IMODE(st.st_mode) == 0o604
        assert st.st_mtime_ns == old_time

    @require_root
    def test_backup_one_file_preserves_owner_and_group(self, tmp_path):
        path = tmp_path / 'key.pem'
        backup = path.with_name(path.name + '.1')
        old_data = 'Old, old, old'
        data = 'Up to date'
        with open(str(path), 'wt') as fd:
            os.chown(fd.fileno(), 1711, 91)
            fd.write(old_data)
        result = cr.backup_one_file(str(path), data, str(backup))
        assert result is cr.BACKUP_SUCCESS
        assert path.exists()
        assert backup.exists()
        st = backup.lstat()
        assert st.st_uid == 1711
        assert st.st_gid == 91

    SENTINEL = object()

    @classmethod
    def prepare_install_files(cls, tmp_path, config):
        paths = [
            ('certificate', tmp_path / 'cert'),
            ('intermediate', tmp_path / 'chain'),
            ('key', tmp_path / 'key'),
        ]
        for what, path in paths:
            key = what + '_path'
            exist = config.get(key, cls.SENTINEL)
            if exist is cls.SENTINEL:
                config[key] = str(path)
            elif exist is None:
                del config[key]
        cls.add_defaults_and_process_config(config)
        return (x[1] for x in paths)

    @staticmethod
    def make_backup_paths(*args):
        return tuple(None if x is None else Path(x).with_name(x.name + '.bak')
                     for x in args)

    def test_install_files_default(self, tmp_path):
        config = {}
        cert, chain, key = self.prepare_install_files(tmp_path, config)
        certs_data = ['application\n', 'intermediate1\n', 'intermediate2\n']
        key_data = 'secret!\n'
        cr.install_files(config, certs_data, key_data)
        assert cert.read_text() == 'application\n'
        assert chain.read_text() == 'intermediate1\nintermediate2\n'
        assert key.read_text() == 'secret!\n'

    def test_install_files_revchain(self, tmp_path):
        config = {
            'intermediate_order': 'ca_first',
        }
        cert, chain, key = self.prepare_install_files(tmp_path, config)
        certs_data = ['1\n', '2\n', '3\n', '4\n']
        key_data = '!\n'
        cr.install_files(config, certs_data, key_data)
        assert cert.read_text() == '1\n'
        assert chain.read_text() == '4\n3\n2\n'
        assert key.read_text() == '!\n'

    def test_install_files_fullchain(self, tmp_path):
        config = {
            'bundle_intermediate': True,
            'intermediate_path': None,
        }
        cert, chain, key = self.prepare_install_files(tmp_path, config)
        certs_data = ['app\n', 'snoopy\n', 'charlie\n']
        key_data = 'password\n'
        cr.install_files(config, certs_data, key_data)
        assert cert.read_text() == 'app\nsnoopy\ncharlie\n'
        assert not chain.exists()
        assert key.read_text() == 'password\n'

    def test_install_files_revfullchain(self, tmp_path):
        config = {
            'bundle_intermediate': True,
            'intermediate_order': 'ca_first',
            'intermediate_path': None,
        }
        cert, chain, key = self.prepare_install_files(tmp_path, config)
        certs_data = ['leaf\n', 'branch1\n', 'branch2\n', 'root\n']
        key_data = 'Maple\n'
        cr.install_files(config, certs_data, key_data)
        assert cert.read_text() == 'root\nbranch2\nbranch1\nleaf\n'
        assert not chain.exists()
        assert key.read_text() == 'Maple\n'

    def test_install_files_all_bundled(self, tmp_path):
        config = {
            'bundle_intermediate': True,
            'bundle_key': True,
            'intermediate_path': None,
        }
        cert, chain, key = self.prepare_install_files(tmp_path, config)
        certs_data = ['hughey\n', 'dewey\n', 'louis\n', 'scrooge\n']
        key_data = '$$$$\n'
        cr.install_files(config, certs_data, key_data)
        assert cert.read_text() == '$$$$\nhughey\ndewey\nlouis\nscrooge\n'
        st = cert.lstat()
        assert stat.S_IMODE(st.st_mode) & 0o077 == 0
        assert not chain.exists()
        assert not key.exists()

    def test_install_files_nochain_key_last(self, tmp_path):
        config = {
            'bundle_key': True,
            'bundle_order': 'key_last',
        }
        cert, chain, key = self.prepare_install_files(tmp_path, config)
        certs_data = ['Certified!\n']
        key_data = 'Key?\n'
        cr.install_files(config, certs_data, key_data)
        assert cert.read_text() == 'Certified!\nKey?\n'
        st = cert.lstat()
        assert stat.S_IMODE(st.st_mode) & 0o077 == 0
        assert not chain.exists()
        assert not key.exists()

    def test_install_files_backups(self, tmp_path):
        config = {}
        cert, chain, key = self.prepare_install_files(tmp_path, config)
        cert_bak, chain_bak, key_bak = self.make_backup_paths(cert, chain, key)
        cert.write_text('A Certificate\n')
        cert_bak.write_text('Backup Certificate\n')
        chain.write_text('Chain\nMail\n')
        chain_bak.write_text('Boiled Leather\n')
        key.write_text('The Secret Key!\n')
        assert not key_bak.exists()
        certs_data = ['Another Certificate\n', 'Chain\n', 'Mail\n']
        key_data = 'Unlocker...\n'
        cr.install_files(config, certs_data, key_data)
        assert cert.read_text() == 'Another Certificate\n'
        assert cert_bak.read_text() == 'A Certificate\n'
        assert chain.read_text() == 'Chain\nMail\n'
        # Retained with old content, since the intermediates did not change
        assert chain_bak.read_text() == 'Boiled Leather\n'
        assert key.read_text() == 'Unlocker...\n'
        assert key_bak.read_text() == 'The Secret Key!\n'

    @staticmethod
    def failp_write_one_file(p, real_write_one_file):
        """
        Returns a function that calls real_write_one_file, but then also
        raises a PermissionError if p(call_count) returns True.
        """
        calls = 0
        def side_effect(file_name, data, config, setting_prefix):
            nonlocal calls
            calls += 1
            print(f'write_one_file: {file_name}')
            real_write_one_file(file_name, data, config, setting_prefix)
            if p(calls):
                raise PermissionError('injected error')
        return side_effect

    @staticmethod
    def failp_backup_one_file(p, real_backup_one_file):
        """
        Returns a function that calls real_backup_one_file, but then also
        raises a PermissionError if p(call_count) returns True.
        """
        calls = 0
        def side_effect(file_name, new_data, backup_file_name):
            nonlocal calls
            calls += 1
            print(f'backup: {file_name} -> {backup_file_name}')
            real_backup_one_file(file_name, new_data, backup_file_name)
            if p(calls):
                raise PermissionError('injected error')
        return side_effect

    def test_install_files_recovery_noexist_write_error(self, tmp_path):
        config = {}
        assert list(tmp_path.iterdir()) == [], 'Test should start with an empty data directory'
        cert, chain, key = self.prepare_install_files(tmp_path, config)
        certs_data = ['data\n', 'data\n', 'data\n']
        key_data = 'data\n'
        real_write_one_file = cr.write_one_file
        with patch('cert_receive.write_one_file') as mock:
            mock.side_effect = self.failp_write_one_file(lambda n: n == 2, real_write_one_file)
            try:
                cr.install_files(config, certs_data, key_data)
            except cr.UpdateFailedException as e:
                assert not re.search(r'\binconsistent\b', str(e))
            else:
                assert False, 'Expected an exception due to fault injection'
        assert not cert.exists()
        assert not chain.exists()
        assert not key.exists()
        assert list(tmp_path.iterdir()) == []

    def test_install_files_recovery_all_changing_write_error(self, tmp_path):
        config = {}
        assert list(tmp_path.iterdir()) == [], 'Test should start with an empty data directory'
        cert, chain, key = self.prepare_install_files(tmp_path, config)
        cert.write_text('cert version 1\n')
        chain.write_text('chain version 1\n')
        key.write_text('key version 1\n')
        initial_files = [x.name for x in tmp_path.iterdir()]
        initial_files.sort()
        assert initial_files == ['cert', 'chain', 'key']
        certs_data = ['cert verison 2\n', 'chain version 2\n']
        key_data = 'key version 2\n'
        real_write_one_file = cr.write_one_file
        with patch('cert_receive.write_one_file') as mock:
            mock.side_effect = self.failp_write_one_file(lambda n: n == 3, real_write_one_file)
            try:
                cr.install_files(config, certs_data, key_data)
            except cr.UpdateFailedException as e:
                assert not re.search(r'\binconsistent\b', str(e))
            else:
                assert False, 'Expected an exception due to fault injection'
        assert cert.read_text() == 'cert version 1\n'
        assert chain.read_text() == 'chain version 1\n'
        assert key.read_text() == 'key version 1\n'
        assert sorted([x.name for x in tmp_path.iterdir()]) == initial_files

    def test_install_files_recovery_backup_error(self, tmp_path):
        config = {
            'bundle_intermediate': True,
            'intermediate_path': None,
        }
        assert list(tmp_path.iterdir()) == [], 'Test should start with an empty data directory'
        cert, _, key = self.prepare_install_files(tmp_path, config)
        cert_bak, key_bak = self.make_backup_paths(cert, key)
        cert.write_text('alpha\nbravo\n')
        cert_bak.write_text('a\nb\n')
        key.write_text('kilo\n')
        key_bak.write_text('k\n')
        initial_files = [x.name for x in tmp_path.iterdir()]
        initial_files.sort()
        assert initial_files == ['cert', 'cert.bak', 'key', 'key.bak']
        certs_data = ['uno\n', 'dos\n']
        key_data = 'tres'
        real_backup_one_file = cr.backup_one_file
        with patch('cert_receive.backup_one_file') as mock:
            mock.side_effect = self.failp_backup_one_file(lambda n: n == 1, real_backup_one_file)
            try:
                cr.install_files(config, certs_data, key_data)
            except cr.UpdateFailedException as e:
                assert not re.search(r'\binconsistent\b', str(e))
            else:
                assert False, 'Expected an exception due to fault injection'
        assert cert.read_text() == 'alpha\nbravo\n'
        assert not cert_bak.exists()
        assert key.read_text() == 'kilo\n'
        assert key_bak.read_text() == 'k\n'
        final_files = [x.name for x in tmp_path.iterdir()]
        final_files.sort()
        assert final_files == ['cert', 'key', 'key.bak']

    @staticmethod
    def failp_rename(p, real_rename):
        """
        Returns a function that calls raises a PermissionError if p(call_count)
        returns True and otherwise calls real_rename.
        """
        calls = 0
        def side_effect(src, dst):
            nonlocal calls
            calls += 1
            if p(calls):
                raise PermissionError('injected error')
            print(f'rename: {src} -> {dst}')
            real_rename(src, dst)
        return side_effect

    def test_install_files_recovery_noexist_rename_error(self, tmp_path):
        config = {}
        assert list(tmp_path.iterdir()) == [], 'Test should start with an empty data directory'
        cert, chain, key = self.prepare_install_files(tmp_path, config)
        certs_data = ['one\n', 'two\n']
        key_data = 'schlage\n'
        real_rename = os.rename
        with patch('os.rename') as mock:
            mock.side_effect = self.failp_rename(lambda n: n == 3, real_rename)
            try:
                cr.install_files(config, certs_data, key_data)
            except cr.UpdateFailedException as e:
                assert not re.search(r'\binconsistent\b', str(e))
            else:
                assert False, 'Expected an exception due to fault injection'
        assert not cert.exists()
        assert not chain.exists()
        assert not key.exists()
        assert list(tmp_path.iterdir()) == []

    def test_install_files_recovery_all_changing_rename_error(self, tmp_path):
        config = {}
        assert list(tmp_path.iterdir()) == [], 'Test should start with an empty data directory'
        cert, chain, key = self.prepare_install_files(tmp_path, config)
        cert.write_text('original cert\n')
        chain.write_text('original chain\n')
        key.write_text('original key\n')
        initial_files = [x.name for x in tmp_path.iterdir()]
        initial_files.sort()
        assert initial_files == ['cert', 'chain', 'key']
        certs_data = ['cert1\n', 'cert2\n', 'cert3\n']
        key_data = 'key\n'
        real_rename = os.rename
        with patch('os.rename') as mock:
            mock.side_effect = self.failp_rename(lambda n: n == 3, real_rename)
            try:
                cr.install_files(config, certs_data, key_data)
            except cr.UpdateFailedException as e:
                assert not re.search(r'\binconsistent\b', str(e))
            else:
                assert False, 'Expected an exception due to fault injection'
        assert cert.read_text() == 'original cert\n'
        assert chain.read_text() == 'original chain\n'
        assert key.read_text() == 'original key\n'
        assert sorted([x.name for x in tmp_path.iterdir()]) == initial_files

    def test_install_files_recovery_one_changing_rename_error(self, tmp_path):
        config = {}
        assert list(tmp_path.iterdir()) == [], 'Test should start with an empty data directory'
        cert, chain, key = self.prepare_install_files(tmp_path, config)
        cert_bak, chain_bak, key_bak = self.make_backup_paths(cert, chain, key)
        cert.write_text('My second certificate\n')
        cert_bak.write_text('My first certificate\n')
        chain.write_text('My intermediate\n')
        chain_bak.write_text('My old intermediate\n')
        key.write_text('My first key\n')
        initial_files = [x.name for x in tmp_path.iterdir()]
        initial_files.sort()
        assert initial_files == ['cert', 'cert.bak', 'chain', 'chain.bak', 'key']
        certs_data = ['My third certificate\n', 'My intermediate\n']
        key_data = 'My first key\n'
        real_rename = os.rename
        with patch('os.rename') as mock:
            mock.side_effect = self.failp_rename(lambda n: n == 3, real_rename)
            try:
                cr.install_files(config, certs_data, key_data)
            except cr.UpdateFailedException as e:
                assert not re.search(r'\binconsistent\b', str(e))
            else:
                assert False, 'Expected an exception due to fault injection'
        assert cert.read_text() == 'My second certificate\n'
        assert not cert_bak.exists()
        assert chain.read_text() == 'My intermediate\n'
        assert chain_bak.read_text() == 'My old intermediate\n'
        assert key.read_text() == 'My first key\n'
        final_files = [x.name for x in tmp_path.iterdir()]
        final_files.sort()
        assert final_files == ['cert', 'chain', 'chain.bak', 'key']
