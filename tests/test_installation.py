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

from contextlib import contextmanager
import grp
import os
import pwd
import stat
import sys
import time
from unittest.mock import mock_open, patch

import pytest

import cert_receive as cr


@pytest.mark.usefixtures('override_g_args')
class TestInstallation:
    def add_defaults_and_process_config(self, config, allow_warn=False):
        for key in cr.CFG_DEFAULT_SETTINGS:
            if key in config:
                continue
            if key.startswith('verify_'):
                config[key] = False
        self.override_g_args.ca_path = None
        self.override_g_args.config_file = 'mock_config.json'
        header, errors, warnings = cr.check_configuration_section('test', config)
        if errors or (warnings and not allow_warn):
            assert False, '\n'.join(['Expected configuration check to pass '
                                     'without errors{} but it reported:\n'.
                                     format(' or warnings' if allow_warn else ''),
                                     header] +
                                    errors + warnings)
        if warnings:
            print('\n'.join(warnings), file=sys.stderr)

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
                break
            except KeyError:
                pass
        else:
            pytest.xfail('Could not find a user name to test with')
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
                break
            except KeyError:
                pass
        else:
            pytest.xfail('Could not find a group name to test with')
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
        with open(str(path), 'wt', encoding='utf-8') as fd:
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
        with open(str(path), 'wt', encoding='utf-8') as fd:
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

    def prepare_install_files(self, tmp_path, config, allow_warn=False):
        paths = [
            ('certificate', tmp_path / 'cert'),
            ('intermediate', tmp_path / 'chain'),
            ('key', tmp_path / 'key'),
        ]
        for what, path in paths:
            key = what + '_path'
            exist = config.get(key, self.SENTINEL)
            if exist is self.SENTINEL:
                config[key] = str(path)
            elif exist is None:
                del config[key]
        self.add_defaults_and_process_config(config, allow_warn=allow_warn)
        return (x[1] for x in paths)

    @staticmethod
    def make_backup_paths(*args):
        return tuple(None if x is None else x.with_name(x.name + '.bak')
                     for x in args)

    @staticmethod
    def make_call_string(name, *args, **kwargs):
        def my_repr(o):
            if o is None or isinstance(o, (bytes, float, int, str, type)):
                return repr(o)
            return '<{} {:#x}>'.format(type(o).__name__, id(o))

        return '{}({})'.format(
            name,
            ', '.join([my_repr(x) for x in args] +
                      ['='.join([k, my_repr(v)]) for k, v in kwargs.items()])
        )

    @classmethod
    def failp_after(cls, p, real_func, etype=PermissionError):
        """
        Returns a function that calls real_func, but then also raises an
        instance of etype if p(call_count) returns True.
        """
        calls = 0
        def side_effect(*args, **kwargs):
            nonlocal calls
            calls += 1
            callstr = cls.make_call_string(real_func.__name__, *args, **kwargs)
            print('CALL {}'.format(callstr), file=sys.stderr)
            ret = real_func(*args, **kwargs)
            if p(calls):
                print('FAIL {}'.format('^' * len(callstr)), file=sys.stderr)
                raise etype('injected error')
            return ret
        return side_effect

    @classmethod
    def failp_before(cls, p, real_func, etype=PermissionError):
        """
        Returns a function that raises an instance of etype if p(call_count)
        returns True but otherwise calls real_func.
        """
        calls = 0
        def side_effect(*args, **kwargs):
            nonlocal calls
            calls += 1
            callstr = cls.make_call_string(real_func.__name__, *args, **kwargs)
            if p(calls):
                print('   FAIL {}'.format(callstr), file=sys.stderr)
                raise etype('injected error')
            print('   CALL {}'.format(callstr), file=sys.stderr)
            return real_func(*args, **kwargs)
        return side_effect

    @staticmethod
    def raises_update_failed_exception(inconsistent=False):
        if inconsistent:
            pattern = r'\binconsistent\b'
        else:
            pattern = r'(?s)^(?!.*\binconsistent\b).*$'
        return pytest.raises(cr.UpdateFailedException, match=pattern)

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
        assert chain.read_text() == ''
        assert not key.exists()

    @pytest.mark.parametrize('mode', ['empty', 'preserve', 'unlink'])
    def test_install_files_nochain(self, mode, tmp_path):
        config = {
            'if_no_intermediate': mode,
        }
        cert, chain, key = self.prepare_install_files(tmp_path, config)
        chain_bak, = self.make_backup_paths(chain)
        certs_data = ['Lonely {} whale\n'.format(mode)]
        chain.write_text('({})This data is obsolete!\n'.format(mode))
        key_data = 'Unlocks all my dreams\n{}\n'.format(hash(mode))
        cr.install_files(config, certs_data, key_data)
        assert cert.read_text() == 'Lonely {} whale\n'.format(mode)
        if mode == 'empty':
            assert chain.read_text() == ''
            assert chain_bak.read_text() == '({})This data is obsolete!\n'.format(mode)
        if mode == 'preserve':
            assert chain.read_text() == '({})This data is obsolete!\n'.format(mode)
            assert not chain_bak.exists()
        if mode == 'unlink':
            assert not chain.exists()
            assert chain_bak.read_text() == '({})This data is obsolete!\n'.format(mode)
        assert key.read_text() == 'Unlocks all my dreams\n{}\n'.format(hash(mode))

    @pytest.mark.parametrize('mode', ['empty', 'unlink'])
    def test_install_files_nochain_bundle_intermediate_path(self, mode, tmp_path):
        config = {
            'bundle_intermediate': True,
            'if_no_intermediate': mode,
        }
        cert, chain, key = self.prepare_install_files(tmp_path, config, allow_warn=True)
        chain_bak, = self.make_backup_paths(chain)
        chain.write_text('DO NOT {} THIS FILE!\n'.format(mode))
        certs_data = ['{}application\n'.format(mode)]
        key_data = 'key {}\n'.format(hash(mode))
        cr.install_files(config, certs_data, key_data)
        assert cert.read_text() == '{}application\n'.format(mode)
        assert chain.read_text() == 'DO NOT {} THIS FILE!\n'.format(mode)
        assert not chain_bak.exists()
        assert key.read_text() == 'key {}\n'.format(hash(mode))

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
        # Intermediates did not change; hence no change to the content of
        # the chain and chain_bak files.
        assert chain.read_text() == 'Chain\nMail\n'
        assert chain_bak.read_text() == 'Boiled Leather\n'
        assert key.read_text() == 'Unlocker...\n'
        assert key_bak.read_text() == 'The Secret Key!\n'

    def test_install_files_recovery_noexist_write_error(self, tmp_path):
        config = {}
        _, _, _ = self.prepare_install_files(tmp_path, config)

        assert list(tmp_path.iterdir()) == [], 'Test should start with an empty data directory'

        certs_data = ['data\n', 'data\n', 'data\n']
        key_data = 'data\n'
        real_write_one_file = cr.write_one_file
        with self.raises_update_failed_exception(), \
             patch('cert_receive.write_one_file') as mock:
            mock.side_effect = self.failp_after(lambda n: n == 2, real_write_one_file)
            cr.install_files(config, certs_data, key_data)

        assert list(tmp_path.iterdir()) == [], 'Test should complete with an empty data directory'

    def test_install_files_recovery_all_changing_write_error(self, tmp_path):
        config = {}
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
        with self.raises_update_failed_exception(), \
             patch('cert_receive.write_one_file') as mock:
            mock.side_effect = self.failp_after(lambda n: n == 3, real_write_one_file)
            cr.install_files(config, certs_data, key_data)

        final_files = [x.name for x in tmp_path.iterdir()]
        final_files.sort()
        assert final_files == initial_files

        assert cert.read_text() == 'cert version 1\n'
        assert chain.read_text() == 'chain version 1\n'
        assert key.read_text() == 'key version 1\n'

    def test_install_files_recovery_backup_error(self, tmp_path):
        config = {
            'bundle_intermediate': True,
            'intermediate_path': None,
        }
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
        with self.raises_update_failed_exception(), \
             patch('cert_receive.backup_one_file') as mock:
            mock.side_effect = self.failp_after(lambda n: n == 1, real_backup_one_file)
            cr.install_files(config, certs_data, key_data)

        final_files = [x.name for x in tmp_path.iterdir()]
        final_files.sort()
        assert final_files == ['cert', 'key', 'key.bak']

        assert cert.read_text() == 'alpha\nbravo\n'
        assert key.read_text() == 'kilo\n'
        assert key_bak.read_text() == 'k\n'

    def test_install_files_recovery_noexist_rename_error(self, tmp_path):
        config = {}
        _, _, _ = self.prepare_install_files(tmp_path, config)

        assert list(tmp_path.iterdir()) == [], 'Test should start with an empty data directory'

        certs_data = ['one\n', 'two\n']
        key_data = 'schlage\n'
        real_rename = os.rename
        with self.raises_update_failed_exception(), \
             patch('os.rename') as mock:
            mock.side_effect = self.failp_before(lambda n: n == 3, real_rename)
            cr.install_files(config, certs_data, key_data)

        assert list(tmp_path.iterdir()) == [], 'Test should complete with an empty data directory'

    def test_install_files_recovery_all_changing_rename_error(self, tmp_path):
        config = {}
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
        with self.raises_update_failed_exception(), \
             patch('os.rename') as mock:
            mock.side_effect = self.failp_before(lambda n: n == 3, real_rename)
            cr.install_files(config, certs_data, key_data)

        final_files = [x.name for x in tmp_path.iterdir()]
        final_files.sort()
        assert final_files == initial_files

        assert cert.read_text() == 'original cert\n'
        assert chain.read_text() == 'original chain\n'
        assert key.read_text() == 'original key\n'

    def test_install_files_recovery_one_changing_rename_error(self, tmp_path):
        config = {}
        cert, chain, key = self.prepare_install_files(tmp_path, config)
        cert_bak, chain_bak = self.make_backup_paths(cert, chain)
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
        with self.raises_update_failed_exception(), \
             patch('os.rename') as mock:
            mock.side_effect = self.failp_before(lambda n: n == 3, real_rename)
            cr.install_files(config, certs_data, key_data)

        final_files = [x.name for x in tmp_path.iterdir()]
        final_files.sort()
        assert final_files == ['cert', 'chain', 'chain.bak', 'key']

        assert cert.read_text() == 'My second certificate\n'
        assert chain.read_text() == 'My intermediate\n'
        assert chain_bak.read_text() == 'My old intermediate\n'
        assert key.read_text() == 'My first key\n'

    def test_install_files_recovery_error_rename(self, tmp_path):
        config = {}
        cert, chain, key = self.prepare_install_files(tmp_path, config)
        cert_bak, chain_bak, key_bak = self.make_backup_paths(cert, chain, key)
        cert.write_text('C maj.\n')
        cert_bak.write_text('C\n')
        chain.write_text('IV V I\n')
        chain_bak.write_text('V I\n')
        key.write_text('progression\n')
        key_bak.write_text('cadence\n')

        initial_files = [x.name for x in tmp_path.iterdir()]
        initial_files.sort()
        assert initial_files == ['cert', 'cert.bak', 'chain', 'chain.bak', 'key', 'key.bak']

        certs_data = ['c minor\n', 'V VI\n']
        key_data = 'deceptive\n'
        real_rename = os.rename
        with self.raises_update_failed_exception(inconsistent=True), \
             patch('os.rename') as mock:
            # Fail installing key, and only succeed recovering cert
            mock.side_effect = self.failp_before(lambda n: n == 3 or n >= 5, real_rename)
            cr.install_files(config, certs_data, key_data)

        final_files = [x.name for x in tmp_path.iterdir()]
        final_files.sort()
        assert final_files == ['cert', 'chain', 'chain.bak', 'key', 'key.bak']

        assert cert.read_text() == 'C maj.\n'
        assert chain.read_text() == 'V VI\n'
        assert chain_bak.read_text() == 'IV V I\n'
        assert key.read_text() == 'progression\n'
        # Backup of unchanged key is not deleted because of the recovery error
        assert key_bak.read_text() == 'progression\n'

    def test_install_files_recovery_error_unlink_no_existing(self, tmp_path):
        config = {
            'bundle_intermediate': True,
            'intermediate_path': None,
        }
        cert, _, _ = self.prepare_install_files(tmp_path, config)

        assert list(tmp_path.iterdir()) == [], 'Test should start with an empty data directory'

        certs_data = ['H: Hydrogen\n', 'He: Helium\n']
        key_data = 'K: Potassium\n'
        real_rename, real_unlink = os.rename, os.unlink
        with self.raises_update_failed_exception(inconsistent=True), \
             patch('os.rename') as mock_rename, patch('os.unlink') as mock_unlink:
            mock_rename.side_effect = self.failp_before(lambda n: n == 2, real_rename)
            mock_unlink.side_effect = self.failp_before(lambda n: n == 2, real_unlink)
            cr.install_files(config, certs_data, key_data)

        final_files = [x.name for x in tmp_path.iterdir()]
        final_files.sort()
        assert final_files == ['cert']

        assert cert.read_text() == 'H: Hydrogen\nHe: Helium\n'

    def test_install_files_recovery_error_unlink_tmpfile(self, tmp_path):
        config = {}
        cert, chain, key = self.prepare_install_files(tmp_path, config)
        cert_bak, chain_bak, key_bak = self.make_backup_paths(cert, chain, key)
        cert.write_text('Apple\n')
        cert_bak.write_text('Chicken\n')
        chain.write_text('Pome\n')
        chain_bak.write_text('Poultry\n')
        key.write_text('Pear\n')
        key_bak.write_text('Turkey\n')

        initial_files = [x.name for x in tmp_path.iterdir()]
        initial_files.sort()
        assert initial_files == ['cert', 'cert.bak', 'chain', 'chain.bak', 'key', 'key.bak']

        certs_data = ['Orange\n','Citrus\n']
        key_data = 'Lime\n'
        real_write_one_file, real_unlink = cr.write_one_file, os.unlink
        with self.raises_update_failed_exception(inconsistent=False), \
             patch('cert_receive.write_one_file') as mock_write, \
             patch('os.unlink') as mock_unlink:
            mock_write.side_effect = self.failp_after(lambda n: n == 2, real_write_one_file)
            mock_unlink.side_effect = self.failp_before(lambda n: n == 1, real_unlink)
            cr.install_files(config, certs_data, key_data)

        expected_files = initial_files[0:]
        expected_files.append('cert.new-{}'.format(os.getpid()))
        expected_files.sort()
        final_files = [x.name for x in tmp_path.iterdir()]
        final_files.sort()
        assert final_files == expected_files

        assert cert.read_text() == 'Apple\n'
        assert cert_bak.read_text() == 'Chicken\n'
        assert chain.read_text() == 'Pome\n'
        assert chain_bak.read_text() == 'Poultry\n'
        assert key.read_text() == 'Pear\n'
        assert key_bak.read_text() == 'Turkey\n'

    def test_install_files_recovery_error_unlink_backup(self, tmp_path):
        config = {
            'bundle_intermediate': True,
            'intermediate_path': None,
        }
        cert, _, key = self.prepare_install_files(tmp_path, config)
        key_bak, = self.make_backup_paths(key)
        cert.write_text('Hola!\n')
        key.write_text('Hello.\n')

        initial_files = [x.name for x in tmp_path.iterdir()]
        initial_files.sort()
        assert initial_files == ['cert', 'key']

        certs_data = ['Adios.\n']
        key_data = 'Good bye.\n'
        real_rename, real_unlink = os.rename, os.unlink
        with self.raises_update_failed_exception(inconsistent=False), \
             patch('os.rename') as mock_rename, patch('os.unlink') as mock_unlink:
            mock_rename.side_effect = self.failp_before(lambda n: n == 2, real_rename)
            mock_unlink.side_effect = self.failp_before(lambda n: n == 2, real_unlink)
            cr.install_files(config, certs_data, key_data)

        final_files = [x.name for x in tmp_path.iterdir()]
        final_files.sort()
        assert final_files == ['cert', 'key', 'key.bak']

        assert cert.read_text() == 'Hola!\n'
        assert key.read_text() == 'Hello.\n'
        assert key_bak.read_text() == 'Hello.\n'

    def test_install_files_recovery_error_unlink_bad_backup(self, tmp_path):
        config = {
            'bundle_intermediate': True,
            'bundle_key': True,
            'intermediate_path': None,
        }
        cert, _, _ = self.prepare_install_files(tmp_path, config)
        cert.write_text('smoosh\ncrunch\n')

        initial_files = [x.name for x in tmp_path.iterdir()]
        initial_files.sort()
        assert initial_files == ['cert']

        certs_data = ['crunchier\n']
        key_data = 'smooshier\n'
        real_backup_one_file, real_unlink = cr.backup_one_file, os.unlink
        with self.raises_update_failed_exception(inconsistent=True), \
             patch('cert_receive.backup_one_file') as mock_backup, \
             patch('os.unlink') as mock_unlink:
            mock_backup.side_effect = self.failp_after(lambda n: n == 1, real_backup_one_file)
            mock_unlink.side_effect = self.failp_before(lambda n: n == 2, real_unlink)
            cr.install_files(config, certs_data, key_data)

        final_files = [x.name for x in tmp_path.iterdir()]
        final_files.sort()
        assert final_files == ['cert', 'cert.bak']

        assert cert.read_text() == 'smoosh\ncrunch\n'


@pytest.fixture()
def class_tmp_path(tmp_path, request):
    request.cls.tmp_path = tmp_path
    yield
    del request.cls.tmp_path


@pytest.mark.usefixtures('class_tmp_path')
class TestUpdateBundle:
    # While the line separator nominally shouldn't matter, cert_receive uses
    # a mix of binary and text I/O.  And that means we can run afoul of things
    # due to Python's automatic newline conversion feature.
    #
    # For that reason, we also need to be careful to use binary I/O when
    # writing to bundle_path in the test cases; otherwise we won't actually
    # test with the intended line separator.
    foreach_linesep = pytest.mark.parametrize('linesep',
                                              ['\n', '\r\n', '\r'],
                                              ids=['lf', 'crlf', 'cr'])

    @classmethod
    @contextmanager
    def create_mocks(cls, bundle_content, config, certificates, key):
        fake_args = [
            'cert_receive.py',
            '--no-ca-path',
            '--no-set-effective-user',
        ]
        real_open = open
        with patch.object(sys, 'argv', new=fake_args), \
             patch('cert_receive.load_configuration') as fake_lc, \
             patch('cert_receive.interact_with_sender') as fake_iws, \
             patch('builtins.open') as fake_open, \
             patch('cert_receive.perform_verifications'):
            cls.bundle_path = cls.tmp_path / 'bundle.pem'
            cls.bundle_path.touch(mode=0o600)
            cls.bundle_path.write_bytes(bundle_content.encode('utf-8'))
            config['certificate_path'] = str(cls.bundle_path)
            config.setdefault('verify_subject_cn', False)
            fake_lc.return_value = {'test_config': config}

            def iws_side_effect(unused_config_in):
                _, e, w = cr.check_configuration_section('test_config', config)
                assert not e, 'Test configuration resulted in errors:\n{}' \
                              .format('\n'.join(e))
                assert not w, 'Test configuration resulted in warnings:\n{}' \
                              .format('\n'.join(e))
                return config, certificates, key
            fake_iws.side_effect = iws_side_effect

            def open_side_effect(name, *args, **kwargs):
                if name.startswith(str(cls.bundle_path)):
                    return real_open(name, *args, **kwargs)
                if name == '/etc/cert_receive.json':
                    return mock_open()(name, *args, **kwargs)
                assert False, 'Code under test opened an unexpected file'
                return None
            fake_open.side_effect = open_side_effect

            yield

            del cls.bundle_path

    @foreach_linesep
    @pytest.mark.parametrize('bundle_order', ['key_first', 'key_last'])
    def test_bundled_key(self, bundle_order, linesep):
        existing = [
            linesep.join([
                '-----BEGIN PRIVATE KEY-----',
                'The key!',
                '-----END PRIVATE KEY-----',
                '',
            ]),
            linesep.join([
                '-----BEGIN CERTIFICATE-----',
                'Old certificate.',
                '-----END CERTIFICATE-----',
                '',
            ]),
        ]
        config = {
            'bundle_key': True,
            'bundle_order': bundle_order,
        }
        new_cert = linesep.join([
            '-----BEGIN CERTIFICATE-----',
            'New certificate, yay.',
            '-----END CERTIFICATE-----',
            '',
        ])
        new_key = None
        expected = [existing[0], new_cert]
        if bundle_order == 'key_last':
            existing.reverse()
            expected.reverse()
        with self.create_mocks(''.join(existing), config, [new_cert], new_key):
            retval = cr.main()
            assert retval == 0
            actual = self.bundle_path.read_text()
            expected = ''.join(expected)
            if linesep != '\n':
                expected = expected.replace(linesep, '\n')
            assert actual == expected

    @foreach_linesep
    @pytest.mark.parametrize('operation',
                             ['empty', 'preserve-ca_first', 'preserve-ca_last'])
    def test_bundled_intermediate(self, operation, linesep):
        existing = [
            linesep.join([
                '-----BEGIN CERTIFICATE-----',
                'Application, signed by Intermediate-1',
                '-----END CERTIFICATE-----',
                '',
            ]),
            linesep.join([
                '-----BEGIN CERTIFICATE-----',
                'Intermediate-1, signed by Intermediate-2',
                '-----END CERTIFICATE-----',
                '',
            ]),
            linesep.join([
                '-----BEGIN CERTIFICATE-----',
                'Intermediate-2, signed by CA',
                '-----END CERTIFICATE-----',
                '',
            ]),
        ]
        config = {
            'key_path': str(self.tmp_path / 'key.pem'),
            'bundle_intermediate': True,
            'if_no_intermediate': operation.split('-')[0],
        }
        new_cert = linesep.join([
            '-----BEGIN CERTIFICATE-----',
            'New application, signed by ' +
            'Intermediate-1' if operation.startswith('preserve-') else 'CA',
            '-----END CERTIFICATE-----',
            '',
        ])
        new_key = None
        expected = [new_cert]
        if operation.startswith('preserve-'):
            expected.extend(existing[1:])
            order = operation.split('-')[1]
            if order == 'ca_first':
                existing.reverse()
                expected.reverse()
            config['intermediate_order'] = order
        with self.create_mocks(''.join(existing), config, [new_cert], new_key):
            retval = cr.main()
            assert retval == 0
            actual = self.bundle_path.read_text()
            expected = ''.join(expected)
            if linesep != '\n':
                expected = expected.replace(linesep, '\n')
            assert actual == expected


@pytest.mark.usefixtures('class_tmp_path', 'mock_g_args', 'noop_privileges')
class TestFileEncoding:
    TEST_KEY = '\n'.join([
        '-----BEGIN PRIVATE KEY-----',
        '0123456789',
        '-----END PRIVATE KEY-----',
        '',
    ])
    TEST_CERTIFICATE = '\n'.join([
        '-----BEGIN CERTIFICATE-----',
        'ABCDEF',
        '-----END CERTIFICATE-----',
        '',
    ])

    foreach_encoding = pytest.mark.parametrize('encoding',
                                               ['utf8', 'latin1', 'shiftjis'])

    @foreach_encoding
    def test_read_ascii_works_with_compatible_encoding(self, encoding):
        bundle = self.tmp_path / 'bundle.pem'
        bundle.write_text(self.TEST_KEY + self.TEST_CERTIFICATE,
                          encoding='ascii')

        with patch('cert_receive.system_encoding') as mock_encoding:
            mock_encoding.return_value = encoding
            key = cr.read_key_from_file(str(bundle),
                                        max_size=cr.OVERALL_PEM_MAXIMUM)
            certs = cr.read_certificates_from_file(str(bundle))

        assert key == self.TEST_KEY
        assert len(certs) == 1
        assert certs[0] == self.TEST_CERTIFICATE

    @foreach_encoding
    def test_read_non_ascii_comments_works_with_same_encoding(self, encoding):
        comments = ['ASCII text']
        if encoding != 'shiftjis':
            comments.append('Fáncy tëxt')
        if encoding != 'latin1':
            comments.append('得体の知れない')
        comments.append('')

        bundle = self.tmp_path / 'bundle.pem'
        bundle.write_text('\n'.join(comments) +
                          self.TEST_KEY + self.TEST_CERTIFICATE,
                          encoding=encoding)

        with patch('cert_receive.system_encoding') as mock_encoding:
            mock_encoding.return_value = encoding
            key = cr.read_key_from_file(str(bundle),
                                        max_size=cr.OVERALL_PEM_MAXIMUM)
            certs = cr.read_certificates_from_file(str(bundle))

        assert key == self.TEST_KEY
        assert len(certs) == 1
        assert certs[0] == self.TEST_CERTIFICATE

    @foreach_encoding
    def test_written_data_is_ascii_with_compatible_encoding(self, encoding):
        cert_path = self.tmp_path / 'certificate.pem'
        config = {
            'certificate_path': cert_path,
            'certificate_owner': 0,
            'certificate_group': 0,
            'certificate_perms': 0o644,
        }

        with patch('cert_receive.system_encoding') as mock_encoding:
            mock_encoding.return_value = encoding
            cr.write_one_file(str(cert_path),
                              self.TEST_CERTIFICATE,
                              config,
                              'certificate_')

        assert cert_path.read_text(encoding='ascii') == self.TEST_CERTIFICATE
