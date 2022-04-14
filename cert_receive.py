#!/usr/bin/python3

import argparse
import grp
import json
import OpenSSL.SSL as ssl
import OpenSSL.crypto as ssl_crypto
import os
import pexpect
import pexpect.fdpexpect
import pwd
import re
import signal
import stat
import subprocess
import sys
import time

DEFAULT_CA_PATH = '/etc/ssl/certs'
DEFAULT_CONFIG_FILE = '/etc/cert_receive.json'

class CertReceivePyException(Exception):
    EXITCODE = 1

class BadConfigException(CertReceivePyException):
    EXITCODE = 2

class BadSenderException(CertReceivePyException):
    EXITCODE = 3

class BadCertificateException(CertReceivePyException):
    EXITCODE = 4

class BadKeyException(CertReceivePyException):
    EXITCODE = 5

class UpdateFailedException(CertReceivePyException):
    EXITCODE = 6

g_args = None

def resolve_user_name(user_name):
    if user_name.startswith('#'):
        return int(user_name[1:])
    try:
        pwent = pwd.getpwnam(user_name)
        return pwent.pw_uid
    except KeyError as e:
        if user_name == 'root':
            return 0
        if not user_name.isdecimal():
            raise e
        return int(user_name)

def resolve_group_name(group_name):
    if group_name.startswith('#'):
        return int(group_name[1:])
    try:
        grent = grp.getgrnam(group_name)
        return grent.gr_gid
    except KeyError as e:
        if group_name == 'root' or group_name == 'wheel':
            return 0
        if not group_name.isdecimal():
            raise e
        return int(group_name)

def drop_privileges():
    '''
    Temporarily drops root privileges when, configured to do so.  To be used
    during parsing/validation steps, to reduce the surface are of any
    vulnerabilities that might exist in that processing.
    '''
    if g_args.set_effective_user is not None:
        try:
            os.seteuid(resolve_user_name(g_args.set_effective_user))
        except OSError:
            raise BadConfigException('Error dropping privileges')

def reacquire_privileges():
    '''
    Regains root privileges if the program was started as root and dropped
    privileges earlier.
    '''
    if g_args.set_effective_user is not None and os.geteuid() != 0:
        os.seteuid(0)

CFG_COMMENT_REGEX = re.compile(r'^(comment|#)')

def load_configuration():
    '''
    Parses the configuration file and returns the parsed configuration.
    '''
    config_file_name = g_args.config_file
    try:
        with open(config_file_name, 'rt') as config_file:
           config = json.load(config_file)
    except (IOError, JSONDecodeError) as e:
        action = 'parsing' if isinstance(e, JSONDecodeError) else 'reading'
        raise BadConfigException('Error {} configuration file "{}":\n{}'
                                 .format(action, config_file_name, str(e)))

    if not isinstance(config, dict):
        raise BadConfigException('Top-level configuration should be a '
                                 'JSON object')

    to_delete = []
    for name in config:
        if CFG_COMMENT_REGEX.search(name):
            to_delete.append(name)

    for name in to_delete:
        del config[name]

    return config

CFG_VALID_SETTINGS = {
    'bundle_intermediate':      bool,
    'bundle_key':               bool,
    'bundle_order':             frozenset(('key_first', 'key_last')),
    'ca_file':                  str,
    'ca_path':                  str,
    'certificate_group':        str,
    'certificate_owner':        str,
    'certificate_path':         str,
    'certificate_perms':        str,
    'expected_subject_cn':      str,
    'intermediate_order':       frozenset(('ca_first', 'ca_last')),
    'intermediate_path':        str,
    'key_group':                str,
    'key_owner':                str,
    'key_path':                 str,
    'key_perms':                str,
    'reload_command':           str,
    'reload_timeout':           int,
    'verify_chain':             bool,
    'verify_loadable':          bool,
    'verify_matching_key':      bool,
    'verify_subject_cn':        bool,
    'verify_times':             bool,
    'verify_trusted_ca':        bool,
}

CFG_DEFAULT_SETTINGS = {
    'bundle_intermediate':      False,
    'bundle_key':               False,
    'bundle_order':             'key_first',
    'certificate_group':        'root',
    'certificate_owner':        'root',
    'certificate_perms':        '0644',
    'intermediate_order':       'ca_last',
    'key_group':                'root',
    'key_owner':                'root',
    'key_perms':                '0600',
    'reload_timeout':           110,
    'verify_chain':             True,
    'verify_loadable':          True,
    'verify_matching_key':      True,
    'verify_subject_cn':        True,
    'verify_times':             True,
    'verify_trusted_ca':        True,
}

CFG_TYPE_TO_JSON = {
    bool:       'boolean',
    dict:       'object',
    float:      'number',
    int:        'number',
    list:       'array',
    str:        'string',
}

def check_configuration_section(name, section):
    '''
    Checks the validity of a single section from the configuration file.
    Also sets default values for any settings that were not provided in
    the configuration section.
    '''
    errors = []
    warnings = []

    def check_one(what, parsed, expected):
        expected_type = expected
        if isinstance(expected, frozenset):
            expected_type = str
        if not isinstance(parsed, expected_type):
            errors.append('{} should be a JSON {}'
                          .format(what, CFG_TYPE_TO_JSON(expected_type)))
            return False
        if isinstance(expected, frozenset) and parsed not in expected:
            errors.append('{} should be one of: {}'.format(what, expected))
            return False
        return True

    if check_one('Section', section, dict):
        to_delete = []
        for setting, value in section.items():
            if CFG_COMMENT_REGEX.search(setting):
                to_delete.append(setting)
            elif not setting in CFG_VALID_SETTINGS:
                errors.append('Unrecognized setting "{}"'.format(setting))
            else:
                check_one('Value of setting "{}"'.format(setting),
                          value,
                          CFG_VALID_SETTINGS[setting])

        for setting in to_delete:
            del section[setting]

        if section.get('bundle_key', False):
            if section.get('bundle_intermediate', False):
                for suffix in ('_group', '_owner', '_perms'):
                    setting = 'certificate' + suffix
                    if setting in section:
                        warnings.append('setting "{}" does not apply when '
                                        '"bundle_key" and "bundle_'
                                        'intermediate" are both true'
                                        .format(setting))
        else:
            if 'bundle_order' in section:
                warnings.append('setting "bundle_order" does not apply when '
                                '"bundle_key" is false')

        if section.get('bundle_intermediate', False):
            if 'intermediate_path' in section:
                warnings.append('setting "intermediate_path" does not apply '
                                'when "bundle_intermediate" is true')

        if 'reload_command' not in section:
            if 'reload_timeout' in section:
                warnings.append('setting "reload_timeout" does not apply '
                                'when a "reload_command" is not provided')

        for setting, value in CFG_DEFAULT_SETTINGS.items():
            section.setdefault(setting, value)
        if g_args.ca_file is not None:
            section.setdefault('ca_file', g_args.ca_file)
        if g_args.ca_path is not None:
            section.setdefault('ca_path', g_args.ca_path)

        if 'certificate_path' not in section:
            errors.append('Missing setting "certificate_path"')
        if section['verify_subject_cn'] and \
           'expected_subject_cn' not in section:
            errors.append('Missing setting "expected_subject_cn"; either '
                          'provide it or set "verify_subject_cn" to false')

        for setting in ('certificate_owner', 'key_owner'):
            try:
                section[setting] = resolve_user_name(section[setting])
            except (KeyError, ValueError):
                errors.append('Setting "{}" does not specify a known '
                              'user name or user id'.format(setting))
        for setting in ('certificate_group', 'key_group'):
            try:
                section[setting] = resolve_group_name(section[setting])
            except (KeyError, ValueError):
                errors.append('Setting "{}" does not specify a known '
                              'group name or group id'.format(setting))
        for setting in ('certificate_perms', 'key_perms'):
            try:
                section[setting] = int(section[setting], base=8)
            except ValueError:
                errors.append('Setting "{}" could not be interpreted '
                              'as an octal number'.format(setting))

    heading = None
    if warnings:
        warnings = ['    Warning, ' + x for x in warnings]
        heading = 'Warnings' if len(warnings) > 1 else 'Warning'
    if errors:
        errors = ['    ' + x for x in errors]
        heading = 'Errors' if len(errors) > 1 else 'Error'
    if heading is not None:
        heading = '{} in configuration file "{}" section "{}":' \
                  .format(heading, g_args.config_file, name)

    return (heading, errors, warnings)

def interact_with_sender(config):
    '''
    Processes input from the sender.  Identifies the applicable configuration,
    then extracts the certificates and, if provided, private key.
    '''
    sender = pexpect.fdpexpect.fdspawn(sys.stdin,
                                       timeout=g_args.timeout,
                                       maxread=20000,
                                       encoding='utf-8')

    try:
        sender.expect(r'^(\w+)\r?\n')
        name = sender.match.group(1)
        if name not in config:
            print('Unknown configuration')
            raise BadConfigException('Aborting, no configuration section '
                                     'for "{}"'
                                     .format(name))

        section = config[name]
        header, errors, warnings = check_configuration_section(name, section)
        if errors:
            print('Error in configuration')
            raise BadConfigException('\n'.join([header] + errors + warnings))
        elif warnings:
            print('\n'.join([header] + warnings), file=sys.stderr)

        certificates = []
        key = None

        while True:
            scratch = []

            sender.expect([
                r'^-----BEGIN ((?:X509 |TRUSTED |)CERTIFICATE)-----\r?\n',
                r'^-----BEGIN ((?:RSA )?PRIVATE KEY)-----\r?\n',
                r'^()\r?\n',
                pexpect.EOF,
            ])
            if sender.match is pexpect.EOF:
                break
            elif not sender.match.group(1):
                continue
            elif sender.match.group(1).endswith('PRIVATE KEY') and \
                 key is not None:
                raise BadSenderException('Aborting, received more than one '
                                         'private key')

            scratch.append(sender.match.group(0))

            end_pattern = r'(?:^|\n)-----END ({})-----\r?\n' \
                          .format(sender.match.group(1))
            sender.expect(end_pattern)
            scratch.append(sender.before)
            scratch.append(sender.match.group(0))

            if sender.match.group(1).endswith('PRIVATE KEY'):
                key = ''.join(scratch).replace('\r', '')
            else:
                certificates.append(''.join(scratch).replace('\r', ''))

    except pexpect.EOF:
        raise BadSenderException('Aborting, unexpected EOF reading from sender')

    except pexpect.TIMEOUT:
        raise BadSenderException('Aborting, timed out reading from sender')

    finally:
        sender.close()

    if not certificates:
        raise BadSenderException('Did not receive any certificates')

    return (section, certificates, key)

def verify_certificate_chain(cert_objects):
    prior_issuer = cert_objects[0].get_issuer()
    for cert_object in cert_objects[1:]:
        if prior_issuer != cert_object.get_subject():
            raise BadCertificateException('Error, did not receive a '
                                          'well-formed certificate chain '
                                          'from sender')
        prior_issuer = cert_object.get_issuer()

def verify_certificate_times(cert_objects):
    now = time.strftime('%Y%m%d%H%M%SZ', time.gmtime()).encode()
    for cert_object in cert_objects:
        if not cert_object.get_notBefore() <= now <= cert_object.get_notAfter():
            raise BadCertificateException('Error, received a certificate '
                                          'from sender that is not currently '
                                          'valid:\n' +
                                          str(cert_object.get_subject()))

def verify_certificate_subject_cn(cert_object, expected_cn):
    for ntype, nvalue in cert_object.get_subject().get_components():
        if ntype == b'CN' and nvalue == expected_cn.encode():
            break
    else:
        raise BadCertificateException('Error, received a certificate from '
                                      'sender that does not have the expected '
                                      'subject CN')

def read_key_from_file(key_file_name):
    reacquire_privileges()
    try:
        with open(key_file_name, 'rt') as key_file:
            st = os.stat(key_file.fileno())
            if st.st_size > 50000:
                raise BadKeyException('Error, refusing to load private key '
                                      'from unexpectedly large file')
            remaining = st.st_size
            chunks = []
            while remaining > 0:
                chunk = key_file.read(remaining)
                if len(chunk) == 0:
                    break
                remaining -= len(chunk)
                chunks.append(chunk)
            data = ''.join(chunks)
    except IOError as e:
        raise BadConfigException('Error reading key file:\n' + str(e))
    finally:
        drop_privileges()

    match = re.search(r'^-----BEGIN ((?:RSA )?PRIVATE KEY)-----\r?\n.*?'
                      r'^-----END \1-----\r?\n',
                      data,
                      re.MULTILINE | re.DOTALL)
    if not match:
        raise BadKeyException('Error, could not find a PEM-encoded private '
                              'key in the configured key file')
    return match.group(0)

def verify_certificate_matches_key(cert_object, key_object):
    method = getattr(ssl, 'TLS_METHOD', None)
    if method is None:
        method = ssl.TLSv1_METHOD
    ctx = ssl.Context(method)
    ctx.use_certificate(cert_object)
    ctx.use_privatekey(key_object)
    try:
        ctx.check_privatekey()
    except ssl.Error:
        raise BadCertificateException('Error, certficate from sender does '
                                      'not match private key')

def verify_certificate_issued_by_trusted_ca(config, cert_objects):
    store = ssl_crypto.X509Store()
    if 'ca_file' in config:
        store.load_locations(cafile=config['ca_file'], capath=None)
    if 'ca_path' in config:
        store.load_locations(cafile=None, capath=config['ca_path'])
    ctx = ssl_crypto.X509StoreContext(store, cert_objects[0], cert_objects[1:])
    try:
        ctx.verify_certificate()
    except ssl_crypt.X509StoreContextError as e:
        raise BadCertificateException('Error, could not verify certificate '
                                      'from sender was issued by a trusted '
                                      'CA:\n' + str(e))

def perform_verifications(config, certificates, key, key_file_name):
    try:
        cert_objects = [ssl_crypto.load_certificate(
                                ssl_crypto.FILETYPE_PEM, x.encode())
                        for x in certificates]
    except ssl_crypto.Error as e:
        raise BadCertificateException('Error loading a certificate from '
                                      'sender:\n' + str(e))

    cannot_reverse = False

    if config['verify_chain']:
        try:
            verify_certificate_chain(cert_objects)
        except BadCertificateException:
            certificates.reverse()
            cert_objects.reverse()
            verify_certificate_chain(cert_objects)
        cannot_reverse = True

    if config['verify_times']:
        verify_certificate_times(cert_objects)

    if config['verify_subject_cn']:
        expected_cn = config['expected_subject_cn']
        try:
            verify_certificate_subject_cn(cert_objects[0], expected_cn)
        except BadCertificateException as e:
            if cannot_reverse:
                raise e
            certificates.reverse()
            cert_objects.reverse()
            verify_certificate_subject_cn(cert_objects[0], expected_cn)
        cannot_reverse = True

    if config['verify_matching_key'] and key is None:
        if key_file_name is None:
            raise BadConfigException('Error, "verify_matching_key" is true, '
                                     'but we do not have a private key to '
                                     'check certificate from sender against')
        key = read_key_from_file(key_file_name)

    if key is not None:
        try:
            key_object = ssl_crypto.load_privatekey(
                                 ssl_crypto.FILETYPE_PEM, key.encode())
            key_object.check()
        except TypeError:
            # This happens if the key is non-RSA; only RSA keys support check()
            pass
        except ssl_crypto.Error as e:
            raise BadKeyException('Error loading private key:\n' + str(e))

    if config['verify_matching_key']:
        try:
            verify_certificate_matches_key(cert_objects[0], key_object)
        except BadCertificateException as e:
            if cannot_reverse:
                raise e
            certificates.reverse()
            cert_objects.reverse()
            verify_certificate_matches_key(cert_objects[0], key_object)
        cannot_reverse = True

    #if config['verify_trusted_ca']:
    #    verify_certificate_issued_by_trusted_ca(config, cert_objects)

def write_one_file(file_name, data, config, setting_prefix):
    with open(file_name, 'wb') as f:
        f.write(data.encode())
    uid, gid = (config[setting_prefix + x] for x in ('owner', 'group'))
    if os.geteuid() == 0:
        os.chown(file_name, uid, gid)
    os.chmod(file_name, config[setting_prefix + 'perms'])

def backup_one_file(file_name, backup_file_name):
    try:
        with open(file_name, 'rb') as f:
            data = f.read()
            s = os.stat(f.fileno())
    except FileNotFoundError:
        return False

    with open(backup_file_name, 'wb') as f:
        f.write(data)
    if os.geteuid() == 0:
        os.chown(backup_file_name, s.st_uid, s.st_gid)
    os.chmod(backup_file_name, stat.S_IMODE(s.st_mode))
    os.utime(backup_file_name, ns=(s.st_atime_ns, s.st_mtime_ns))
    return True

def install_files(config, certificates, key):
    certificate_data = []
    intermediate_data = []
    key_data = ''

    if config['bundle_intermediate']:
        certificate_data = certificates[0:]
    else:
        certificate_data = certificates[0:1]
        intermediate_data = certificates[1:]

    if not config['intermediate_order'] == 'ca_last':
        certificate_data.reverse()
        intermediate_data.reverse()

    if config['bundle_key']:
        if config['bundle_order'] == 'key_first':
            key_data = key + '\n'.join(certificate_data)
        else:
            key_data = '\n'.join(certificate_data) + key
        certificate_data = []
    elif key is not None:
        key_data = key

    certificate_data = '\n'.join(certificate_data)
    intermediate_data = '\n'.join(intermediate_data)

    tmpsuffix = '.new-{}'.format(os.getpid())

    old_umask = os.umask(0o077)
    written = []
    backed_up = set()
    installed = []
    try:
        for thing, prefix in (
            ('certificate', 'certificate_'),
            ('intermediate', 'certificate_'),
            ('key', 'key_')
        ):
            data = locals().get(thing + '_data')
            file_name = config.get(thing + '_path')
            if thing == 'key' and config['bundle_key']:
                file_name = config['certificate_path']
            if data and file_name:
                written.append(file_name)
                write_one_file(file_name + tmpsuffix, data, config, prefix)

        for file_name in written:
            if backup_one_file(file_name, file_name + '.bak'):
                backed_up.add(file_name)

        while written:
            file_name = written[-1]
            os.rename(file_name + tmpsuffix, file_name)
            installed.append(written.pop())

    except OSError as e:
        recovered = True
        for tmpfile in [x + tmpsuffix for x in written]:
            try:
                os.unlink(tmpfile)
            except OSError:
                pass

        for file_name in installed:
            try:
                if file_name in backed_up:
                    os.rename(file_name + '.bak', file_name)
                else:
                    os.unlink(file_name)
            except OSError:
                recovered = False

        msgs = []
        msgs.append('An error occurred installing the new certificates or key:')
        msgs.append('    ' + str(e))
        if not recovered:
            msgs.append('    The certificate and key files may have been left '
                        'in an inconsistent state.  Please check them and make '
                        'any necessary corrections.')
        raise UpdateFailedException('\n'.join(msgs))

    finally:
        os.umask(old_umask)

def reload_service(config):
    proc = subprocess.Popen(
        config['reload_command'],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        preexec_fn=lambda: os.setpgid(0, 0))

    timedout = False
    try:
        try:
            output, _ = proc.communicate(timeout=config['reload_timeout'])
        except subprocess.TimeoutExpired:
            timedout = True
            os.kill(-proc.pid, signal.SIGTERM)
            output, _ = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        os.kill(-proc.pid, signal.SIGKILL)
        output, _ = proc.communicate()

    if proc.returncode != 0:
        msgs = []
        msgs.append('An error occurred restarting the associated service:')
        if timedout:
            msgs.append('    Process timed out and was killed.')
        elif proc.returncode > 0:
            msgs.append('    Process exited with return code {}.'
                        .format(proc.returncode))
        else:
            msgs.append('    Process died due to signal {}.'
                        .format(-proc.returncode))
        output = str(output, encoding='utf-8')
        output = output.strip('\r\n')
        if output:
            msgs.append('>>>> OUTPUT >>>>')
            msgs.append(output)
            msgs.append('<<<<<<<<<<<<<<<<')
        raise UpdateFailedException('\n'.join(msgs))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ca-file')
    parser.add_argument('--ca-path',
                        default=DEFAULT_CA_PATH)
    parser.add_argument('--no-ca-path',
                        dest='ca_path',
                        action='store_const',
                        const=None)
    parser.add_argument('--check-config',
                        action='store_true')
    parser.add_argument('--config-file',
                        default=DEFAULT_CONFIG_FILE)
    parser.add_argument('--set-effective-user',
                        default='nobody')
    parser.add_argument('--timeout',
                        type=int,
                        default=10)
    parser.add_argument('--no-set-effective-user',
                        dest='set_effective_user',
                        action='store_const',
                        const=None)
    global g_args
    g_args = parser.parse_args()

    drop_privileges()

    config = load_configuration()

    if g_args.check_config:
        messages = []
        had_errors = False
        for name, section in config.items():
            header, errors, warnings = check_configuration_section(name,
                                                                   section)
            if errors:
                had_errors = True
            if header is not None:
                messages.extend([header] + errors + warnings)
        if had_errors:
            raise BadConfigException('\n'.join(messages))
        elif messages:
            print('\n'.join(messages), file=sys.stderr)
        return

    config, certificates, key = interact_with_sender(config)

    key_file_name = config.get('key_path')
    if config['bundle_key']:
        key_file_name = config['certificate_path']
    if key is not None and key_file_name is None:
        raise BadConfigException('Error, received a private key from sender, '
                                 'but no destination for it is configured',)

    if [x for x in config if x.startswith('verify_') and config[x]]:
        perform_verifications(config, certificates, key, key_file_name)

    reacquire_privileges()

    install_files(config, certificates, key)

    if 'reload_command' in config:
        reload_service(config)

if __name__ == '__main__':
    try:
        main()
    except CertReceivePyException as e:
        print(str(e), file=sys.stderr)
        sys.exit(e.EXITCODE)
