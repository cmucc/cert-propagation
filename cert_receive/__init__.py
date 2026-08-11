# Copyright (C) 2022-2026 Keith Allen Bare II
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

'''
Python package implementing a cert_receive script that performs TLS/SSL
certificate installation.

WARNING: only the main method should be considered a public interface.  All
other methods and variables should be considered internal to the package and
may not maintain a stable API.
'''

import argparse
import errno
import grp
import json
import locale
import os
import pwd
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time

try:
    from importlib.metadata import version as pkg_version
except ImportError:
    try:
        from importlib_metadata import version as pkg_version
    except ImportError:
        def pkg_version(_):
            return '0.3'

import OpenSSL.SSL as ssl
import OpenSSL.crypto as ssl_crypto

from . import mini_expect

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

g_args = None #pylint: disable=useless-suppression,invalid-name; this is a
              #        global variable, but pylint thinks it's a constant

def resolve_user_name(user_name):
    '''
    Attempts to determine a UID for the specified user_name.  The caller can
    force interpretation of a numeric UID by providing the UID prefixed by a
    '#' character.  If no matching user name is found in the password
    database, 'root' is treated as UID 0 while decimal strings are
    interpreted as numeric UIDs.

    Raises KeyError if user_name could not be resolved.
    '''
    if user_name.startswith('#'):
        return int(user_name[1:])
    try:
        pwent = pwd.getpwnam(user_name)
        return pwent.pw_uid
    except KeyError:
        if user_name == 'root':
            return 0
        if not user_name.isdecimal():
            raise
        return int(user_name)

def resolve_group_name(group_name):
    '''
    Attempts to determine a GID for the specified group_name.  The caller
    can force interpretation of a numeric GID by providing the GID prefixed
    by a '#' character.  If no matching user name is found in the password
    database, 'root' and 'wheel' are treated as GID 0 while decimal strings
    are interpreted as numeric GIDs.

    Raises KeyError if group_name could not be resolved.
    '''
    if group_name.startswith('#'):
        return int(group_name[1:])
    try:
        grent = grp.getgrnam(group_name)
        return grent.gr_gid
    except KeyError:
        if group_name in ('root', 'wheel'):
            return 0
        if not group_name.isdecimal():
            raise
        return int(group_name)

def drop_privileges():
    '''
    Temporarily drops root privileges when configured to do so.  To be used
    during parsing/validation steps, to reduce the surface area of any
    vulnerabilities that might exist in that processing.
    '''
    if g_args.set_effective_user is not None:
        try:
            os.seteuid(resolve_user_name(g_args.set_effective_user))
        except OSError as e:
            raise BadConfigException('Error dropping privileges') from e

def reacquire_privileges():
    '''
    Regains root privileges if the program was started as root and dropped
    privileges earlier.
    '''
    if g_args.set_effective_user is not None and os.geteuid() != 0:
        os.seteuid(0)

CFG_COMMENT_REGEX = re.compile(r'^#')

def load_configuration(config_in):
    '''
    Parses the configuration file and returns the parsed configuration.
    '''
    config_file_name = g_args.config_file
    try:
        config = json.load(config_in)
    except (IOError, json.JSONDecodeError) as e:
        action = 'parsing' if isinstance(e, json.JSONDecodeError) else 'reading'
        raise BadConfigException('Error {} configuration file "{}":\n{}'
                                 .format(action, config_file_name, str(e))) \
              from e

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

#: Indicates the supported configuration keys and the types their values
#: should have.
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
    'if_no_intermediate':       frozenset(('empty', 'preserve', 'unlink')),
    'intermediate_order':       frozenset(('ca_first', 'ca_last')),
    'intermediate_path':        str,
    'key_group':                str,
    'key_owner':                str,
    'key_path':                 str,
    'key_perms':                str,
    'openssl_ciphers':          str,
    'reload_command':           str,
    'reload_timeout':           int,
    'verify_chain':             bool,
    'verify_dates':             bool,
    'verify_loadable':          bool,
    'verify_matching_key':      bool,
    'verify_subject_cn':        bool,
    'verify_trusted_ca':        bool,
}

#: Indicates the default values for configuration keys.
CFG_DEFAULT_SETTINGS = {
    'bundle_intermediate':      False,
    'bundle_key':               False,
    'bundle_order':             'key_first',
    'certificate_group':        'root',
    'certificate_owner':        'root',
    'certificate_perms':        '0644',
    'if_no_intermediate':       'empty',
    'intermediate_order':       'ca_last',
    'key_group':                'root',
    'key_owner':                'root',
    'key_perms':                '0600',
    'reload_timeout':           50,
    'verify_chain':             True,
    'verify_dates':             True,
    'verify_loadable':          True,
    'verify_matching_key':      True,
    'verify_subject_cn':        True,
    'verify_trusted_ca':        True,
}

#: Mapping of Python types to the JSON type that parses into the Python type.
#: Used for error messages during configuration validation.
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
    Also sets default values for any settings that were not provided in the
    configuration section.

    Returns a 3-tuple consisting of: 1) a string indicating the overall
    result of the configuration check, 2) a list of configuration errors,
    and 3) a list of configuration warnings.
    '''
    errors = []
    warnings = []

    def check_one(what, parsed, expected):
        expected_type = expected
        if isinstance(expected, frozenset):
            expected_type = str
        if not isinstance(parsed, expected_type):
            errors.append('{} should be a JSON {}'
                          .format(what, CFG_TYPE_TO_JSON[expected_type]))
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
                # The user provided an intermediate_path, despite the fact
                # we're bundling the intermediates.  Clear the key from the
                # configuration, to make sure we do not muck with the
                # indicated path based on the if_no_intermediate setting.
                del section['intermediate_path']
            if section.get('if_no_intermediate', '') == 'unlink':
                warnings.append('ignoring "if_no_intermediate" value of '
                                '"unlink", which does not make sense when '
                                '"bundle_intermediate" is true')
                del section['if_no_intermediate']

        if 'reload_command' not in section:
            if 'reload_timeout' in section:
                warnings.append('setting "reload_timeout" does not apply '
                                'when a "reload_command" is not provided')

        try:
            section['openssl_ciphers'].encode('ascii', errors='strict')
        except UnicodeError:
            errors.append('setting "openssl_ciphers" should not include non-'
                          'ASCII characters')
        except KeyError:
            pass

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
    if heading is None:
        heading = 'Configuration file "{}" section "{}" has no errors or ' \
                  'warnings'.format(g_args.config_file, name)
    else:
        heading = '{} in configuration file "{}" section "{}":' \
                  .format(heading, g_args.config_file, name)

    return (heading, errors, warnings)

# From RFC 7468
PEM_LABEL = re.compile(br'(?:[\x21-\x2c\x2e-\x7e]'
                       br' (?:[\ -]?[\x21-\x2c\x2e-\x7e])*)?$',
                       re.VERBOSE)

KEY_LABELS = frozenset([b'PRIVATE KEY', b'RSA PRIVATE KEY'])
CERTIFICATE_LABELS = frozenset([b'CERTIFICATE', b'TRUSTED CERTIFICATE',
                                b'X.509 CERTIFICATE', b'X509 CERTIFICATE'])

PEM_BLOCK_MAXIMUM = 20000
OVERALL_PEM_MAXIMUM = 200000

def interact_with_sender(full_config):
    '''
    Processes input from the sender.  Identifies the applicable configuration,
    then extracts the certificates and, if provided, the private key.

    Returns a 3-tuple consisting of: 1) the applicable configuration section,
    as a dictionary, 2) a list of received certificates, 3) the received
    private key, or None if no private key was sent.

    Raises BadConfigException if the configuration name presented by the
    sender is unknown or if there are errors in the associated configuration
    section.

    Raises BadSenderException if the sender does not follow protocol or
    provide the expected data.
    '''
    sender = mini_expect.MiniExpect(os.dup(sys.stdin.fileno()),
                                    timeout=g_args.receive_timeout,
                                    maxread=int(PEM_BLOCK_MAXIMUM / 4),
                                    maxbuffer=PEM_BLOCK_MAXIMUM)

    try:
        # We expect the input to be ASCII-compatible.  E.g., UTF-8, where
        # multibyte encodings never contain bytes from 7-bit ASCII.  Hence
        # it should be safe to apply byte regular expressions where all
        # literals are ASCII.
        sender.expect(br'^([^\r\n]*)[\r\n]')
        try:
            name = sender.match.group(1).decode('utf-8')
        except UnicodeError as e:
            raise BadSenderException('Aborting, could not decode '
                                     'configuration name') from e
        if not re.match(r'[-\.\w]+$', name):
            raise BadSenderException('Aborting, received an invalid '
                                     'configuration name')
        if name not in full_config:
            print('Unknown configuration')
            raise BadConfigException('Aborting, no configuration section '
                                     'for "{}"'
                                     .format(name))

        section = full_config[name]
        header, errors, warnings = check_configuration_section(name, section)
        if errors:
            print('Error in configuration')
            raise BadConfigException('\n'.join([header] + errors + warnings))
        if warnings:
            print('\n'.join([header] + warnings), file=sys.stderr)

        total_bytes = 0
        certificates = []
        key = None

        adjacent = False
        while True:
            scratch = []

            idx = sender.expect([
                br'-----BEGIN (?P<label>[^\r\n]*?)-----',
                br'-----......(?<!BEGIN )',
                br'^[^\r\n]*[\r\n]',
                mini_expect.EOF,
            ])
            if adjacent and sender.before.startswith(b'-'):
                # Prior END delimiter had extra trailing dash(es)
                raise BadSenderException('Received invalid or non-END '
                                         'delimiter for PEM data block')
            if idx == 2 and b'-----' not in sender.match.group(0):
                # Line that does not look like a PEM delimiter
                if adjacent and sender.match.group(0).startswith(b'-'):
                    raise BadSenderException('Received invalid or non-END '
                                             'delimiter for PEM data block')
                adjacent = False
                continue
            if idx == 3:
                # EOF
                break
            if idx != 0 or sender.before.endswith(b'-') or \
               not PEM_LABEL.match(sender.match.group('label')):
                raise BadSenderException('Received invalid or non-BEGIN '
                                         'delimiter for PEM data block')

            what = sender.match.group('label')
            if what in KEY_LABELS:
                if key is not None:
                    raise BadSenderException('Aborting, received more than '
                                             'one private key')
            elif what not in CERTIFICATE_LABELS:
                raise BadSenderException('Received unrecognized PEM data '
                                         'block type')

            block_bytes = sender.match.end() - sender.match.start()
            if total_bytes + block_bytes > OVERALL_PEM_MAXIMUM:
                raise BadSenderException('Overall PEM data exceeds the '
                                         'maximum allowable length')
            scratch.append(sender.match.group(0))

            idx = sender.expect([
                br'-----END (?P<label>[^\r\n]*?)-----',
                br'-----....(?<!END )',
            ])
            if sender.before.startswith(b'-'):
                # BEGIN delimiter had extra trailing dash(es)
                raise BadSenderException('Received invalid or non-BEGIN '
                                         'delimiter for PEM data block')
            if idx != 0 or sender.before.endswith(b'-') or \
               not PEM_LABEL.match(sender.match.group('label')):
                raise BadSenderException('Received invalid or non-END '
                                         'delimiter for PEM data block')

            what2 = sender.match.group('label')
            if what != what2:
                raise BadSenderException('Received END delimiter of PEM data '
                                         'block with the wrong type')

            adjacent = True

            block_bytes = (block_bytes + len(sender.before) +
                           sender.match.end() - sender.match.start() + 1)
            total_bytes = total_bytes + block_bytes
            if block_bytes > PEM_BLOCK_MAXIMUM:
                raise BadSenderException('PEM data block exceeds the '
                                         'maximum allowable length')
            if total_bytes > OVERALL_PEM_MAXIMUM:
                raise BadSenderException('Overall PEM data exceeds the '
                                         'maximum allowable length')

            scratch.extend([sender.before, sender.match.group(0), b'\n'])
            pem_item = ''.join(part.decode('ascii') for part in scratch)

            if what.endswith(b'PRIVATE KEY'):
                key = pem_item
            else:
                certificates.append(pem_item)

    except UnicodeError as e:
        raise BadSenderException('Aborting, invalid PEM block with non-ASCII '
                                 'characters from sender') from e

    except mini_expect.EOF as e:
        raise BadSenderException('Aborting, unexpected EOF reading from sender') from e

    except mini_expect.TIMEOUT as e:
        raise BadSenderException('Aborting, timed out reading from sender') from e

    except mini_expect.BufferFull as e:
        raise BadSenderException('Aborting, received excess data from sender') from e

    finally:
        sender.close()

    if not certificates:
        raise BadSenderException('Did not receive any certificates')

    return (section, certificates, key)

def system_encoding():
    '''
    Returns the encoding specified by the locale currently in use by the
    system C library.  The locale.setlocale method should be called prior
    to this routine, to ensure that the C library's current locale is
    initialized.
    '''
    # Reading the documentation for various Python versions, it appears that
    # a call to local.setlocale during one-time initialization, followed by
    # locale.getlocale is the best way to determine the encoding to use
    # based on system/user settings across a wide range of Python versions.
    # Python < 3.10 does not have locale.getencoding.  On the other hand,
    # the locale.getpreferredencoding API available in earlier versions can
    # lie in Python >= 3.7.
    _, encoding = locale.getlocale()
    if encoding is None:
        encoding = 'ascii'
    return encoding

def read_data_to_preserve(config, certificates, key):
    if key is None and config['bundle_key']:
        # We're bundling the key with the certificate, but the sender did not
        # provide a key.  We'll need to read the existing key so that we can
        # rewrite it in the new bundle.
        key = read_key_from_file(config['certificate_path'],
                                 max_size=OVERALL_PEM_MAXIMUM)

    if (len(certificates) == 1 and config['bundle_intermediate'] and
            config['if_no_intermediate'] == 'preserve'):
        # We're bundling intermediates with the certificate and need to
        # preserve any existing intermediates because the sender did not
        # provide any.  To do so, we'll need to read the intermediates from
        # the existing bundle so that we can rewrite them in the new bundle.
        preserved = read_certificates_from_file(config['certificate_path'])
        if config['intermediate_order'] == 'ca_last':
            certificates = certificates + preserved[1:]
        else:
            certificates = preserved[0:-1] + certificates
            certificates.reverse()

    return certificates, key

def verify_certificate_chain(cert_objects):
    '''
    Validates the provided cert_objects chain, e.g., the issuer of the first
    certificate is the subject of the second, the issuer of the second is the
    subject of the third, and so forth.

    Raises BadCertificateException if the cert_objects do not form a chain.
    '''
    prior_issuer = cert_objects[0].get_issuer()
    for cert_object in cert_objects[1:]:
        if prior_issuer != cert_object.get_subject():
            raise BadCertificateException('Error, did not receive a '
                                          'well-formed certificate chain '
                                          'from sender')
        prior_issuer = cert_object.get_issuer()

def verify_certificate_dates(cert_objects):
    '''
    Validates that the provided cert_objects are valid now.

    Raises BadCertificateException if any certificate is not valid now.
    '''
    now = time.strftime('%Y%m%d%H%M%SZ', time.gmtime()).encode(system_encoding())
    for cert_object in cert_objects:
        if not cert_object.get_notBefore() <= now <= cert_object.get_notAfter():
            raise BadCertificateException('Error, received a certificate '
                                          'from sender that is not currently '
                                          'valid:\n' +
                                          str(cert_object.get_subject()))

def verify_certificate_subject_cn(cert_object, expected_cn):
    '''
    Validates that the subject of the provided cert_object has a common name
    equal to expected_cn.

    Raises BadCertificateException if the certificate subject does not contain
    the expected common name.
    '''
    for ntype, nvalue in cert_object.get_subject().get_components():
        if ntype == b'CN' and nvalue == expected_cn.encode(system_encoding()):
            break
    else:
        raise BadCertificateException('Error, received a certificate from '
                                      'sender that does not have the expected '
                                      'subject CN')

def read_from_file(file_name, max_size=OVERALL_PEM_MAXIMUM):
    '''
    Helper for reading data from a file.  Re-acquires privileges, opens the
    target file, and then drops privileges in order to support reading files
    with restrictive permissions.

    Raises OSError or a derivative if an error occurs.  Indicates an EFBIG
    errno if the file is larger than max_size.
    '''
    reacquire_privileges()

    try:
        #pylint: disable=consider-using-with; try/finally is less awkward,
        #        given the goal to drop privileges immediately after the open
        fd = open(file_name, 'rt', encoding=system_encoding(), errors='replace')
    finally:
        drop_privileges()

    try:
        st = os.stat(fd.fileno())
        if st.st_size > max_size:
            raise OSError(errno.EFBIG,
                          'Refusing to load data from unexpectedly large file',
                          file_name)
        remaining = st.st_size
        chunks = []
        while remaining > 0:
            chunk = fd.read(remaining)
            if len(chunk) == 0:
                break
            remaining -= len(chunk)
            chunks.append(chunk)
        data = ''.join(chunks)

    finally:
        fd.close()

    return data

def find_pem_block(data, labels, pos=0):
    '''
    Extracts the first PEM block in data[pos:] with a label matching
    label_regex.

    Returns a (block, endpos) pair, where endpos is the first position in
    data after the matching block.
    '''
    dashes = '-----'
    labels = [x.decode('ascii') for x in labels]
    begin_pat = re.compile('-----BEGIN ({})-----'.format('|'.join(labels)))
    end_pat = re.compile('-----END ({})-----'.format('|'.join(labels)))

    while pos < len(data):
        begin = begin_pat.search(data, pos)
        if not begin:
            return None, -1
        if begin.start() > 0 and data[begin.start() - 1] == '-':
            leading = data[max(0, begin.start() - len(dashes) - 1):begin.start()]
            if leading[-len(dashes):] != dashes or leading[-len(dashes) - 1:-len(dashes)] == '-':
                # BEGIN delimiter candidate has too many leading dashes
                pos = begin.end() - len(dashes)
                continue

        next_pos = data.find(dashes, begin.end())
        if next_pos == -1:
            return None, -1
        if begin.end() < next_pos and data[begin.end()] == '-':
            # BEGIN delimiter candidate has too many trailing dashes
            pos = next_pos
            continue

        end = end_pat.search(data, next_pos)
        if not end:
            return None, -1
        if end.start() > next_pos:
            # we do not have an END delimiter at next_pos, or it is an
            # END delimiter with too many leading dashes
            pos = next_pos
            continue
        if end.end() < len(data) and data[end.end()] == '-':
            trailing = data[end.end():end.end() + len(dashes) + 1]
            if trailing[0:len(dashes)] != dashes or trailing[len(dashes):] == '-':
                # END delimiter has too many trailing dashes
                pos = end.end() - len(dashes)
                continue
        if begin.group(1) != end.group(1):
            # labels do not match
            pos = end.end()
            continue

        return data[begin.start():end.end()] + '\n', end.end()

    # we used up all of data
    return None, -1

def read_key_from_file(key_file_name, max_size=PEM_BLOCK_MAXIMUM):
    '''
    Reads and returns an already-installed PEM private key.

    Raises BadConfigException if there is an issue reading the key file.

    Raises BadKeyException if the key file does not appear to contain a PEM
    private key.
    '''
    try:
        data = read_from_file(key_file_name, max_size=max_size)
    except OSError as e:
        etype = BadKeyException if e.errno == errno.EFBIG else BadConfigException
        raise etype('Error reading key file:\n' + str(e)) from e

    key, _ = find_pem_block(data, KEY_LABELS)
    if key is None:
        raise BadKeyException('Error, could not find a PEM-encoded private '
                              'key in {!r}'
                              .format(key_file_name))
    return key

def read_certificates_from_file(cert_file_name):
    '''
    Reads and returns PEM certificates from an already installed certificate
    file.

    Raises OSError or a derivative if there is an issue reading the file.

    Raises BadCertificateException if the file does not appear to contain
    any PEM-encoded certificates.
    '''
    data = read_from_file(cert_file_name)
    certs = []

    pos = 0
    while pos != -1:
        cert, pos = find_pem_block(data, CERTIFICATE_LABELS, pos=pos)
        if cert is not None:
            certs.append(cert)

    if not certs:
        raise BadCertificateException('Error, could not find any PEM-'
                                      'encoded certificates in {!r}'
                                      .format(cert_file_name))
    return certs

def verify_certificate_matches_key(config, cert_object, key_object):
    '''
    Validates that the public key associated with cert_object and private
    key associated with key_object are a matching pair.

    Raises BadCertificateException if the certificate does not match the key.
    '''
    for method_name in ('TLS_METHOD', 'TLSv1_METHOD'):
        method = getattr(ssl, method_name, None)
        if method is not None:
            break
    ctx = ssl.Context(method)
    if 'openssl_ciphers' in config:
        ctx.set_cipher_list(config['openssl_ciphers'].encode(system_encoding()))
    ctx.use_certificate(cert_object)
    try:
        ctx.use_privatekey(key_object)
        ctx.check_privatekey()
    except ssl.Error as e:
        try:
            # Yuck, there's not a good way to programmatically examine the
            # error reason.
            # Exception's args attribute is a tuple of arguments.
            # For OpenSSL.SSL.Error, the args tuple has one argument, a list
            # of (lib, function, reason) string-triples.
            # If the args are in the expected form and the list has exactly
            # one element indicating a key mismatch, we'll indicate our
            # verification failed.  Otherwise we'll re-raise the exception
            # from OpenSSL.
            if (len(e.args[0]) == 1 and
                    re.search(r'\bkey\b.*\b(mis)?match\b', e.args[0][0][2])):
                raise BadCertificateException('Error, certficate from sender '
                                              'does not match private key') \
                      from e
        except TypeError:
            pass
        raise

def _verify_trust_python(config, cert_objects):
    '''
    Implementation of verify_certificate_issued_by_trusted_ca utilizing the
    pyOpenSSL module's X509StoreContext.  It requires a pyOpenSSL that is
    new enough to have the X509StoreContext.load_locations method.
    '''
    store = ssl_crypto.X509Store()
    if 'ca_file' in config:
        store.load_locations(cafile=config['ca_file'], capath=None)
    if 'ca_path' in config:
        store.load_locations(cafile=None, capath=config['ca_path'])
    ctx = ssl_crypto.X509StoreContext(store, cert_objects[0], cert_objects[1:])
    try:
        ctx.verify_certificate()
    except ssl_crypto.X509StoreContextError as e:
        raise BadCertificateException('Error, could not verify certificate '
                                      'from sender was issued by a trusted '
                                      'CA:\n' + str(e)) \
              from e

_openssl_executable = None  #pylint: disable=useless-suppression,invalid-name
_openssl_version = None     #pylint: disable=useless-suppression,invalid-name
_openssl_env = None         #pylint: disable=useless-suppression,invalid-name
                            #        these are all global variables, but pylint
                            #        thinks they're constants

def _verify_trust_openssl_subprocess(config, certificates):
    '''
    Implementation of verify_certificate_issued_by_trusted_ca utilizing an
    "openssl verify" subprocess.
    '''
    global _openssl_executable
    global _openssl_version
    global _openssl_env

    kwargs = {}
    # Fully drop root privileges when running openssl
    if os.getuid() == 0:
        euid = os.geteuid()
        if euid != 0:
            # It is safe to use preexec_fn since we do not run multiple
            # threads when validating trust.
            def permanently_drop_privileges():
                os.seteuid(0)
                os.setuid(euid)
            kwargs['preexec_fn'] = permanently_drop_privileges

    if _openssl_executable is None:
        _openssl_executable = os.getenv('OPENSSL', default='openssl')
        cmd = [_openssl_executable, 'version']
        with subprocess.Popen(args=cmd,
                              stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT,
                              **kwargs) as proc:
            output, _ = proc.communicate()

        match = re.search(
            br'\bOpenSSL\s+([0-9]+)(?:\.([0-9]+)(?:\.([0-9]+)([a-z])?)?)?',
            output
        )
        if match:
            def convert(x):
                try:
                    return int(x)
                except ValueError:
                    return x.decode(system_encoding(),
                                    errors='backslashreplace')
            _openssl_version = tuple(convert(match.group(ii))
                                     for ii in range(1, 5)
                                     if match.group(ii) is not None)
        else:
            _openssl_version = (99999,)
        _openssl_env = os.environ.copy()

    _openssl_env.pop('SSL_CERT_FILE', None)
    _openssl_env.pop('SSL_CERT_DIR', None)

    cmd = [_openssl_executable, 'verify']
    if 'ca_file' in config:
        cmd.append('-CAfile')
        cmd.append(config['ca_file'])
    else:
        if _openssl_version >= (1, 1):
            cmd.append('-no-CAfile')
        else:
            _openssl_env['SSL_CERT_FILE'] = '/dev/null'

    if 'ca_path' in config:
        cmd.append('-CApath')
        cmd.append(config['ca_path'])
    else:
        if _openssl_version >= (1, 1):
            cmd.append('-no-CApath')
        else:
            _openssl_env['SSL_CERT_DIR'] = '/dev/null'

    if _openssl_version >= (3,):
        cmd.append('-no-CAstore')

    intermediate_temp_file = None
    intermediate_temp_file_name = None

    try:
        if len(certificates) > 1:
            intermediate_temp_file = tempfile.NamedTemporaryFile(
                mode='wt',
                encoding=system_encoding(),
                prefix='cert_receive_intermediate_',
                suffix='.pem',
                delete=False,
            )
            intermediate_temp_file_name = intermediate_temp_file.name

            print(''.join(certificates[1:]), file=intermediate_temp_file)
            intermediate_temp_file.flush()
            intermediate_temp_file.close()
            intermediate_temp_file = None

            cmd.append('-untrusted')
            cmd.append(intermediate_temp_file_name)

        proc = subprocess.Popen(args=cmd,
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                env=_openssl_env,
                                **kwargs)
        timedout = False
        try:
            output, _ = proc.communicate(
                input=certificates[0].encode(system_encoding()),
                timeout=15,
            )
        except subprocess.TimeoutExpired:
            timedout = True
            try:
                os.kill(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            output, _ = proc.communicate()

        if proc.returncode != 0:
            etype = BadConfigException
            msgs = []
            msgs.append('Error verifying certificate from sender was issued '
                        'by a trusted CA:')
            if timedout:
                msgs.append('    "openssl verify" timed out and was killed.')
            elif proc.returncode > 0:
                etype = BadCertificateException
                msgs.append('    "openssl verify" exited with return code {}.'
                            .format(proc.returncode))
            else:
                msgs.append('    "openssl verify" died due to signal {}.'
                            .format(-proc.returncode))
            output = output.decode(system_encoding(), errors='backslashreplace')
            output = output.strip('\r\n')
            if output:
                msgs.append('>>>> OUTPUT >>>>')
                msgs.append(output)
                msgs.append('<<<<<<<<<<<<<<<<')
            raise etype('\n'.join(msgs))

    except OSError as e:
        raise BadConfigException('Error verifying certificate from sender '
                                 'was issued by a trusted CA:\n' + str(e)) \
              from e

    finally:
        if intermediate_temp_file is not None:
            intermediate_temp_file.close()
        if intermediate_temp_file_name is not None:
            os.unlink(intermediate_temp_file_name)

def verify_certificate_issued_by_trusted_ca(config, certificates, cert_objects):
    '''
    Validates that the received service certificate has a verification path to
    a trusted CA.

    Raises BadConfigException if a system error prevented verification from
    completing.

    Raises BadCertificateException if the service certificate failed
    verification.
    '''
    if hasattr(ssl_crypto.X509Store, 'load_locations'):
        _verify_trust_python(config, cert_objects)
    else:
        _verify_trust_openssl_subprocess(config, certificates)

def perform_verifications(config, certificates, key):
    cert_object_storage = []
    def get_cert_objects():
        """
        Helper for lazily parsing/loading the certificates.  If no
        verifications are configured, that work is avoided.
        """
        nonlocal cert_object_storage
        already_loaded = len(cert_object_storage)
        if already_loaded < len(certificates):
            try:
                cert_object_storage[already_loaded:] = [
                        ssl_crypto.load_certificate(ssl_crypto.FILETYPE_PEM,
                                                    x.encode(system_encoding()))
                        for x in certificates[already_loaded:]
                ]
            except ssl_crypto.Error as e:
                raise BadCertificateException('Error loading a certificate '
                                              'from sender:\n' + str(e)) \
                      from e
        return cert_object_storage

    intermediates_tried = False
    cannot_reverse = False
    def try_to_read_preserved_intermediates():
        nonlocal certificates
        nonlocal intermediates_tried
        nonlocal cannot_reverse
        if intermediates_tried:
            return
        intermediates_tried = True
        if config['if_no_intermediate'] != 'preserve' or len(certificates) > 1:
            return
        try:
            intermediates = read_certificates_from_file(config['intermediate_path'])
            if config['intermediate_order'] != 'ca_last':
                intermediates.reverse()
            certificates = certificates + intermediates
            cannot_reverse = True
        except (KeyError, OSError, BadCertificateException):
            # For any of several reasons, we couldn't read the intermediate
            # certificates we should be preserving.  We'll simply continue
            # attempting verifications without them.
            pass

    def make_key_object(kdata):
        """
        Helper for constructing a private key object from its PEM
        representation.
        """
        try:
            kobject = ssl_crypto.load_privatekey(ssl_crypto.FILETYPE_PEM,
                                                 kdata.encode(system_encoding()))
            try:
                kobject.check()
            except TypeError:
                # This happens if the key is non-RSA; only RSA keys support check()
                pass
        except ssl_crypto.Error as e:
            raise BadKeyException('Error loading private key:\n' + str(e)) from e
        return kobject

    if (key is not None and
            'key_path' not in config and
            not config['bundle_key']):
        raise BadConfigException('Error, received a private key from sender, '
                                 'but no destination for it is configured')
    if (len(certificates) > 1 and
           'intermediate_path' not in config and
           not config['bundle_intermediate']):
        raise BadConfigException('Error, received one or more intermediate '
                                 'certificates, but no destination for them '
                                 'is configured')

    key_object = None

    if config['verify_loadable']:
        _ = get_cert_objects()
        if key is not None:
            key_object = make_key_object(key)

    if config['verify_chain']:
        try_to_read_preserved_intermediates()
        try:
            verify_certificate_chain(get_cert_objects())
        except BadCertificateException:
            if cannot_reverse:
                raise
            certificates.reverse()
            get_cert_objects().reverse()
            verify_certificate_chain(get_cert_objects())
        cannot_reverse = True

    if config['verify_dates']:
        try_to_read_preserved_intermediates()
        verify_certificate_dates(get_cert_objects())

    if config['verify_subject_cn']:
        expected_cn = config['expected_subject_cn']
        try:
            verify_certificate_subject_cn(get_cert_objects()[0], expected_cn)
        except BadCertificateException:
            if cannot_reverse:
                raise
            certificates.reverse()
            get_cert_objects().reverse()
            verify_certificate_subject_cn(get_cert_objects()[0], expected_cn)
        cannot_reverse = True

    if config['verify_matching_key']:
        if key is None:
            try:
                key = read_key_from_file(config['key_path'])
            except KeyError as e:
                raise BadConfigException('Error, "verify_matching_key" is '
                                         'true, but we do not have a private '
                                         "key to check the sender's "
                                         'certificate against') \
                      from e
        if key_object is None:
            key_object = make_key_object(key)
        try:
            verify_certificate_matches_key(config,
                                           get_cert_objects()[0],
                                           key_object)
        except BadCertificateException:
            if cannot_reverse:
                raise
            certificates.reverse()
            get_cert_objects().reverse()
            verify_certificate_matches_key(config,
                                           get_cert_objects()[0],
                                           key_object)
        cannot_reverse = True

    if config['verify_trusted_ca']:
        try_to_read_preserved_intermediates()
        verify_certificate_issued_by_trusted_ca(config,
                                                certificates,
                                                get_cert_objects())

def write_one_file(file_name, data, config, setting_prefix):
    with open(file_name, 'wt', encoding=system_encoding()) as f:
        if data:
            f.write(data)
    uid, gid = (config[setting_prefix + x] for x in ('owner', 'group'))
    if os.geteuid() == 0:
        os.chown(file_name, uid, gid)
    os.chmod(file_name, config[setting_prefix + 'perms'])

BACKUP_NOEXIST = object()
BACKUP_SAMEDATA = object()
BACKUP_SUCCESS = object()
BACKUP_FAILED = object()

def backup_one_file(file_name, new_data, backup_file_name):
    try:
        with open(file_name, 'rb') as f:
            existing_data = f.read()
            s = os.stat(f.fileno())
    except FileNotFoundError:
        return BACKUP_NOEXIST

    if (new_data is not None and
            existing_data == new_data.encode(system_encoding())):
        return BACKUP_SAMEDATA

    with open(backup_file_name, 'wb') as f:
        f.write(existing_data)
    if os.geteuid() == 0:
        os.chown(backup_file_name, s.st_uid, s.st_gid)
    os.chmod(backup_file_name, stat.S_IMODE(s.st_mode))
    os.utime(backup_file_name, ns=(s.st_atime_ns, s.st_mtime_ns))
    return BACKUP_SUCCESS

def install_files(config, certificates, key):
    #pylint: disable=possibly-unused-variable; common installation logic is
    #        factored-out in way that utilizes dynamic variable access via locals()
    certificate_data = []
    intermediate_data = []
    key_data = ''

    if config['bundle_intermediate']:
        certificate_data = certificates[0:]
    else:
        certificate_data = certificates[0:1]
        intermediate_data = certificates[1:]

    if config['intermediate_order'] != 'ca_last':
        certificate_data.reverse()
        intermediate_data.reverse()

    if config['bundle_key']:
        if config['bundle_order'] == 'key_first':
            key_data = ''.join([key] + certificate_data)
        else:
            key_data = ''.join(certificate_data + [key])
        certificate_data = []
    elif key is not None:
        key_data = key

    certificate_data = ''.join(certificate_data)
    intermediate_data = ''.join(intermediate_data)

    intermediate_operation = None
    if not intermediate_data:
        intermediate_operation = config['if_no_intermediate']

    tmpsuffix = '.new-{}'.format(os.getpid())

    old_umask = os.umask(0o077)
    written_as_tmpfile = []
    written_data = []
    backed_up = {}
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
            do_install = bool(data)
            if thing == 'intermediate' and intermediate_operation == 'empty':
                do_install = True
            if do_install and file_name:
                written_as_tmpfile.append(file_name)
                written_data.append(data)
                write_one_file(file_name + tmpsuffix, data, config, prefix)

        for file_name, data in zip(written_as_tmpfile, written_data):
            try:
                backed_up[file_name] = backup_one_file(file_name, data, file_name + '.bak')
            except OSError:
                backed_up[file_name] = BACKUP_FAILED
                raise

        if intermediate_operation == 'unlink':
            file_name = config.get('intermediate_path')
            if file_name:
                try:
                    backed_up[file_name] = backup_one_file(file_name, None, file_name + '.bak')
                except OSError:
                    backed_up[file_name] = BACKUP_FAILED
                    raise

        # Reverse written_as_tmpfile so that working backwards popping
        # elements performs the renames in the same order the tmpfiles were
        # written above.  While this isn't necessary, it makes it easier to
        # understand what a test injecting a fault at an nth call will
        # affect-- for each step, an applicable certificate, intermediate
        # bundle, and key are manipulated in that order.
        written_as_tmpfile.reverse()
        try:
            while written_as_tmpfile:
                file_name = written_as_tmpfile[-1]
                os.rename(file_name + tmpsuffix, file_name)
                installed.append(written_as_tmpfile.pop())
        finally:
            written_as_tmpfile.reverse()

        if intermediate_operation == 'unlink':
            file_name = config.get('intermediate_path')
            if file_name:
                try:
                    os.unlink(file_name)
                    installed.append(file_name)
                except FileNotFoundError:
                    pass

    except OSError as e:
        recovered = True
        for tmpfile in [x + tmpsuffix for x in written_as_tmpfile]:
            try:
                os.unlink(tmpfile)
            except OSError:
                pass

        for file_name in installed:
            try:
                backup_state = backed_up.get(file_name)
                if backup_state is BACKUP_SUCCESS:
                    os.rename(file_name + '.bak', file_name)
                elif backup_state is BACKUP_NOEXIST:
                    try:
                        os.unlink(file_name)
                    except FileNotFoundError:
                        pass
                # The file_name will only end up in the installed list if we
                # obtained a non-failure result while backing it up.  Hence
                # any partial back-up for a file with a BACKUP_FAILED result
                # will still be unlinked when the remaining content of the
                # backed_up map is iterated below, assuming no errors during
                # the recovery processing.
                try:
                    del backed_up[file_name]
                except KeyError:
                    pass
            except OSError:
                recovered = False

        if recovered:
            for file_name, backup_state in backed_up.items():
                if backup_state in (BACKUP_SUCCESS, BACKUP_FAILED):
                    try:
                        os.unlink(file_name + '.bak')
                    except FileNotFoundError:
                        pass
                    except OSError:
                        if backup_state is BACKUP_FAILED:
                            # Failed back-ups may be incomplete, so we'll
                            # indicate there's a potential inconsistency if
                            # we couldn't remove it but it's still present.
                            recovered = False
                        # On the other hand, successful back-ups have
                        # consistent but non-useful content, since they'll
                        # be the same as some file we couldn't change for
                        # whatever reason.  Hence no need to flag that
                        # there may be an inconsistency.

        msgs = []
        msgs.append('An error occurred installing the new certificates or key:')
        msgs.append('    ' + str(e))
        if not recovered:
            msgs.append('    The certificate and key files may have been left '
                        'in an inconsistent state.  Please check them and make '
                        'any necessary corrections.')
        raise UpdateFailedException('\n'.join(msgs)) from e

    finally:
        os.umask(old_umask)

def reload_service(config):
    #pylint: disable=subprocess-popen-preexec-fn; we do not run multiple
    #        threads when reloading services
    proc = subprocess.Popen(
        args=config['reload_command'],
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
    except (subprocess.TimeoutExpired, ProcessLookupError):
        try:
            os.kill(-proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
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
        output = output.decode(system_encoding(), errors='backslashreplace')
        output = output.strip('\r\n')
        if output:
            msgs.append('>>>> OUTPUT >>>>')
            msgs.append(output)
            msgs.append('<<<<<<<<<<<<<<<<')
        raise UpdateFailedException('\n'.join(msgs))

def version():
    my_version = pkg_version('cert_receive')
    print('\n'.join([
        '{} version {}'.format(os.path.basename(sys.argv[0]), my_version),
        'Copyright (C) 2022-2026 Keith Allen Bare II',
        '',
        'This program comes with ABSOLUTELY NO WARRANTY.  It is free software',
        'and you are welcome to redistribute it.  For details, see the GNU',
        'General Public License, either version 3, or (at your option) any',
        'later version.  <https://www.gnu.org/licenses/gpl.html>',
    ]))

def main():
    try:
        # Make sure Python and C libraries like OpenSSL agree on the locale
        # and therefore system encoding in-use.
        locale.setlocale(locale.LC_ALL, '')

        parser = argparse.ArgumentParser()
        parser.add_argument('-V', '--version',
                            action='store_true',
                            help='show program version and copying '
                                 'information then exit')
        parser.add_argument('--ca-file',
                            metavar='FILE',
                            help='set FILE as the default CA file when '
                                 'verifying certificates')
        parser.add_argument('--ca-path',
                            metavar='PATH',
                            default=DEFAULT_CA_PATH,
                            help='set PATH as the default CA path when '
                                 'verifying certificates')
        parser.add_argument('--no-ca-path',
                            dest='ca_path',
                            action='store_const',
                            const=None,
                            help='refrain from setting a default CA path')
        parser.add_argument('--check-config',
                            action='store_true',
                            help='check configuration and exit')
        parser.add_argument('--config-file',
                            metavar='FILE',
                            default=DEFAULT_CONFIG_FILE,
                            help='read configuration from FILE')
        parser.add_argument('--receive-timeout',
                            metavar='TIMEOUT',
                            type=int,
                            default=10,
                            help='fail if no data is received within '
                                 'TIMEOUT seconds')
        parser.add_argument('--set-effective-user',
                            metavar='USER',
                            default='nobody',
                            help='set effective user to USER when superuser '
                                 'privileges are not required')
        parser.add_argument('--no-set-effective-user',
                            dest='set_effective_user',
                            action='store_const',
                            const=None,
                            help='do not change the effective user')
        global g_args #pylint: disable=global-statement
        g_args = parser.parse_args()

        if g_args.version:
            version()
            return 0

        try:
            with open(g_args.config_file, 'rt', encoding='utf-8') as config_in:
                drop_privileges()
                config = load_configuration(config_in)
        except IOError as e:
            raise BadConfigException('Error opening configuration file "{}":\n{}'
                                     .format(g_args.config_file, str(e))) \
                  from e

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
            if messages:
                print('\n'.join(messages), file=sys.stderr)
            return 0

        config, certificates, key = interact_with_sender(config)

        certificates, key = read_data_to_preserve(config, certificates, key)

        perform_verifications(config, certificates, key)

        reacquire_privileges()

        install_files(config, certificates, key)

        if 'reload_command' in config:
            reload_service(config)

        return 0

    except CertReceivePyException as e:
        print(str(e), file=sys.stderr)
        return e.EXITCODE

if __name__ == '__main__':
    sys.exit(main())
