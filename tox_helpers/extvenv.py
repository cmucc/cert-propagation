"""
Tox plugin that adds an 'external-virtualenv' runner as well as 'external-virtualenv-pep-517' and
'external-virtualenv-cmd-builder' packagers.  These behave simililarly to 'virtualenv' and friends, but utilize an
external command (optionally from within a different tox environment) to create Python environments.
"""

from abc import ABC
import os
from pathlib import Path
import subprocess
import sys
from typing import List

from tox.config.types import Command
from tox.execute.api import StdinSource
from tox.execute.local_sub_process import LocalSubProcessExecutor
from tox.plugin import impl as hook_impl
from tox.tox_env.errors import Fail
from tox.tox_env.python.api import Python, PythonInfo, VersionInfo
from tox.tox_env.python.pip.pip_install import Pip
from tox.tox_env.python.runner import PythonRun
from tox.tox_env.python.virtual_env.package.cmd_builder import VenvCmdBuilder
from tox.tox_env.python.virtual_env.package.pyproject import Pep517VenvPackager
from virtualenv.discovery.py_spec import PythonSpec

_CONFIG = None

class _OverrideConf:
    """
    Context manager that facilitates monkey-patching ConfigSet instances.

    There are a few cases where we need to adjust the defaults or otherwise override configuration keys installed by
    base classes.  Other solutions involved re-implementing signifcant amounts of the base class' logic or overriding
    private base class methods.  The former involved copying an unappetizingly large amount of code, while the latter
    would be tightly coupled to the current 'virtualenv' implementation and prone to breaking with newer versions of
    tox.
    """
    def __init__(self, conf):
        self.conf = conf
        self.kwargs = None
        self.real_add_config = None
        self.override_add_config = None
        self.real_add_constant = None
        self.override_add_constant = None
        self._real_class_getitem = None
        self.real_getitem = None
        self.override_getitem = None

    def __enter__(self):
        self.real_add_config = self.conf.add_config
        self.conf.add_config = self._wrap_add_config
        self.real_add_constant = self.conf.add_constant
        self.conf.add_constant = self._wrap_add_constant
        self._real_class_getitem = type(self.conf).__getitem__
        type(self.conf).__getitem__ = self._make_wrap_getitem()
        self.real_getitem = lambda key: self._real_class_getitem(self.conf, key)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.conf.add_config = self.real_add_config
        self.conf.add_constant = self.real_add_constant
        type(self.conf).__getitem__ = self._real_class_getitem
        return False

    def _wrap_add_config(self, *args, **kwargs):
        if self.override_add_config is None:
            return self.real_add_config(*args, **kwargs)
        args_iter = iter(args)
        self.kwargs = dict(kwargs)
        keys = kwargs.get('keys', None)
        if keys is None:
            try:
                keys = next(args_iter)
                self.kwargs['of_type'] = next(args_iter)
                self.kwargs['default'] = next(args_iter)
                self.kwargs['desc'] = next(args_iter)
                self.kwargs['post_process'] = next(args_iter)
                self.kwargs['factory'] = next(args_iter)
            except StopIteration:
                pass
        if keys is None:
            raise TypeError('missing keys argument')
        if isinstance(keys, str):
            keys = [keys]
        self.kwargs['keys'] = keys
        return self.override_add_config()

    def _wrap_add_constant(self, *args, **kwargs):
        if self.override_add_constant is None:
            return self.real_add_constant(*args, **kwargs)
        args_iter = iter(args)
        self.kwargs = dict(kwargs)
        try:
            self.kwargs['keys'] = next(args_iter)
            self.kwargs['desc'] = next(args_iter)
            self.kwargs['value'] = next(args_iter)
        except StopIteration:
            pass
        return self.override_add_constant()

    def _make_wrap_getitem(self):
        def wrap_getitem(conf, key):
            if conf is not self.conf or self.override_getitem is None:
                return self._real_class_getitem(conf, key)
            self.kwargs = {}
            return self.override_getitem(key)
        return wrap_getitem

class ExternalVenv(Python, ABC):
    """
    An analogue of VirtualEnv that uses an external command (optionally from within a different tox environment) to
    create the Python virtual environment, rather than the virtualenv distribution package collocated in the same Python
    environment tox is running from.

    This has the benefit that it decouples the virtualenv creator's requirement's from tox's requirements.  For example,
    this allows use of virtualenv<20.22.0 to create virtual environments for Python 2.7, Python 3.5, Python 3.6, and
    Python 3.7 with the latest tox.  On the other hand, if you add a requirement for virtualenv<20.22.0 to the core
    requires list as suggested in the tox FAQ, tox<4.5.2 gets provisioned because newer versions of tox have a
    conflicting platformdirs requirement.  This is surprising and disappointing if you want to use features that were
    added to tox more recently, like TOML configuration.
    """
    def __init__(self, create_args):
        self._executor = None
        self._installer = None
        self._creating = False
        self._ev_base_python = None
        super().__init__(create_args)

    # we use ev_ prefixes for the next two methods to avoid inadvertently overriding what would be obvious names for
    # future non-private methods dealing with the relevant configuration keys in the base classes

    def ev_default_pass_env(self, conf, env_name, base_default):
        if callable(base_default):
            value = base_default(conf, env_name)
        else:
            value = base_default.copy()
        value.append('PIP_*')
        value.append('VIRTUALENV_*')
        return value

    def ev_default_set_env(self, conf, env_name, base_default):
        if callable(base_default):
            value = base_default(conf, env_name)
        else:
            value = base_default.copy()
        value.append('PIP_DISABLE_PIP_VERSION_CHECK=1')
        return value

    # it also seems advisable to add an ev_ prefix to creator, since it is also a virtualenv class/concept

    @property
    def ev_creator_bin_dir(self):
        creator_env = self.conf['create_with_ext_env']
        if not creator_env:
            return None
        if creator_env not in _CONFIG:
            raise Fail(f'could not find configuration for the specified create_with_ext_env: {creator_env}')
        subdir = 'Scripts' if sys.platform == 'win32' else 'bin'
        return _CONFIG.get_env(creator_env)['env_dir'] / subdir

    def default_ext_commands(self, *unused_args, **unused_kwargs):
        conf = self.conf
        values = [
            Command([conf['ext_python']] + conf['ext_python_isolate'] + ['-m', 'virtualenv', conf['env_dir']]),
        ]
        return values

    EV_PRINT_SPEC_CODE = """
import platform
import struct
print(
  '{}{}-{}'.format(
    platform.python_implementation(),
    platform.python_version(),
    struct.calcsize('P')*8,
  ),
  end='',
)
"""

    # Implementations/extensions of ToxEnv API
    ####################################################################################################################

    @property
    def executor(self):
        if self._executor is None:
            self._executor = LocalSubProcessExecutor(self.options.is_colored)
        return self._executor

    @property
    def installer(self):
        if self._installer is None:
            self._installer = Pip(self)
        return self._installer

    def register_config(self):
        with _OverrideConf(self.conf) as helper:
            def override_add_config():
                base_default = helper.kwargs['default']
                if 'pass_env' in helper.kwargs['keys']:
                    helper.kwargs['default'] = lambda conf, env_name: \
                        self.ev_default_pass_env(conf, env_name, base_default)
                if 'set_env' in helper.kwargs['keys']:
                    helper.kwargs['default'] = lambda conf, env_name: \
                        self.ev_default_set_env(conf, env_name, base_default)
                return helper.real_add_config(**helper.kwargs)
            helper.override_add_config = override_add_config
            super().register_config()

        self.conf.add_config(
            keys=['create_with_ext_commands'],
            of_type=List[Command],
            default=self.default_ext_commands,
            desc='external commands to invoke when creating this environment',
        )
        self.conf.add_config(
            keys=['create_with_ext_env'],
            of_type=str,
            default='',
            desc='run external commands from the indicated environment when creating this environment',
        )
        self.conf.add_config(
            keys=['ext_python_isolate'],
            of_type=List[str],
            default=['-I'],
            desc="flag(s) to pass to the external python to isolate it from the users's environment",
        )

        self.conf.add_constant(
            keys=['ext_python'],
            desc='default external python to use for environment creation',
            value='python' if self.conf['create_with_ext_env'] else sys.executable,
        )
        try:
            self.conf.add_constant(
                keys=['ext_python_from_base_python'],
                desc="external python used as this environment's base python; only set when the base python is an "
                     'absolute path',
                value=str(self.base_python.extra['executable']),
            )
        except KeyError:
            pass
        if self.conf['create_with_ext_env']:
            self.conf.add_constant(
                keys=['ext_python_from_env'],
                desc='external python from the create_with_ext_env environment; only set when create_with_ext_env '
                     'is set and non-empty',
                value='python',
            )
        self.conf.add_constant(
            keys=['ext_python_from_tox'],
            desc='external python that is running tox',
            value=sys.executable,
        )

    @property
    def environment_variables(self):
        env = super().environment_variables
        env['VIRTUAL_ENV'] = self.env_dir
        if self._creating:
            env = env.copy()
            env.setdefault('VIRTUALENV_NO_PERIODIC_UPDATE', 'True')
            env['VIRTUALENV_CLEAR'] = 'False'
            env.setdefault('VIRTUALENV_SYSTEM_SITE_PACKAGES', 'False')
            for var in ('VIRTUALENV_COPIES', 'VIRTUALENV_ALWAYS_COPY', 'VIRTUALENV_SYMLINK'):
                if var in env:
                    break
            else:
                env.setdefault('VIRTUALENV_COPIES', 'False')
            env.setdefault('VIRTUALENV_DOWNLOAD', 'False')
            env['VIRTUALENV_PYTHON'] = '\n'.join(self.conf['base_python'])
            creator_bin_dir = self.ev_creator_bin_dir
            if creator_bin_dir is not None:
                env['PATH'] = f'{creator_bin_dir}{os.pathsep}{env["PATH"]}'
        return env

    @property
    def runs_on_platform(self):
        return sys.platform

    # Implementations/extensions of Python API
    ####################################################################################################################

    @classmethod
    def python_spec_for_path(cls, path):
        try_isolate = [['-I'], ['-E', '-s'], ['-E'], []]
        for isolate in try_isolate:
            # TODO: can/should a tox executor be used instead? it isn't as simple as using ToxEnv.execute because this
            # is a classmethod
            result = subprocess.run([path] + isolate + ['-c', cls.EV_PRINT_SPEC_CODE],
                                    stdout=subprocess.PIPE,
                                    check=False)
            if result.returncode == 0:
                return PythonSpec.from_string_spec(result.stdout.decode())
        return None

    # I based the handling for win32 and pypy off of the tox-uv plugin; I haven't actually tested with win32 or pypy
    # though

    def env_site_package_dir(self):
        if sys.platform == 'win32':
            return self.env_dir / 'Lib'
        py_info = self.base_python
        impl = 'pypy' if py_info.implementation == 'pypy' else 'python'
        return self.env_dir / 'lib' / (impl + py_info.version_dot)

    def env_python(self):
        suffix = '.exe' if sys.platform == 'win32' else ''
        return self.env_bin_dir() / ('python' + suffix)

    def env_bin_dir(self):
        subdir = 'Scripts' if sys.platform == 'win32' else 'bin'
        return self.env_dir / subdir

    def prepend_env_var_path(self):
        return [self.env_bin_dir()]

    # despite the leading underbar indicating it's not a public API, _get_python is marked as an abstract method in the
    # Python base class, forcing us to implement the method
    def _get_python(self, base_python):
        for base in base_python:
            extra = {}
            base_path = Path(base)
            if base_path.is_absolute():
                spec = self.python_spec_for_path(base_path)
                if spec is None:
                    continue
                extra['executable'] = base_path
            else:
                spec = PythonSpec.from_string_spec(base)
            extra['architecture'] = spec.architecture
            return PythonInfo(
                implementation=spec.implementation or 'CPython',
                version_info=VersionInfo(
                    major=spec.major,
                    minor=spec.minor,
                    micro=spec.micro,
                    releaselevel='',
                    serial=0,
                ),
                version=str(spec),
                is_64=spec.architecture == 64,
                platform=sys.platform,
                extra=extra,
            )
        return None

    def create_python_env(self):
        self._creating = True
        try:
            args = None
            helper = None
            ii = 0
            for cmd in self.conf['create_with_ext_commands']:
                try:
                    dir_at = cmd.args.index("{env_dir}")
                    args = cmd.args.copy()
                    args[dir_at] = self.env_dir
                except ValueError:
                    args = cmd.args
                with _OverrideConf(self.conf) as helper:
                    def override_getitem(key):
                        value = helper.real_getitem(key)
                        if key == 'allowlist_externals':
                            creator_bin_dir = self.ev_creator_bin_dir
                            if creator_bin_dir is not None:
                                # for create_with_ext_venv, we'll override allowlist_externals so execute will only
                                # allow commands from within that environment
                                value = [f"{creator_bin_dir}{os.sep}*"]
                            else:
                                # otherwise, we'll allow the specific command from create_with_ext_commands
                                value = [args[0]]
                        return value
                    helper.override_getitem = override_getitem
                    result = self.execute(args,
                                          StdinSource.OFF,
                                          run_id=f'extvenv_create[{ii}]')
                if cmd.invert_exit_code:
                    result.assert_failure()
                elif not cmd.ignore_exit_code:
                    result.assert_success()
        finally:
            self._creating = False

class ExternalVenvRunner(ExternalVenv, PythonRun):
    """
    An analogue of VirtualEnvRunner that uses an external command (optionally from within a different tox environment)
    to create the Python virtual environment, rather than the virtualenv distribution package collocated in the same
    Python environment tox is running from.
    """

    # we use evr_ prefixes for the next three methods to avoid inadvertently overriding what would be obvious names for
    # future non-private methods dealing with the relevant configuration keys in the base classes

    def evr_post_process_depends(self, values, base_post_process):
        if base_post_process is not None:
            values = base_post_process(values)
        creator_env = self.conf['create_with_ext_env']
        if creator_env and creator_env not in values:
            values.envs.append(creator_env)
        return values

    def evr_default_package_env(self, conf, env_name, base_default):
        if callable(base_default):
            value = base_default(conf, env_name)
        else:
            value = base_default
        if self.conf['package_tox_env_type'] in ('external-virtualenv-pep-517', 'external-virtualenv-cmd-builder'):
            return value + '-extvenv'
        return value

    def evr_post_process_package_env_type(self, value):
        if value.endswith('-pep-517') or value.endswith('-cmd-builder'):
            return value
        suffix = '-pep-517' if self.conf['package'] != 'external' else '-cmd-builder'
        return value + suffix

    def register_config(self):
        with _OverrideConf(self.conf) as helper:
            def override_add_config():
                if 'depends' in helper.kwargs['keys']:
                    base_post_process = helper.kwargs.get('post_process', None)
                    helper.kwargs['post_process'] = lambda values: \
                        self.evr_post_process_depends(values, base_post_process)
                return helper.real_add_config(**helper.kwargs)
            helper.override_add_config = override_add_config
            super().register_config()

    def get_package_env_types(self):
        with _OverrideConf(self.conf) as helper:
            def override_add_config():
                if 'package_env' in helper.kwargs['keys']:
                    base_default = helper.kwargs['default']
                    helper.kwargs['default'] = lambda conf, env_name: \
                        self.evr_default_package_env(conf, env_name, base_default)
                return helper.real_add_config(**helper.kwargs)
            helper.override_add_config = override_add_config
            def override_add_constant():
                if 'package_tox_env_type' in helper.kwargs['keys']:
                    # we'll potentially define package_tox_env_type as a configurable rather than a constant below
                    return None
                return helper.real_add_constant(**helper.kwargs)
            helper.override_add_constant = override_add_constant
            def override_getitem(key):
                if key in ('package_env', 'package_tox_env_type'):
                    # the package_env value is dummied up to avoid evaluating its default method until after we set up
                    # package_tox_env_type below; package_tox_env_type is dummied up so the super class method can
                    # succesfully access a value for it despite the fact we haven't added it to the configuration yet
                    return 'dummy'
                return helper.real_getitem(key)
            helper.override_getitem = override_getitem
            super_result = super().get_package_env_types()
        if super_result is None:
            # nothing to build and package, so we will not add package_tox_env_type
            return None
        self.conf.add_config(
            keys=['package_tox_env_type'],
            of_type=str,
            default='virtualenv',
            desc='tox package environment type used to generate the package',
            post_process=self.evr_post_process_package_env_type,
        )
        return self.conf['package_env'], self.conf['package_tox_env_type']

    @staticmethod
    def id():
        return 'external-virtualenv'

    # the following need to be defined so we can successfully call super().get_package_env_types() above

    @property
    def _package_tox_env_type(self):
        return 'dummy'

    @property
    def _external_pkg_tox_env_type(self):
        return 'dummy'

class Pep517ExternalVenvPackager(Pep517VenvPackager, ExternalVenv):
    """
    An analogue of Pep517VirtualEnvPackager that uses an external command (optionally from within a different tox
    environment) to create the Python virtual environment, rather than the virtualenv distribution package collocated in
    the same Python environment tox is running from.
    """
    @staticmethod
    def id():
        return 'external-virtualenv-pep-517'

class ExternalVenvCmdBuilder(VenvCmdBuilder, ExternalVenv):
    """
    An analogue of VirtualEnvCommandBuilder that uses an external command (optionally from within a different tox
    environment) to create the Python virtual environment, rather than the virtualenv distribution package collocated in
    the same Python environment tox is running from.
    """
    @staticmethod
    def id():
        return 'external-virtualenv-cmd-builder'

@hook_impl
def tox_add_core_config(core_conf, state):
    global _CONFIG
    _ = core_conf
    _CONFIG = state.conf

@hook_impl
def tox_register_tox_env(register):
    register.add_run_env(ExternalVenvRunner)
    register.add_package_env(Pep517ExternalVenvPackager)
    register.add_package_env(ExternalVenvCmdBuilder)
