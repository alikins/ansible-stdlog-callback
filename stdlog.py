# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

# TODO: it would be useful to support logging.dictConfig as well, but
# config doesn't have a dict type. We could add a 'dict_config_yaml_string'
# that would be a string of yaml/json we would deserialize and send to logging.dictConfig
# but yaml inside yaml is kind of weird
DOCUMENTATION = '''
    callback: stdlog
    type: notification
    short_description: Sends events to python stdlib logging
    description:
      - This callback plugin will use python stdlib logging, create a logger and handlers, and send detailed events to the logger
      - In 2.4 and above you can just put it in the main Ansible configuration file.
    version_added: "2.5"
    requirements:
      - whitelisting in configuration
      - jsonlogging (python library), if you want to use json logging
      - color_debug (python library), if you want colorful stdout logging
    options:
      foo:
        description: which foo
        env:
          - name: STDLOG_FOO
        default: foo_default
        ini:
          - section: callback_stdlog
            key: foo
      blip:
        description: a collective of blip
        env:
            - name: STDLOG_BLIP
        default: platypus
        ini:
          - section: callback_stdlog
            key: blip
      logger_name:
        description: The name of the base logger to use
        env:
            - name: STDLOG_LOGGER_NAME
        default: ansible_stdlog
        ini:
          - section: callback_stdlog
            key: logger_name
      logger_level:
        description: The log level of the base logger
        env:
          - name: STDLOG_LOGGER_LEVEL
        ini:
          - section: callback_stdlog
            key: logger_level
        default: DEBUG
      stdout_formatter:
        description:
          - which formatter to use for stdout
        env:
          - name: STDLOG_STDOUT_FORMATTER
        default: SortedJSONFormatter
        ini:
          - section: callback_stdlog
            key: stdout_formatter
      file_formatter:
        description: formatter to use for log file
        default: SortedJSONFormatter
        env:
          - name: STDLOG_FILE_FORMATTER
        ini:
          - section: callback_stdlog
            key: file_formatter
      file_formatter_format:
        description: format string to pass to file_formatter
        env:
          - name: STDLOG_FILE_FORMATTER
        ini:
          - section: callback_stdlog
            key: file_formatter_format
        default: "%(asctime)s [%(levelname)s] %(process)d @%(filename)s:%(lineno)d - %(message)s"
      file_formatter_file:
        description: the file name the file_formatter should log to
        env:
          - name: STDLOG_FILE_FORMATTER_FILE
        ini:
          - section: callback_stdlog
            key: file_formatter_file
        type: path
        default: ~/.ansible_stdlog.log
      stdout_formatter_format:
        description: format string to pass to stdout_formatter
        env:
          - name: STDLOG_STDOUT_FORMATTER
        ini:
          - section: callback_stdlog
            key: stdout_formatter_format
'''
#        default: "%(asctime)s [%(levelname)s] %(process)d @%(filename)s:%(lineno)d - %(message)s"

import getpass
import json
import logging
import logging.handlers
import os
import pprint
import pwd
import re
import sys

# import color_debug

# from ansible.utils.unicode import to_bytes
from ansible.plugins.callback import CallbackBase
from ansible.release import __version__ as ansible_version

# import logging_tree
import jsonlogging
import color_debug

# NOTE: in Ansible 1.2 or later general logging is available without
# this plugin, just set ANSIBLE_LOG_PATH as an environment variable
# or log_path in the DEFAULTS section of your ansible configuration
# file.  This callback is an example of per hosts logging for those
# that want it.
BASE_LOGGER_NAME = 'ansible_stdlog'
log = logging.getLogger(BASE_LOGGER_NAME)

PLAY = ' [playbook=%(playbook)s play=%(play)s task=%(task)s] (%(process)d):%(funcName)s:%(lineno)d - %(message)s'
PLAY_DETAILS = ' play_uuid=%(play_uuid)s play_hosts=%(play_hosts)s'
TASK_DETAILS = ' task_uuid=%(task_uuid)s task_role=%(task_role)s'
ROLES = ' play_roles=%(play_roles)s'
PLAY_TAGS = ' play_tags=%(play_tags)s task_tags=%(task_tags)s'
ANSIBLE_VERSION = ' ansible_version="%(ansible_version)s"'
PYTHON_VERSION = ' python_version="%(python_version)s" python_compiler="%(python_compiler)s"'
CLI = ' cli_cmd_name=%(cli_cmd_name)s cli_cmd_line="%(cli_cmd_line)s"' + \
    ' cli_cli_name_full_path=%(cli_name_full_path)s'
USER = ' user=%(user)s uid=%(uid)d gid=%(gid)d'

BECOME = ' play_become=%(play_become)s play_become_user=%(play_become_user)s' + \
    ' play_become_method=%(play_become_method)s'

CONTEXT_DEBUG_LOG_FORMAT = "%(asctime)s [%(name)s %(levelname)s %(hostname)s]" + PLAY
EVERYTHING = CONTEXT_DEBUG_LOG_FORMAT + PLAY_DETAILS + PLAY_TAGS + ROLES + TASK_DETAILS + BECOME + ANSIBLE_VERSION + PYTHON_VERSION + CLI + USER
DEBUG_LOG_FORMAT = "%(asctime)s [%(name)s %(levelname)s %(hostname)s %(playbook)s] pid=%(process)d %(funcName)s:%(lineno)d - %(message)s"
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(process)d @%(filename)s:%(lineno)d - %(message)s"
MIN_LOG_FORMAT = "%(asctime)s %(funcName)s:%(lineno)d - %(message)s"


def sluggify(value):
    return '%s' % (re.sub(r'[^\w-]', '_', value).lower().lstrip('_'))


# Don't need this for syslog
class CliContextLoggingFilter(object):
    """Find the name of the process as 'cmd_name'"""
    cli_cmd_name = os.path.basename(sys.argv[0])
    cli_cmd_name_full_path = sys.argv[0]
    cli_cmd_line = ' '.join(sys.argv)

    def __init__(self, name):
        self.name = name

    def filter(self, record):
        record.cli_cmd_name = self.cli_cmd_name
        record.cli_cmd_line = self.cli_cmd_line
        record.cli_name_full_path = self.cli_cmd_name_full_path

        return True


class VersionContextLoggingFilter(object):
    ansible_version = ansible_version

    def __init__(self, name):
        self.name = name

    def filter(self, record):
        record.ansible_version = self.ansible_version

        return True


class PythonVersionContextLoggingFilter(object):
    python_version = sys.version.splitlines()[0]
    python_compiler = sys.version.splitlines()[1]

    def __init__(self, name):
        self.name = name

    def filter(self, record):
        record.python_version = self.python_version
        record.python_compiler = self.python_compiler

        return True


class UserContextLoggingFilter(object):
    user = getpass.getuser()
    pwent = pwd.getpwnam(user)
    uid = pwent.pw_uid
    gid = pwent.pw_gid

    def __init__(self, name):
        self.name = name

    def filter(self, record):
        record.user = self.user
        record.uid = self.uid
        record.gid = self.gid

        return True


class PlaybookContextLoggingFilter(object):
    def __init__(self, name, playbook_context=None):
        self.name = name
        self.playbook_context = playbook_context

    def filter(self, record):
        if not self.playbook_context:
            return True

        # TODO: squash this with properties

        record.playbook = None
        record.playbook_uuid = None
        record.play = None
        record.play_uuid = None
        record.play_tags = []
        record.play_become = None
        record.play_become_method = None
        record.play_become_user = None
        record.play_hosts = []
        record.play_roles = []
        record.task = None
        record.task_uuid = None
        record.task_tags = []
        record.hostname = getattr(record, 'hostname', '')
        record.task_log = getattr(record, 'task_log', '')
        record.task_role = {}
        record.cb = getattr(record, 'cb', '')

        if self.playbook_context.playbook:
            record.playbook = os.path.basename(self.playbook_context.playbook._file_name)

        if self.playbook_context.playbook_uuid:
            record.playbook_uuid = self.playbook_context.playbook_uuid

        if self.playbook_context.play:
            record.play = sluggify(self.playbook_context.play.get_name())
            record.play_tags = self.playbook_context.play.tags
            record.play_become = self.playbook_context.play.become
            record.play_become_method = self.playbook_context.play.become_method
            record.play_become_user = self.playbook_context.play.become_user
            record.play_hosts = self.playbook_context.play.hosts

            # workaround for Roles not being json serializable
            record.play_roles = [{'name': x._role_name, 'path': x._role_path} for x in self.playbook_context.play.roles]

        if self.playbook_context.play_uuid:
            record.play_uuid = self.playbook_context.play_uuid

        if self.playbook_context.task:
            record.task = sluggify(self.playbook_context.task.get_name())
            record.task_tags = self.playbook_context.task.tags

            if self.playbook_context.task._role:
                record.task_role = {'name': self.playbook_context.task._role._role_name,
                                    'path': self.playbook_context.task._role._role_path}

        if self.playbook_context.task_uuid:
            record.task_uuid = self.playbook_context.task_uuid

        if self.playbook_context.hostname:
            record.hostname = self.playbook_context.hostname

        return True


class StdlogFileHandler(logging.handlers.WatchedFileHandler, object):
    def __init__(self, *args, **kwargs):
        playbook_context = kwargs.pop('playbook_context', None)
        super(StdlogFileHandler, self).__init__(*args, **kwargs)

        self.addFilter(PlaybookContextLoggingFilter(name="",
                                                    playbook_context=playbook_context))

        self.addFilter(CliContextLoggingFilter(name=""))
        self.addFilter(VersionContextLoggingFilter(name=""))
        self.addFilter(UserContextLoggingFilter(name=""))
        self.addFilter(PythonVersionContextLoggingFilter(name=""))


class StdlogStreamHandler(logging.StreamHandler, object):
    def __init__(self, *args, **kwargs):
        playbook_context = kwargs.pop('playbook_context', None)
        super(StdlogStreamHandler, self).__init__(*args, **kwargs)

        self.addFilter(PlaybookContextLoggingFilter(name="",
                                                    playbook_context=playbook_context))

        self.addFilter(CliContextLoggingFilter(name=""))
        self.addFilter(VersionContextLoggingFilter(name=""))
        self.addFilter(UserContextLoggingFilter(name=""))
        self.addFilter(PythonVersionContextLoggingFilter(name=""))


class TaskResultRepr(object):
    def __init__(self, result):
        self.result = result
        self.host = self.result._host
        self.task = self.result._task
        self.verbose = True
        self.task_fields = self.result._task_fields

    def __repr__(self):
        # return "TaskResult(host=%s, task=%s, return_data=%s)" % (self._host, self._task, self._result)
        return "TaskResult(host=%s, uuid=%s, tags=%s)" % (self.host, self.task._uuid, self.task_fields['tags'])

    def str_impl(self):
        parts = []
        parts.append("TaskResult:")
        parts.append("    host: %s" % self.host)
        parts.append("    task: %s" % self.task)
        parts.append("    task._uuid: %s" % self.task._uuid)
        parts.append("    return_data: %s" % pprint.pformat(self.result))
        for key, value in self.result._result.items():
            parts.append(' key: %s=%s' % (key, value))
        return '\n'.join(parts)

    # enable for way more verbose logs
    # __str__ = str_impl


class PlaybookContext(object):
    def __init__(self, playbook=None, play=None, task=None):
        # TODO: use something like chainmap for nested context?
        self.playbook = playbook
        self.playbook_uuid = None

        self.play = play
        self.play_uuid = None

        self.task = task
        self.task_uuid = None

        self.hostname = None

    def update(self, result=None):
        """On a task result, if for the current task, that task is done."""
        if not result:
            return

        if self.task_uuid == result._task._uuid:
            self.task = None
            self.task_uuid = None

        self.hostname = result._host.get_name()

    # NOTE: not used currently
    def logger_name(self, base_logger_name=None):
        logger_name = base_logger_name or ""
        if self.playbook:
            logger_name += '.%s' % self.playbook._name
        if self.play:
            play_name = sluggify(self.play.get_name())
            logger_name += '.%s' % play_name
        if self.task:
            if self.task.name:
                task_name = sluggify(self.task.name)
                logger_name += '.%s' % task_name
        return logger_name


class SortedJSONFormatter(jsonlogging.JSONFormatter):
    @classmethod
    def serialize(cls, message, indent=None):
        return json.dumps(message, indent=indent, sort_keys=True)


class CallbackModule(CallbackBase):
    """
    Logging callbacks using python stdlin logging
    """
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'notification'
    # CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = 'stdlog'
    # CALLBACK_NEEDS_WHITELIST = True
    CALLBACK_NEEDS_WHITELIST = False

    default_logger_level = logging.DEBUG
    default_logger_name = 'ansible_stdlog'
    default_stdout_formatter = "ColorFormatter"
    default_stdout_formatter_format = EVERYTHING
    default_file_formatter = "SortedJSONFormatter"
    default_file_formatter_format = EVERYTHING
    default_file_formatter_file = "~/.ansible_stdlog.log"

    # log_format = CONTEXT_DEBUG_LOG_FORMAT
    # log_format = LOG_FORMAT
    # log_format = MIN_LOG_FORMAT
    # log_format = DEBUG_LOG_FORMAT

    def __init__(self, options=None):
        super(CallbackModule, self).__init__(options=options)

        # TODO: replace with a stack
        self.host = None
        self.context = PlaybookContext()

        # Note.. reference to the class to be used as a callable not an instance
        self.rr = TaskResultRepr

        # FIXME: change task_queue_manager to build options first and pass to init
        # FIXME: if we are

    def _choose_stdout_formatter(self, formatter_name):
        # FIXME: how much of logging.dictConfig is approriate to re-invent?
        if formatter_name == 'ColorFormatter':
            # use the calculated color of log_record_attr as the color for record_attr1 and record_attr2 as well.
            # The inner list is more or less a group of record attrs that should have the same color, and the
            # tuple[0] item is where they get the color from.
            # [(log_record_attr, [record_attr1, record_attr2])]
            color_groups = [('funcName', ['funcName', 'lineno']),
                            ('thread', ['thread', 'threadName']),
                            ('process', ['processName'])]
            color_formatter = color_debug.ColorFormatter(fmt=self.stdout_formatter_format,
                                                         default_color_by_attr='name',
                                                         color_groups=color_groups)
            return color_formatter

        # default
        return SortedJSONFormatter(indent=4)

    def _choose_file_formatter(self, formatter_name):
        return SortedJSONFormatter(indent=4)

    # This is second half of init, to be called after setup_options(). We don't know
    # the config option values until after init, so we have to init, the on/after set_options
    # we get config options and apply them.
    def initialize(self):

        self.stream_handler = StdlogStreamHandler(playbook_context=self.context)
        stream_formatter = self._choose_stdout_formatter(self.stdout_formatter)
        self.stream_handler.setFormatter(stream_formatter)

        self.file_handler = StdlogFileHandler(self.file_formatter_file,
                                              playbook_context=self.context)
        file_formatter = self._choose_file_formatter(self.file_formatter)
        self.file_handler.setFormatter(file_formatter)

        self.logger = logging.getLogger(self.logger_name)
        if not any([isinstance(handler, (StdlogFileHandler, StdlogStreamHandler)) for handler in self.logger.handlers]):
            self.logger.addHandler(self.stream_handler)
            self.logger.addHandler(self.file_handler)

        self.logger.setLevel(self.logger_level)

        import logging_tree
        logging_tree.printout()

    def apply_config(self):
        # log_level
        # log_format
        # base logger_name
        # base logger level
        # handlers
        #   FileHandlers
        #       filename
        #       which formatter
        #       level
        #   StreamHandlers
        #      stdout/stdout
        #      which formatter
        #      level
        #   formatters
        #     formatter options
        #     ColorFormatter (color_groups, default_attr)
        #     JSONFormatter (sorted, indent, encoder)
        pass

    def set_options(self, task_keys=None, var_options=None, direct=None):
        super(CallbackModule, self).set_options(task_keys, var_options, direct)

        self.stdout_formatter = self._plugin_options['stdout_formatter'] or self.default_stdout_formatter
        self.stdout_formatter_format = self._plugin_options['stdout_formatter_format'] or self.default_stdout_formatter_format

        self.file_formatter = self._plugin_options['file_formatter'] or self.default_file_formatter
        self.file_formatter_format = self._plugin_options['file_formatter_format'] or self.default_file_formatter_format
        self.file_formatter_file = self._plugin_options['file_formatter_file'] or self.default_file_formatter_file

        self.logger_level = self._plugin_options['logger_level'] or self.default_logger_level

        self.logger_name = self._plugin_options['logger_name'] or self.default_logger_name

        # FIXME: would be nice to do this in init
        self.initialize()

    # Note: it would be useful to have a 'always called'
    # callback, and a 'only called if not handled' callback
    def _handle_v2_on_any(self, *args, **kwargs):
        extra = {'cb': 'v2_on_any',
                 'v2_on_any_args': args,
                 'v2_on_any_kwargs': kwargs}
        self.logger.debug('args=%s kwargs=%s', args, repr(kwargs), extra=extra)
        # for arg in args:
        #    self.logger.debug(arg, extra=extra)

        # for k, v in kwargs.items():
        #    self.logger.debug('kw_k=%s', k, extra=extra)
        #    self.logger.debug('kw_v=%s', v, extra=extra)

    # To enable logging any hits to 'on_any' callbacks, uncomment here.
    # WARNING: we don't know the name the callback method was actually called as and
    # the args/kwargs could be anything
    v2_on_any = _handle_v2_on_any

    # TODO: remove, not used at,
    def context_logger(self, host=None):
        # 'ansible_stdlog.host.playbook.play.task'
        # 'ansible_stdlog.host.playbook.'
        # ansible_stdlog.play.task? ansible_stdlog.play.task.host?
        # playbook.play.task.
        # playbook filename sans ext?
        # TODO: figure out a reasonable label style name for a playbook

        logger = logging.getLogger(self.context.logger_name(self.log_name))
        logger.setLevel(self.log_level)
        return logger

    def result_update(self, result, extra=None):
        extra = extra or {}

        for log_record_dict in result._result.get('log_records', []):
            log_record_dict['hostname'] = result._host
            log_record_dict['task_log'] = 'task_log'
            # log_record_dict['args'] = tuple(log_record_dict['arg_reprs']) or None

            log_record = logging.makeLogRecord(log_record_dict)
            self.logger.handle(log_record)
        self.context.update(result)
        self.logger.debug('result=%s', self.rr(result), extra=extra)

    # Add host info to context and remove this method
    def not_result_logger(self, result):
        """Grab a logging.Logger with the host and category in the logger name.

        Why not log the result here? Because we get the
        calling method name logged for free if we do it in
        the entry point, where we'd get 'result_update' here."""

        return self.context_logger(host=result.host.get_name())

    def v2_runner_on_failed(self, result, ignore_errors=None):
        extra = {'cb': 'v2_runner_on_failed'}
        self.result_update(result, extra=extra)
        self.logger.debug('result=%s', self.rr(result), extra=extra)
        self.logger.debug('ignore_errors=%s', ignore_errors or False, extra=extra)

    def v2_runner_on_ok(self, result):
        extra = {'cb': 'v2_runner_on_ok'}
        self.result_update(result, extra=extra)
        self.logger.debug('result=%s', self.rr(result), extra=extra)

    def v2_runner_on_skipped(self, result):
        extra = {'cb': 'v2_runner_on_skipped'}
        self.result_update(result, extra=extra)
        self.logger.debug('result=%s', self.rr(result), extra=extra)

    def v2_runner_on_unreachable(self, result):
        self.result_update(result)
        self.logger.debug('result=%s', self.rr(result))

    def v2_runner_on_no_hosts(self, task):
        self.logger.debug('no hosts on task=%s', task)

    def v2_runner_on_async_pool(self, result):
        # need a async_result_logger?
        self.result_update(result)
        self.logger.debug('result=%s', result)

    def v2_runner_on_async_ok(self, result):
        self.result_update(result)
        self.logger.debug('result=%s', result)

    def v2_runner_on_async_failed(self, result):
        self.result_update(result)
        self.logger.debug('result=%s', result)

    def v2_runner_on_file_diff(self, result, diff):
        self.result_update(result)
        self.logger.debug('diff=%s', diff)

    def v2_playbook_on_start(self, playbook):
        extra = {'cb': 'v2_playbook_on_start'}
        # self.playbook = playbook
        self.context.playbook = playbook
        self.logger.debug('playbook=%s', playbook, extra=extra)

    def v2_playbook_on_notify(self, result, handler):
        extra = {'cb': 'v2_playbook_on_notify'}
        self.result_update(result, extra=extra)
        self.logger.debug('result=%s', result, extra=extra)
        self.logger.debug('handler=%s', handler, extra=extra)

    def v2_playbook_on_play_start(self, play):
        extra = {'cb': 'v2_playbook_on_play_start'}
        # self.play = play
        self.context.play = play
        self.context.play_uuid = play._uuid

        self.logger.debug('play=%s',
                          extra=extra)

    def v2_playbook_on_no_hosts_matched(self):
        self.logger.debug('playbook=%s, no hosts matches' % self.context.playbook)

    def v2_playbook_on_hosts_remaining(self):
        self.logger.debug('playbook=%s, no hosts remaining' % self.context.playbook)

    def v2_playbook_on_task_start(self, task, is_conditional):
        extra = {'cb': 'v2_playbook_on_task_start'}
        # TODO self.context.update(task=, task_uuid=) ?
        self.context.task = task
        self.context.task_uuid = task._uuid

        self.logger.debug('playbook=%s', self.context.playbook,
                          extra=extra)
        self.logger.debug('task=%s', task, extra=extra)
        self.logger.debug('is_conditional=%s', is_conditional, extra=extra)

    def v2_playbook_on_cleanup_task_start(self, task):
        self.logger.debug('playbook=%s, cleanup on task=%s', self.context.playbook, task)

        # NOTE: needed?
        # self.context.playbook = None

    def v2_playbook_on_handler_task_start(self, task):
        self.logger.debug('playbook=%s, handler start for task=%s',
                          self.context.playbook, task)

    def v2_playbook_on_vars_prompt(self, varname, private=None,
                                   prompt=None, encrypt=None, confirm=None,
                                   salt_size=None, salt=None, default=None):
        self.logger.debug('playbook=%s vars_prompt=%s',
                          self.context.playbook, locals())

    def v2_playbook_on_setup(self):
        self.logger.debug('playbook=%s, setup', self.context.playbook)

    def v2_playbook_on_import_for_host(self, result, imported_file):
        self.result_update(result)
        self.logger.debug('playbook=%s', self.context.playbook)
        self.logger.debug('imported_file=%s', imported_file)
        self.logger.debug('result=%s', result)

    def v2_playbook_on_not_import_for_host(self, result, imported_file):
        self.result_update(result)
        self.logger.debug('playbook=%s', self.context.playbook)
        self.logger.debug('(not) imported_file=%s', imported_file)
        self.logger.debug('result=%s', result)

    def v2_playbook_on_stats(self, stats):
        extra = {'cb': 'v2_playbook_on_task_start'}
        # self.stats_update ?
        self.logger.debug('playbook=%s', self.context.playbook, extra=extra)
        self.logger.debug('stats=%s', stats, extra=extra)
        self.context.playbook = None

    def v2_on_file_diff(self, result):
        self.result_update(result)
        self.logger.debug('result=%s', result)

    def v2_runner_item_on_ok(self, result):
        extra = {'cb': 'v2_runner_item_on_ok'}
        self.result_update(result, extra=extra)
        self.logger.debug('result=%s', result, extra=extra)

    def v2_playbook_on_include(self, included_file):
        self.logger.debug('playbook=%s', self.context.playbook)
        self.logger.debug('included_file=%s', included_file)

    def v2_runner_item_on_failed(self, result):
        extra = {'cb': 'v2_runner_item_on_failed'}
        self.result_update(result, extra=extra)
        self.logger.debug('result=%s', result, extra=extra)

    def v2_runner_item_on_skipped(self, result):
        self.result_update(result)
        self.logger.debug('result=%s', result)

    def v2_runner_retry(self, result):
        self.result_update(result)
        self.logger.debug('result=%s', result)
