# coding: utf-8
"""
iptables manipulation functions.
"""

import subprocess
import logging
import collections.abc

logger = logging.getLogger(__name__)

class BadRuleError(Exception):
    """
    Raised when an iptables command failes with the "Bad rule" message
    This will occur when trying to check or delete a rule which does not exist
    """
    def __init__(self, rule):
        self.rule = rule

    def __str__(self):
        return "rule specified by '{:s}' does not exist in chain {:s}".format(" ".join(self.rule.args()), self.rule.chain)

class IptablesRule:
    exe = 'iptables'
    badrulemsg = b'Bad rule'

    def __init__(self, chain, rulenum=None, **kwargs):
        self.chain = chain
        self.rulenum = rulenum
        self.options = kwargs
        self.applied = False

    def args(self):
        result = []
        for name, value in self.options.items():
            if len(name) == 1:
                result.append('-{:s}'.format(name))
            else:
                result.append('--{:s}'.format(name.replace('_', '-')))

            # None is special to indicate the option has no value
            if value is not None:
                # iptables has options with more than one value following
                if any(isinstance(value, t) for t in (str, bytes)):
                    result.append(value)
                elif isinstance(value, collections.abc.Iterable):
                    result.extend(value)
                else:
                    result.append(str(value))

        return result

    def _run(self, cmd, **kwargs):
        try:
            return subprocess.run(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                **kwargs
            )
        except subprocess.CalledProcessError as e:
            if self.badrulemsg in e.stderr:
                raise BadRuleError(self)
            else:
                raise

    def exists(self):
        try:
            self._run([self.exe, '-C', self.chain] + self.args())
        except BadRuleError:
            return False
        return True

    def apply(self):
        if self.rulenum is not None:
            self._run([self.exe, '-I', self.chain, str(self.rulenum)] + self.args())
        else:
            self._run([self.exe, '-A', self.chain] + self.args())
        self.applied = True

    def delete(self):
        self._run([self.exe, '-D', self.chain] + self.args())
        self.applied = False

    def __enter__(self):
        if not self.applied:
            self.apply()
        return self

    def __exit__(self, *args, **kwargs):
        if self.applied:
            self.delete()
