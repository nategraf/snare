# coding: utf-8
"""
OpenVPN functions.
"""
import fcntl
import os
import subprocess
import logging

logger = logging.getLogger(__name__)

class OpenVpnError(Exception):
    def __init__(self, instance, msg):
        self.instance = instance
        super().__init__(msg)

class OpenVpn:
    exe = 'openvpn'
    initmsg = b'Initialization Sequence Completed'

    def __init__(self, **kwargs):
        if 'daemonize' in kwargs:
            warnings.warn("This class will not be able to close a daemonized tunnel", warnings.Warning)

        self.options = kwargs
        self.initialized = False
        self._process = None

    def args(self):
        result = []
        for name, value in self.options.items():
            result.append('--{:s}'.format(name.replace('_', '-')))

            # None is special to indicate the option have no value
            if value is not None:
                result.append(str(value))
        return result

    def check(self):
        if self._process is not None:
            self._process.poll()
            code = self._process.returncode
            if code is not None and code != 0:
                raise OpenVpnError(self, "`openvpn {:s}` exited with error code: {:d}".format(" ".join(self.args()), code))

    def running(self):
        return self._process is not None and self._process.poll() is None

    @staticmethod
    def maketun():
        os.makedirs('/dev/net', exist_ok=True)
        subprocess.run(['mknod', '/dev/net/tun', 'c', '10', '200'], check=True)

    def connect(self):
        if not os.path.exists('/dev/net/tun'):
            self.maketun()

        if not self.running():
            self.initialized = False
            self._process = subprocess.Popen(
                [self.exe] + self.args(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            self.check()

    def disconnect(self):
        if self.running():
            self._process.terminate()
            try:
                os.waitpid(self._process.pid, 0)
            except ChildProcessError:
                # process is already dead
                pass

    def waitforinit(self):
        if not self.initialized:
            for line in self._process.stdout:
                logger.debug("openvpn: %s", line.decode('utf-8').strip())
                if self.initmsg in line:
                    self.initialized = True
                    break
            else:
                self.check()
                raise OpenVpnError(self, "OpenVPN exited with code 0, but did not display init msg")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args, **kwargs):
        self.disconnect()

