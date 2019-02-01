import setuptools
import subprocess
import os
import re

root = os.path.dirname(os.path.realpath(__file__))
vexp = re.compile(r'v(\d+)(\.\d+)+([.-]\w+)?')

def cmd(*args):
    return subprocess.check_output(args, cwd=root).decode().strip()

def tag():
   t = cmd('git', 'tag', '-l', '--contains', 'HEAD') or "v0.0.dev0"
   if not vexp.fullmatch(t):
       raise ValueError(f"current tag {t:s} is not a version number")
   return t

def readme():
    with open(os.path.join(root, 'README.rst'), 'r') as f:
        return f.read()

setuptools.setup(
    name='snare',
    description='Network capture and manipulation module',
    packages=['snare', 'snare.net'],
    version=tag().strip('v'),
    url='https://github.com/nategraf/snare',

    author='Victor "Nate" Graf',
    author_email="nategraf1@gmail.com",
    license='MIT',

    long_description=readme(),
    long_description_content_type="text/x-rst",
    keywords=[],

    install_requires=['scapy'],
    python_requires='>=3',

    classifiers=[
        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: MIT License',

        'Operating System :: OS Independent',
        'Natural Language :: English',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3 :: Only',

	'Topic :: Security',
	'Topic :: Communications',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
