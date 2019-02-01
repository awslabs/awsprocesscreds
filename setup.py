#!/usr/bin/env python
import codecs
import os.path
import re
from setuptools import setup, find_packages

HERE = os.path.abspath(os.path.dirname(__file__))


def read(*parts):
    return codecs.open(os.path.join(HERE, *parts), 'r').read()


def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")



install_requires = [
    'botocore>=1.8.1,<2.0.0',
    'six>=1.8.0,<2.0.0',
    'requests>=2.7.0,<3.0.0'
]

setup(
    name='awsprocesscreds',
    version=find_version('awsprocesscreds', '__init__.py'),
    description='AWS Process Credential Providers.',
    long_description=read('README.rst'),
    author='Amazon Web Services',
    url='https://github.com/awslabs/awsprocesscreds',
    packages=find_packages(exclude=['tests']),
    install_requires=install_requires,
    license='Apache License 2.0',
    keywords='aws credentials',
    entry_points={
        'console_scripts': [
            'awsprocesscreds-saml = awsprocesscreds.cli:saml'
        ]
    },
    classifiers=(
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ),
)
