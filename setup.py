#!/usr/bin/env python
from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    README = readme_file.read()


install_requires = [
    'botocore>=1.8.1,<2.0.0',
    'six>=1.8.0,<2.0.0',
    'requests>=2.7.0,<3.0.0'
]

setup(
    name='awsprocesscreds',
    version='0.0.1',
    description='AWS Process Credential Providers.',
    long_description=README,
    author='Amazon Web Services',
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
