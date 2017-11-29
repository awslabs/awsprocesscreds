from __future__ import print_function
import argparse
import json
import getpass
import sys
import logging
import base64
import xml.dom.minidom

import botocore.session

from .saml import SAMLCredentialFetcher
from .cache import JSONFileCache


def saml(argv=None, prompter=getpass.getpass, client_creator=None,
         cache_dir=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-e', '--endpoint', required=True, help=(
            'The SAML idp endpoint.'
        )
    )
    parser.add_argument(
        '-u', '--username', required=True,
        help='Your SAML username.'
    )
    parser.add_argument(
        '-p', '--provider', required=True, choices=['okta', 'adfs'],
        help=(
            'The name of your SAML provider. Currently okta and adfs '
            'form-based auth is supported.'
        )
    )
    parser.add_argument(
        '-a', '--role-arn', required=True, help=(
            'The role arn you wish to assume. Your SAML provider must be '
            'configured to give you access to this arn.'
        )
    )
    parser.add_argument(
        '--no-cache', action='store_false', default=True, dest='cache',
        help=(
            'Disables the storing and retrieving of credentials from the '
            'local file cache.'
        )
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true', help=('Enables verbose mode.')
    )
    args = parser.parse_args(argv)

    if args.verbose:
        logger = logging.getLogger('awsprocesscreds')
        logger.setLevel(logging.INFO)
        handler = PrettyPrinterLogHandler(sys.stdout)
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    if client_creator is None:
        client_creator = botocore.session.Session().create_client

    cache = {}
    if args.cache:
        cache = JSONFileCache(cache_dir)

    fetcher = SAMLCredentialFetcher(
        client_creator=client_creator,
        provider_name=args.provider,
        saml_config={
            'saml_endpoint': args.endpoint,
            'saml_authentication_type': 'form',
            'saml_username': args.username,
            'role_arn': args.role_arn
        },
        password_prompter=prompter,
        cache=cache
    )
    creds = fetcher.fetch_credentials()
    creds['Version'] = 1
    print(json.dumps(creds) + '\n')


class PrettyPrinterLogHandler(logging.StreamHandler):
    def emit(self, record):
        self._pformat_record_args(record)
        super(PrettyPrinterLogHandler, self).emit(record)

    def _pformat_record_args(self, record):
        if isinstance(record.args, dict):
            record.args = self._pformat_dict(record.args)
        elif getattr(record, 'is_saml_assertion', False):
            formatted = self._pformat_saml_assertion(record.args[0])
            record.args = tuple([formatted])

    def _pformat_dict(self, args):
        return json.dumps(args, indent=4, sort_keys=True)

    def _pformat_saml_assertion(self, assertion):
        xml_string = base64.b64decode(assertion).decode('utf-8')
        return xml.dom.minidom.parseString(xml_string).toprettyxml()
