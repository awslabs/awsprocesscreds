import argparse
import json
import getpass

import botocore.session

from .saml import SAMLCredentialFetcher


def saml(argv=None, prompter=getpass.getpass, client_creator=None):
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
    args = parser.parse_args(argv)

    if client_creator is None:
        client_creator = botocore.session.Session().create_client

    fetcher = SAMLCredentialFetcher(
        client_creator=client_creator,
        provider_name=args.provider,
        saml_config={
            'saml_endpoint': args.endpoint,
            'saml_authentication_type': 'form',
            'saml_username': args.username,
            'role_arn': args.role_arn
        },
        password_prompter=prompter
    )
    creds = fetcher.fetch_credentials()
    creds['Version'] = 1
    print(json.dumps(creds) + '\n')
