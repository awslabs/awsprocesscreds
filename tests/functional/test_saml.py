import mock
import json

import requests
import pytest

from awsprocesscreds.cli import saml
from awsprocesscreds.saml import SAMLCredentialFetcher


@pytest.fixture
def argv():
    return [
        '--endpoint', 'https://example.com',
        '--username', 'monty',
        '--provider', 'okta',
        '--role-arn', 'arn:aws:iam::123456789012:role/monty',
    ]


def test_cli(mock_requests_session, argv, prompter, assertion, client_creator,
             capsys):
    session_token = {'sessionToken': 'spam'}
    token_response = mock.Mock(
        spec=requests.Response, status_code=200, text=json.dumps(session_token)
    )
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % assertion.decode('ascii')
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )

    mock_requests_session.post.return_value = token_response
    mock_requests_session.get.return_value = assertion_response
    saml(argv=argv, prompter=prompter, client_creator=client_creator)

    stdout, _ = capsys.readouterr()
    assert stdout.endswith('\n')

    response = json.loads(stdout)
    expected_response = {
        "AccessKeyId": "foo",
        "SecretAccessKey": "bar",
        "SessionToken": "baz",
        "Expiration": mock.ANY,
        "Version": 1
    }
    assert response == expected_response


def test_unsupported_saml_auth_type(client_creator, prompter):
    invalid_config = {
        'saml_authentication_type': 'unsupported',
        'saml_provider': 'okta',
        'saml_endpoint': 'https://example.com/',
        'saml_username': 'monty',
    }
    fetcher = SAMLCredentialFetcher(
        client_creator=client_creator,
        saml_config=invalid_config,
        provider_name='okta',
        password_prompter=prompter,
    )
    with pytest.raises(ValueError):
        fetcher.fetch_credentials()


def test_unsupported_saml_provider(client_creator, prompter):
    invalid_config = {
        'saml_authentication_type': 'form',
        'saml_provider': 'unsupported',
        'saml_endpoint': 'https://example.com/',
        'saml_username': 'monty',
    }
    with pytest.raises(ValueError):
        SAMLCredentialFetcher(
            client_creator=client_creator,
            saml_config=invalid_config,
            provider_name='unsupported',
            password_prompter=prompter,
        )


def test_prompter_only_called_once(client_creator, prompter, assertion,
                                   mock_requests_session):
    session_token = {'sessionToken': 'spam'}
    token_response = mock.Mock(
        spec=requests.Response, status_code=200, text=json.dumps(session_token)
    )
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % assertion.decode('ascii')
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )

    mock_requests_session.post.return_value = token_response
    mock_requests_session.get.return_value = assertion_response

    config = {
        'saml_authentication_type': 'form',
        'saml_provider': 'okta',
        'saml_endpoint': 'https://example.com/',
        'saml_username': 'monty',
        'role_arn': 'arn:aws:iam::123456789012:role/monty'
    }
    fetcher = SAMLCredentialFetcher(
        client_creator=client_creator,
        saml_config=config,
        provider_name='okta',
        password_prompter=prompter,
    )
    for _ in range(5):
        fetcher.fetch_credentials()
    response = fetcher.fetch_credentials()
    expected_response = {
        "AccessKeyId": "foo",
        "SecretAccessKey": "bar",
        "SessionToken": "baz",
        "Expiration": mock.ANY,
    }
    assert response == expected_response
    assert prompter.call_count == 1
