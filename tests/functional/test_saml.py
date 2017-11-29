import mock
import json
import logging
import xml.dom.minidom
import base64

import requests
import pytest

from tests import create_assertion
from awsprocesscreds.cli import saml, PrettyPrinterLogHandler
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
             capsys, cache_dir):
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
    saml(argv=argv, prompter=prompter, client_creator=client_creator,
         cache_dir=cache_dir)

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


def test_no_cache(mock_requests_session, argv, prompter, assertion,
                  client_creator, capsys, cache_dir):
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

    argv.append('--no-cache')

    expected_response = {
        "AccessKeyId": "foo",
        "SecretAccessKey": "bar",
        "SessionToken": "baz",
        "Expiration": mock.ANY,
        "Version": 1
    }

    call_count = 5
    for _ in range(call_count):
        saml(argv=argv, prompter=prompter, client_creator=client_creator,
             cache_dir=cache_dir)
        stdout, _ = capsys.readouterr()
        assert json.loads(stdout) == expected_response

    assert mock_requests_session.post.call_count == call_count
    assert mock_requests_session.get.call_count == call_count
    assert prompter.call_count == call_count


def test_verbose(mock_requests_session, argv, prompter, assertion,
                 client_creator, cache_dir):
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

    argv.append('--verbose')

    saml(argv=argv, prompter=prompter, client_creator=client_creator,
         cache_dir=cache_dir)

    logger = logging.getLogger('awsprocesscreds')
    assert logger.level == logging.INFO

    pretty_handlers = [
        h for h in logger.handlers if isinstance(h, PrettyPrinterLogHandler)
    ]
    assert len(pretty_handlers) == 1
    handler = pretty_handlers[0]
    assert handler.level == logging.INFO


def test_log_handler_parses_assertion(mock_requests_session, argv, prompter,
                                      client_creator, cache_dir, caplog):
    session_token = {'sessionToken': 'spam'}
    token_response = mock.Mock(
        spec=requests.Response, status_code=200, text=json.dumps(session_token)
    )

    provider_arn = 'arn:aws:iam::123456789012:saml-provider/Example'
    role_arn = 'arn:aws:iam::123456789012:role/monty'
    saml_assertion = create_assertion([
        '%s, %s' % (provider_arn, role_arn)
    ])
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % saml_assertion.decode('ascii')
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )

    mock_requests_session.post.return_value = token_response
    mock_requests_session.get.return_value = assertion_response

    argv.append('--verbose')

    saml(argv=argv, prompter=prompter, client_creator=client_creator,
         cache_dir=cache_dir)

    decoded_assertion = base64.b64decode(saml_assertion).decode('utf-8')
    expected_assertion = xml.dom.minidom.parseString(decoded_assertion)
    expected_assertion = expected_assertion.toprettyxml()
    expected_log = (
        'awsprocesscreds.saml',
        logging.INFO,
        'Received the following SAML assertion: \n%s' % expected_assertion
    )
    assert expected_log in caplog.record_tuples


def test_log_handler_parses_dict(mock_requests_session, argv, prompter,
                                 client_creator, cache_dir, caplog):
    session_token = {'sessionToken': 'spam'}
    token_response = mock.Mock(
        spec=requests.Response, status_code=200, text=json.dumps(session_token)
    )

    provider_arn = 'arn:aws:iam::123456789012:saml-provider/Example'
    role_arn = 'arn:aws:iam::123456789012:role/monty'
    saml_assertion = create_assertion([
        '%s, %s' % (provider_arn, role_arn)
    ])
    assertion_form = '<form><input name="SAMLResponse" value="%s"/></form>'
    assertion_form = assertion_form % saml_assertion.decode('ascii')
    assertion_response = mock.Mock(
        spec=requests.Response, status_code=200, text=assertion_form
    )

    mock_requests_session.post.return_value = token_response
    mock_requests_session.get.return_value = assertion_response

    argv.append('--verbose')

    saml(argv=argv, prompter=prompter, client_creator=client_creator,
         cache_dir=cache_dir)

    expected_params = {
        'PrincipalArn': provider_arn,
        'RoleArn': role_arn,
        'SAMLAssertion': saml_assertion.decode('utf-8')
    }
    expected_log_message = (
        'Retrieving credentials with STS.AssumeRoleWithSaml() using the '
        'following parameters: %s' % json.dumps(
            expected_params, indent=4, sort_keys=True)
    )
    expected_log = (
        'awsprocesscreds.saml',
        logging.INFO,
        expected_log_message
    )
    assert expected_log in caplog.record_tuples


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
