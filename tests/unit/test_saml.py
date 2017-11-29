import base64
import json
from datetime import datetime, timedelta
from copy import deepcopy

import mock
from dateutil.tz import tzlocal
import pytest
import requests

from awsprocesscreds.saml import ADFSFormsBasedAuthenticator
from awsprocesscreds.saml import FormParser
from awsprocesscreds.saml import GenericFormsBasedAuthenticator
from awsprocesscreds.saml import OktaAuthenticator
from awsprocesscreds.saml import SAMLAuthenticator
from awsprocesscreds.saml import SAMLError, FormParserError
from awsprocesscreds.saml import SAMLCredentialFetcher
from tests import create_assertion


@pytest.fixture
def mock_requests_session():
    return mock.Mock(spec=requests.Session)


@pytest.fixture
def generic_auth(prompter, mock_requests_session):
    return GenericFormsBasedAuthenticator(prompter, mock_requests_session)


@pytest.fixture
def okta_auth(prompter, mock_requests_session):
    return OktaAuthenticator(prompter, mock_requests_session)


@pytest.fixture
def adfs_auth(prompter, mock_requests_session):
    return ADFSFormsBasedAuthenticator(prompter, mock_requests_session)


@pytest.fixture
def generic_config():
    return {
        'saml_endpoint': 'https://example.com',
        'saml_authentication_type': 'form',
        'saml_username': 'monty',
        'role_arn': 'arn:aws:iam::123456789012:role/monty',
    }


@pytest.fixture
def okta_config():
    return {
        'saml_endpoint': 'https://example.com',
        'saml_authentication_type': 'form',
        'saml_username': 'monty',
        'saml_provider': 'okta',
    }


@pytest.fixture
def adfs_config():
    return {
        'saml_endpoint': 'https://example.com',
        'saml_authentication_type': 'form',
        'saml_username': 'monty',
        'saml_provider': 'adfs',
    }


@pytest.fixture
def mock_authenticator():
    return mock.Mock(spec=SAMLAuthenticator)


@pytest.fixture
def basic_form():
    return (
        '<form action="/path/login/">'
        '<input name="spam" value="eggs"/>'
        '</form>'
    )


@pytest.fixture
def cache():
    return {}


@pytest.fixture
def fetcher(generic_config, client_creator, prompter, mock_authenticator,
            cache):
    provider_name = 'myprovider'
    authenticator_cls = mock.Mock(return_value=mock_authenticator)

    class MockSAMLFetcher(SAMLCredentialFetcher):
        SAML_FORM_AUTHENTICATORS = {
            provider_name: authenticator_cls
        }

    saml_fetcher = MockSAMLFetcher(
        client_creator=client_creator,
        provider_name=provider_name,
        saml_config=generic_config,
        password_prompter=prompter,
        cache=cache
    )
    return saml_fetcher


class TestSAMLGenericFormsBasedAuthenticator(object):
    def test_form_auth_type_suitable(self, generic_auth):
        config = {'saml_authentication_type': 'form'}
        assert generic_auth.is_suitable(config)

    def test_no_auth_type_not_suitable(self, generic_auth):
        assert not generic_auth.is_suitable({})

    def test_non_form_auth_type_not_suitable(self, generic_auth):
        config = {'saml_authentication_type': 'javascript'}
        assert not generic_auth.is_suitable(config)

    def test_config_missing_username(self, generic_auth):
        config = {
            'saml_endpoint': 'https://example.com',
            'saml_authentication_type': 'form',
        }
        with pytest.raises(SAMLError, match='Missing required'):
            generic_auth.retrieve_saml_assertion(config)

    def test_config_missing_endpoint(self, generic_auth):
        config = {
            'saml_username': 'monty',
            'saml_authentication_type': 'form',
        }
        with pytest.raises(SAMLError, match='Missing required'):
            generic_auth.retrieve_saml_assertion(config)

    def test_login_form_doesnt_exist(self, generic_auth, mock_requests_session,
                                     generic_config):
        mock_requests_session.get.return_value = mock.Mock(
            spec=requests.Response, status_code=200, text='<html>noform</html>'
        )
        with pytest.raises(SAMLError, match='form'):
            generic_auth.retrieve_saml_assertion(generic_config)

    def test_non_https_url(self, generic_auth, mock_requests_session,
                           login_form):
        config = {
            'saml_endpoint': 'http://example.com',
            'saml_authentication_type': 'form',
            'saml_username': 'monty',
        }
        # The error is raised after the call to get the form, but before the
        # call to submit it.
        mock_requests_session.get.return_value = mock.Mock(
            spec=requests.Response, status_code=200, text=login_form
        )
        with pytest.raises(SAMLError, match='HTTPS'):
            generic_auth.retrieve_saml_assertion(config)

    def test_form_action_appended_to_url(self, generic_auth, generic_config,
                                         login_form, mock_requests_session):
        mock_requests_session.get.return_value = mock.Mock(
            spec=requests.Response, status_code=200, text=login_form
        )
        mock_requests_session.post.return_value = mock.Mock(
            spec=requests.Response, status_code=200, text=(
                '<form><input name="SAMLResponse" '
                'value="fakeassertion"/></form>'
            )
        )
        generic_auth.retrieve_saml_assertion(generic_config)
        url_used = mock_requests_session.post.call_args[0][0]
        assert url_used == "https://example.com/login"

    def test_extract_assertion(self, generic_auth, mock_requests_session,
                               generic_config, login_form):
        mock_requests_session.get.return_value = mock.Mock(
            spec=requests.Response, status_code=200, text=login_form
        )
        mock_requests_session.post.return_value = mock.Mock(
            spec=requests.Response, status_code=200, text=(
                '<form><input name="SAMLResponse" '
                'value="fakeassertion"/></form>'
            )
        )

        saml_assertion = generic_auth.retrieve_saml_assertion(generic_config)
        assert saml_assertion == 'fakeassertion'

        mock_requests_session.post.assert_called_with(
            "https://example.com/login", verify=True,
            data={'username': 'monty', 'password': 'mypassword'}
        )

    def test_passes_in_other_form_fields(self, generic_auth, generic_config,
                                         mock_requests_session):
        saml_form = (
            '<html>'
            '<form action="/path/login/">'
            '<input name="spam"/>'
            '<input name="username"/>'
            '<input name="password"/>'
            '</form>'
            '</html>'
        )
        mock_requests_session.get.return_value = mock.Mock(
            spec=requests.Response, status_code=200, text=saml_form
        )
        mock_requests_session.post.return_value = mock.Mock(
            spec=requests.Response, status_code=200, text=(
                '<form><input name="SAMLResponse" '
                'value="fakeassertion"/></form>'
            )
        )
        saml_assertion = generic_auth.retrieve_saml_assertion(generic_config)
        assert saml_assertion == 'fakeassertion'

        mock_requests_session.post.assert_called_with(
            "https://example.com/path/login/", verify=True,
            data={
                'username': 'monty',
                'password': 'mypassword',
                'spam': ''
            }
        )

    def tests_uses_default_form_values(self, generic_auth, generic_config,
                                       mock_requests_session):
        saml_form = (
            '<html>'
            '<form action="/path/login/">'
            '<input name="spam" value="eggs"/>'
            '<input name="username"/>'
            '<input name="password"/>'
            '</form>'
            '</html>'
        )
        mock_requests_session.get.return_value = mock.Mock(
            spec=requests.Response, status_code=200, text=saml_form
        )
        mock_requests_session.post.return_value = mock.Mock(
            spec=requests.Response, status_code=200, text=(
                '<form><input name="SAMLResponse" '
                'value="fakeassertion"/></form>'
            )
        )
        saml_assertion = generic_auth.retrieve_saml_assertion(generic_config)
        assert saml_assertion == 'fakeassertion'

        mock_requests_session.post.assert_called_with(
            "https://example.com/path/login/", verify=True,
            data={
                'username': 'monty',
                'password': 'mypassword',
                'spam': 'eggs'
            }
        )

    def test_error_getting_form(self, generic_auth, mock_requests_session,
                                generic_config):
        mock_requests_session.get.return_value = mock.Mock(
            spec=requests.Response, status_code=404, url='https://example.com',
            text='<html>Not Found</html>'
        )
        with pytest.raises(SAMLError, match='non-200'):
            generic_auth.retrieve_saml_assertion(generic_config)

    def test_missing_form_username(self, generic_auth, mock_requests_session,
                                   generic_config):
        missing_form_fields = (
            '<html><form action="login">'
            '<input name="password"/>'
            '</form></html>'
        )
        mock_requests_session.get.return_value = mock.Mock(
            spec=requests.Response, status_code=200, text=missing_form_fields
        )
        with pytest.raises(SAMLError, match='could not find'):
            generic_auth.retrieve_saml_assertion(generic_config)

    def test_missing_form_password(self, generic_auth, mock_requests_session,
                                   prompter, generic_config):
        missing_form_fields = (
            '<html><form action="login">'
            '<input name="username"/>'
            '</form></html>'
        )
        mock_requests_session.get.return_value = mock.Mock(
            spec=requests.Response, status_code=200, text=missing_form_fields
        )
        mock_requests_session.post.return_value = mock.Mock(
            spec=requests.Response, status_code=200, text=(
                '<form><input name="SAMLResponse" '
                'value="fakeassertion"/></form>'
            )
        )

        saml_assertion = generic_auth.retrieve_saml_assertion(generic_config)
        assert saml_assertion == 'fakeassertion'

        mock_requests_session.post.assert_called_with(
            "https://example.com/login", verify=True,
            data={'username': 'monty'}
        )
        prompter.assert_not_called()

    @pytest.mark.parametrize('assertion_response', [
        ('<form></form>'),
        ('<form><input name="notsaml"></input></form>')
    ])
    def test_empty_assertion(self, generic_auth, mock_requests_session,
                             login_form, generic_config, assertion_response):
        mock_requests_session.get.return_value = mock.Mock(
            spec=requests.Response, status_code=200, text=login_form
        )
        mock_requests_session.post.return_value = mock.Mock(
            spec=requests.Response, status_code=200, text=assertion_response
        )
        with pytest.raises(SAMLError, match='Login failed'):
            generic_auth.retrieve_saml_assertion(generic_config)

    def test_non_200_authenticate_response(self, generic_auth, generic_config,
                                           mock_requests_session, login_form):
        mock_requests_session.get.return_value = mock.Mock(
            spec=requests.Response, text=login_form, status_code=200
        )

        # This 401 response represents an auth failure, such as a bad password.
        form_text = (
            '<form><input name="SAMLResponse" value="fakeassertion"/></form>'
        )
        mock_requests_session.post.return_value = mock.Mock(
            spec=requests.Response, text=form_text, status_code=4-1
        )
        with pytest.raises(SAMLError, match='failed'):
            generic_auth.retrieve_saml_assertion(generic_config)

    def test_no_saml_assertion_in_response(self, generic_auth, generic_config,
                                           mock_requests_session, login_form):
        mock_requests_session.get.return_value = mock.Mock(
            spec=requests.Response, text=login_form, status_code=200
        )
        mock_requests_session.post.return_value = mock.Mock(
            spec=requests.Response, text='<html>login failed</html>',
            status_code=200
        )
        with pytest.raises(SAMLError):
            generic_auth.retrieve_saml_assertion(generic_config)


class TestOktaAuthenticator(object):
    def test_is_suitable(self, okta_auth, okta_config):
        assert okta_auth.is_suitable(okta_config)

    def test_non_form_not_suitable(self, okta_auth):
        config = {
            'saml_authentication_type': 'javascript',
            'saml_provider': 'okta'
        }
        assert not okta_auth.is_suitable(config)

    def test_non_okta_not_suitable(self, okta_auth):
        config = {
            'saml_authentication_type': 'form',
            'saml_provider': 'adfs'
        }
        assert not okta_auth.is_suitable(config)

    def test_authn_requests_made(self, okta_auth, okta_config,
                                 mock_requests_session):
        session_token = 'mytoken'
        # 1st response is for authentication.
        mock_requests_session.post.return_value = mock.Mock(
            text=json.dumps({"sessionToken": session_token}),
            status_code=200
        )
        # 2nd response is to then retrieve the assertion.
        mock_requests_session.get.return_value = mock.Mock(
            text=('<form><input name="SAMLResponse" '
                  'value="fakeassertion"/></form>'),
            status_code=200
        )
        saml_assertion = okta_auth.retrieve_saml_assertion(okta_config)
        assert saml_assertion == 'fakeassertion'

        # Verify we made the correct auth request.
        call_args = mock_requests_session.post.call_args
        url = call_args[0][0]
        payload = json.loads(call_args[1]['data'])
        headers = call_args[1]['headers']

        expected_headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        assert call_args[0][0] == 'https://example.com/api/v1/authn'
        assert payload == {'username': 'monty', 'password': 'mypassword'}
        assert headers == expected_headers

        # And the GET for the SAML assertion should inject the session token.
        mock_requests_session.get.assert_called_with(
            'https://example.com?sessionToken=%s' % session_token
        )


class TestADFSAuthenticator(object):
    def test_is_suitable(self, adfs_auth, adfs_config):
        assert adfs_auth.is_suitable(adfs_config)

    def test_non_form_not_suitable(self, adfs_auth):
        config = {
            'saml_authentication_type': 'javascript',
            'saml_provider': 'adfs',
        }
        assert not adfs_auth.is_suitable(config)

    def test_non_adfs_not_suitable(self, adfs_auth):
        config = {
            'saml_authentication_type': 'form',
            'saml_provider': 'okta',
        }
        assert not adfs_auth.is_suitable(config)

    def test_uses_adfs_fields(self, adfs_auth, mock_requests_session,
                              adfs_config):
        adfs_login_form = (
            '<html>'
            '<form action="login">'
            '<input name="ctl00$ContentPlaceHolder1$UsernameTextBox"/>'
            '<input name="ctl00$ContentPlaceHolder1$PasswordTextBox"/>'
            '</form>'
            '</html>'
        )
        mock_requests_session.get.return_value = mock.Mock(
            spec=requests.Response, status_code=200, text=adfs_login_form
        )
        mock_requests_session.post.return_value = mock.Mock(
            spec=requests.Response, status_code=200, text=(
                '<form><input name="SAMLResponse" '
                'value="fakeassertion"/></form>'
            )
        )

        saml_assertion = adfs_auth.retrieve_saml_assertion(adfs_config)
        assert saml_assertion == 'fakeassertion'

        mock_requests_session.post.assert_called_with(
            "https://example.com/login", verify=True,
            data={
                'ctl00$ContentPlaceHolder1$UsernameTextBox': 'monty',
                'ctl00$ContentPlaceHolder1$PasswordTextBox': 'mypassword'
            }
        )


class TestFormParser(object):
    def test_parse_form(self, basic_form):
        html_input = '<html>%s</html>' % basic_form
        parser = FormParser()
        parser.feed(html_input)
        assert parser.extract_form(0) == basic_form

    def test_ignores_input_outside_form(self, basic_form):
        html_input = '<html><input type="button" action="spam"/>%s</html>'
        html_input = html_input % basic_form
        parser = FormParser()
        parser.feed(html_input)
        assert parser.extract_form(0) == basic_form

    def test_handles_multiple_inputs(self):
        form = (
            '<form action="/path/login/">'
            '<input name="username"/>'
            '<input name="password"/>'
            '</form>'
        )
        html_input = '<html>%s</html>' % form
        parser = FormParser()
        parser.feed(html_input)
        assert parser.extract_form(0) == form

    def test_handles_multiple_forms(self, basic_form):
        html_input = '<html>%s%s</html>' % (basic_form, basic_form)
        parser = FormParser()
        parser.feed(html_input)
        assert parser.extract_form(0) == basic_form
        assert parser.extract_form(1) == basic_form

    def test_strips_unneccesary_elements(self, basic_form):
        html_input = (
            '<html>'
            '<form action="/path/login/">'
            '<div>This will be ignored</div>'
            '<input name="spam" value="eggs"/>'
            '</form>'
            '</html>'
        )
        parser = FormParser()
        parser.feed(html_input)
        assert parser.extract_form(0) == basic_form

    def test_preserves_escaped_characters(self):
        html_input = (
            '<html>'
            '<form action="/path/login/">'
            '<input name="spam&amp;" value="eggs"/>'
            '</form>'
            '</html>'
        )
        expected_output = (
            '<form action="/path/login/">'
            '<input name="spam&amp;" value="eggs"/>'
            '</form>'
        )
        parser = FormParser()
        parser.feed(html_input)
        assert parser.extract_form(0) == expected_output

    def test_raise_error(self):
        parser = FormParser()
        message = 'Why do we have to implement this?'
        with pytest.raises(FormParserError, match=message):
            parser.error(message)


class TestSAMLCredentialFetcher(object):
    def test_assume_role_with_form_provider(self, fetcher, assertion,
                                            mock_authenticator):
        mock_authenticator.retrieve_saml_assertion.return_value = assertion
        creds = fetcher.fetch_credentials()

        assert creds['AccessKeyId'] == 'foo'
        assert creds['SecretAccessKey'] == 'bar'
        assert creds['SessionToken'] == 'baz'

    def test_no_assertion(self, fetcher, mock_authenticator):
        mock_authenticator.retrieve_saml_assertion.return_value = None
        with pytest.raises(SAMLError):
            fetcher.fetch_credentials()

    def test_role_arn_unavailable(self, fetcher, assertion, generic_config,
                                  mock_authenticator):
        mock_authenticator.retrieve_saml_assertion.return_value = assertion
        generic_config['role_arn'] = 'arn:aws:iam::123456789012:role/fake'
        with pytest.raises(SAMLError):
            fetcher.fetch_credentials()

    def test_no_roles_in_assertion(self, fetcher, mock_authenticator):
        saml_assertion = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<saml2p:Response '
            'xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">'
            '<saml2:Assertion '
            'xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">'
            '<saml2:Attribute Name="unknown">'
            '</saml2:Attribute>'
            '</saml2:Assertion>'
            '</saml2p:Response>'
        )
        saml_assertion = base64.b64encode(saml_assertion.encode('ascii'))
        retrieve = mock_authenticator.retrieve_saml_assertion
        retrieve.return_value = saml_assertion
        with pytest.raises(SAMLError):
            fetcher.fetch_credentials()

    def test_arns_stripped(self, fetcher, mock_authenticator):
        provider_arn = 'arn:aws:iam::123456789012:saml-provider/Example'
        role_arn = 'arn:aws:iam::123456789012:role/monty'
        saml_assertion = create_assertion([
            '%s, %s' % (provider_arn, role_arn)
        ])
        retrieve = mock_authenticator.retrieve_saml_assertion
        retrieve.return_value = saml_assertion
        creds = fetcher.fetch_credentials()

        assert creds['AccessKeyId'] == 'foo'
        assert creds['SecretAccessKey'] == 'bar'
        assert creds['SessionToken'] == 'baz'

    def test_cache_key_is_windows_safe(self, fetcher, cache,
                                       mock_authenticator):
        provider_arn = 'arn:aws:iam::123456789012:saml-provider/Example'
        role_arn = 'arn:aws:iam::123456789012:role/monty'
        saml_assertion = create_assertion([
            '%s, %s' % (provider_arn, role_arn)
        ])
        retrieve = mock_authenticator.retrieve_saml_assertion
        retrieve.return_value = saml_assertion
        fetcher.fetch_credentials()

        cache_key = '0cebd512540a4f5fe2edce26319cf1cf3138684f'
        assert cache_key in cache

    def test_datetime_cache_is_always_serialized(self, fetcher, cache,
                                                 mock_botocore_client,
                                                 mock_authenticator):
        expiration = datetime.now(tzlocal()) + timedelta(days=1)
        mock_botocore_client.assume_role_with_saml.return_value = {
            'Credentials': {
                'AccessKeyId': 'foo',
                'SecretAccessKey': 'bar',
                'SessionToken': 'baz',
                'Expiration': expiration
            },
        }

        provider_arn = 'arn:aws:iam::123456789012:saml-provider/Example'
        role_arn = 'arn:aws:iam::123456789012:role/monty'
        saml_assertion = create_assertion([
            '%s, %s' % (provider_arn, role_arn)
        ])
        retrieve = mock_authenticator.retrieve_saml_assertion
        retrieve.return_value = saml_assertion
        fetcher.fetch_credentials()

        cache_key = '0cebd512540a4f5fe2edce26319cf1cf3138684f'
        cache_expiration = cache[cache_key]['Credentials']['Expiration']
        assert not isinstance(cache_expiration, datetime)
        assert cache_expiration == expiration.isoformat()

    def test_only_prompted_once(self, fetcher, mock_botocore_client,
                                mock_authenticator, assertion, cache):
        expiration = datetime.now(tzlocal()) + timedelta(days=1)
        response = {
            'Credentials': {
                'AccessKeyId': 'foo',
                'SecretAccessKey': 'bar',
                'SessionToken': 'baz',
                'Expiration': expiration
            },
        }

        # The fetcher will mutate the response, so we have to pre-fill
        # several responses so that we don't encounter one that's mutated.
        mock_botocore_client.assume_role_with_saml.side_effect = [
            deepcopy(response) for _ in range(5)
        ]
        mock_authenticator.retrieve_saml_assertion.return_value = assertion
        for _ in range(5):
            fetcher.fetch_credentials()
            cache.clear()

        assert mock_authenticator.retrieve_saml_assertion.call_count == 1
