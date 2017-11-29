import base64
import getpass
import logging
import xml.etree.cElementTree as ET
from hashlib import sha1
from copy import deepcopy

import six
import requests
import botocore
from botocore.client import Config
from botocore.compat import urlsplit
from botocore.compat import urljoin
from botocore.compat import json
from botocore.credentials import CachedCredentialFetcher
import botocore.session

from .compat import escape


class SAMLError(Exception):
    pass


logger = logging.getLogger(__name__)


class FormParserError(Exception):
    pass


def _role_selector(role_arn, roles):
    """Select a role based on pre-configured role_arn and IdP roles list.

    Given a roles list in the form of [{"RoleArn": "...", ...}, ...],
    return the item which matches the role_arn, or None otherwise.
    """
    chosen = [r for r in roles if r['RoleArn'] == role_arn]
    return chosen[0] if chosen else None


class SAMLAuthenticator(object):
    def is_suitable(self, config):
        """Return True if this instance intends to perform authentication.

        :type config: dict
        :param config: It is the profile dictionary loaded from user's profile,
            i.e. {'saml_endpoint': 'https://...', 'saml_provider': '...', ...}
        """
        raise NotImplementedError("is_suitable")

    def retrieve_saml_assertion(self, config):
        """Return SAML assertion when login succeeds, or None otherwise."""
        raise NotImplementedError("retrieve_saml_assertion")


class GenericFormsBasedAuthenticator(SAMLAuthenticator):
    USERNAME_FIELD = 'username'
    PASSWORD_FIELD = 'password'

    _ERROR_BAD_RESPONSE = (
        'Received a non-200 response (%s) when making a request to: %s'
    )
    _ERROR_NO_FORM = (
        'Could not find login form from: %s'
    )
    _ERROR_MISSING_FORM_FIELD = (
        'Error parsing HTML form, could not find the form field: "%s"'
    )
    _ERROR_LOGIN_FAILED_NON_200 = (
        'Login failed, received non 200 response: %s'
    )
    _ERROR_LOGIN_FAILED = (
        'Login failed, could not retrieve SAML assertion. '
        'Double check you have entered your password correctly.'
    )
    _ERROR_MISSING_CONFIG = (
        'Missing required config value for SAML: "%s"'
    )

    def __init__(self, password_prompter, requests_session=None):
        """Retrieve SAML assertion using form based auth.

        This class can retrieve a SAML assertion by using form
        based auth.  The supported workflow is:

            * Make a GET request to ``saml_endpoint``
            * Parse the HTML to look for an HTML form
            * Fill in the form data with the username, password
            * Make a POST request to the URL indicated by the form
              action with the filled in form data.
            * Parse the HTML returned from the service and
              extract out the SAMLAssertion.

        :param password_prompter: A function that takes a prompt string and
            returns a password string.

        :param requests_session: A requests session object used to make
            requests to the saml provider.
        """
        if requests_session is None:
            requests_session = requests.Session()
        self._requests_session = requests_session
        self._password_prompter = password_prompter

    def is_suitable(self, config):
        return config.get('saml_authentication_type') == 'form'

    def retrieve_saml_assertion(self, config):
        """Retrive SAML assertion using form based auth.

        This is a generic form based authenticator that will
        make an HTTP request to retrieve an HTML form, fill in the
        form fields with username/password, and submit the form.

        :type config: dict
        :param config: The config associated with the profile.  Contains:

            * saml_endpoint
            * saml_username

        :raises SAMLError: Raised when we are unable to retrieve a
            SAML assertion.

        :rtype: str
        :return: The base64 encoded SAML assertion if the login process
            was successful.

        """
        # precondition: self.is_suitable() returns true.
        # We still need other values in the config dict to work
        # properly, so we have to validate config params before
        # going any further.
        self._validate_config_values(config)
        endpoint = config['saml_endpoint']
        login_url, form_data = self._retrieve_login_form_from_endpoint(
            endpoint)
        self._fill_in_form_values(config, form_data)
        response = self._send_form_post(login_url, form_data)
        return self._extract_saml_assertion_from_response(response)

    def _validate_config_values(self, config):
        for required in ['saml_endpoint', 'saml_username']:
            if required not in config:
                raise SAMLError(self._ERROR_MISSING_CONFIG % required)

    def _retrieve_login_form_from_endpoint(self, endpoint):
        response = self._requests_session.get(endpoint, verify=True)
        self._assert_non_error_response(response)
        login_form_html_node = self._parse_form_from_html(response.text)
        if login_form_html_node is None:
            raise SAMLError(self._ERROR_NO_FORM % endpoint)
        form_action = urljoin(endpoint,
                              login_form_html_node.attrib.get('action', ''))
        if not form_action.lower().startswith('https://'):
            raise SAMLError('Your SAML IdP must use HTTPS connection')
        payload = dict((tag.attrib['name'], tag.attrib.get('value', ''))
                       for tag in login_form_html_node.findall(".//input"))
        return form_action, payload

    def _assert_non_error_response(self, response):
        if response.status_code != 200:
            raise SAMLError(
                self._ERROR_BAD_RESPONSE % (response.status_code,
                                            response.url))

    def _parse_form_from_html(self, html):
        # Scrape a form from html page, and return it as an elementtree element
        parser = FormParser()
        parser.feed(html)
        if parser.forms:
            return ET.fromstring(parser.extract_form(0))

    def _fill_in_form_values(self, config, form_data):
        username = config['saml_username']
        if self.USERNAME_FIELD not in form_data:
            raise SAMLError(
                self._ERROR_MISSING_FORM_FIELD % self.USERNAME_FIELD)
        else:
            form_data[self.USERNAME_FIELD] = username
        if self.PASSWORD_FIELD in form_data:
            form_data[self.PASSWORD_FIELD] = self._password_prompter(
                "Password: ")

    def _send_form_post(self, login_url, form_data):
        response = self._requests_session.post(
            login_url, data=form_data, verify=True
        )
        if response.status_code != 200:
            raise SAMLError(self._ERROR_LOGIN_FAILED_NON_200 %
                            response.status_code)
        return response.text

    def _extract_saml_assertion_from_response(self, response_body):
        parsed = self._parse_form_from_html(response_body)
        if parsed is not None:
            assertion = self._get_value_of_first_tag(
                parsed, 'input', 'name', 'SAMLResponse')
            if assertion is not None:
                return assertion
        # We can reach here in two cases.
        # First, we were able to login but for some reason we can't find the
        # SAMLResponse in the response body.  The second (and more likely)
        # reason is that the login has failed.  For example, if you provide an
        # invalid password when trying to login, many IdPs will return a 200
        # status code and return HTML content that indicates an error occurred.
        # This is the error we'll present to the user.
        raise SAMLError(self._ERROR_LOGIN_FAILED)

    def _get_value_of_first_tag(self, root, tag, attr, trait):
        for element in root.findall(tag):
            if element.attrib.get(attr) == trait:
                return element.attrib.get('value')


class OktaAuthenticator(GenericFormsBasedAuthenticator):
    _AUTH_URL = '/api/v1/authn'

    def retrieve_saml_assertion(self, config):
        self._validate_config_values(config)
        endpoint = config['saml_endpoint']
        hostname = urlsplit(endpoint).netloc
        auth_url = 'https://%s/api/v1/authn' % hostname
        username = config['saml_username']
        password = self._password_prompter("Password: ")
        logger.info(
            'Sending HTTP POST with username (%s) and password to Okta API '
            'endpoint: %s', username, auth_url
        )
        response = self._requests_session.post(
            auth_url,
            headers={'Content-Type': 'application/json',
                     'Accept': 'application/json'},
            data=json.dumps({'username': username,
                             'password': password})
        )
        parsed = json.loads(response.text)
        session_token = parsed['sessionToken']
        saml_url = endpoint + '?sessionToken=%s' % session_token
        response = self._requests_session.get(saml_url)
        logger.info(
            'Received HTTP response of status code: %s', response.status_code)
        r = self._extract_saml_assertion_from_response(response.text)
        logger.info(
            'Received the following SAML assertion: \n%s', r,
            extra={'is_saml_assertion': True}
        )
        return r

    def is_suitable(self, config):
        return (config.get('saml_authentication_type') == 'form' and
                config.get('saml_provider') == 'okta')


class ADFSFormsBasedAuthenticator(GenericFormsBasedAuthenticator):
    USERNAME_FIELD = 'ctl00$ContentPlaceHolder1$UsernameTextBox'
    PASSWORD_FIELD = 'ctl00$ContentPlaceHolder1$PasswordTextBox'

    def is_suitable(self, config):
        return (config.get('saml_authentication_type') == 'form' and
                config.get('saml_provider') == 'adfs')


class FormParser(six.moves.html_parser.HTMLParser):
    def __init__(self):
        """Parse an html saml login form."""
        six.moves.html_parser.HTMLParser.__init__(self)
        self.forms = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        if tag == 'form':
            self._current_form = dict(attrs)
        if tag == 'input' and self._current_form is not None:
            self._current_form.setdefault('_fields', []).append(dict(attrs))

    def handle_endtag(self, tag):
        if tag == 'form' and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def _dict2str(self, d):
        # When input contains things like "&amp;", HTMLParser will unescape it.
        # But we need to use escape() here to nullify the default behavior,
        # so that the output will be suitable to be fed into an ET later.
        return ' '.join(sorted(
            '%s="%s"' % (k, escape(v)) for k, v in d.items()))

    def extract_form(self, index):
        form = dict(self.forms[index])  # Will raise exception if out of bound
        fields = form.pop('_fields', [])
        return '<form %s>%s</form>' % (
            self._dict2str(form),
            ''.join('<input %s/>' % self._dict2str(f) for f in fields))

    def error(self, message):
        # ParserBase, the parent of HTMLParser, defines this abstract method
        # instead of just raising an exception for some silly reason,
        # so we have to implement it.
        raise FormParserError(message)


class SAMLCredentialFetcher(CachedCredentialFetcher):
    SAML_FORM_AUTHENTICATORS = {
        'okta': OktaAuthenticator,
        'adfs': ADFSFormsBasedAuthenticator

    }

    def __init__(self, client_creator, provider_name, saml_config,
                 role_selector=_role_selector,
                 password_prompter=getpass.getpass, cache=None,
                 expiry_window_seconds=60 * 15):
        """Credential fetcher for SAML."""
        self._client_creator = client_creator
        self._role_selector = role_selector
        self._config = saml_config
        self._provider_name = provider_name
        authenticator_cls = self.SAML_FORM_AUTHENTICATORS.get(provider_name)
        if authenticator_cls is None:
            raise ValueError('Unsupported SAML provider: %s' % provider_name)
        self._authenticator = authenticator_cls(password_prompter)

        self._assume_role_kwargs = None

        if cache is None:
            cache = {}
        self._cache = cache
        self._stored_cache_key = None
        self._expiry_window_seconds = expiry_window_seconds

    @property
    def _cache_key(self):
        if self._stored_cache_key is None:
            self._stored_cache_key = self._create_cache_key()
        return self._stored_cache_key

    def _create_cache_key(self):
        cache_key_kwargs = {
            'provider_name': self._provider_name,
            'saml_config': self._config.copy()
        }
        cache_key_kwargs = json.dumps(cache_key_kwargs, sort_keys=True)
        argument_hash = sha1(cache_key_kwargs.encode('utf-8')).hexdigest()
        return self._make_file_safe(argument_hash)

    def fetch_credentials(self):
        creds = super(SAMLCredentialFetcher, self).fetch_credentials()
        return {
            'AccessKeyId': creds['access_key'],
            'SecretAccessKey': creds['secret_key'],
            'SessionToken': creds['token'],
            'Expiration': creds['expiry_time']
        }

    def _get_credentials(self):
        kwargs = self._get_assume_role_kwargs()
        client = self._create_client()
        logger.info(
            'Retrieving credentials with STS.AssumeRoleWithSaml() using the '
            'following parameters: %s', kwargs
        )
        response = deepcopy(client.assume_role_with_saml(**kwargs))
        expiration = response['Credentials']['Expiration'].isoformat()
        response['Credentials']['Expiration'] = expiration
        return response

    def _create_client(self):
        return self._client_creator(
            'sts', config=Config(signature_version=botocore.UNSIGNED)
        )

    def _get_role_and_principal_arn(self, assertion):
        idp_roles = self._parse_roles(assertion)
        role_arn = self._role_selector(self._config.get('role_arn'), idp_roles)
        if not role_arn:
            role_arns = [r['RoleArn'] for r in idp_roles]
            raise SAMLError('Unable to choose role "%s" from %s' % (
                self._config.get('role_arn'), role_arns
            ))

        return role_arn

    def _get_assume_role_kwargs(self):
        if self._assume_role_kwargs is not None:
            return self._assume_role_kwargs

        config = self._config.copy()
        config['saml_provider'] = self._provider_name

        if not self._authenticator.is_suitable(config):
            raise ValueError('Invalid config')
        assertion = self._authenticator.retrieve_saml_assertion(config)
        if not assertion:
            raise SAMLError(
                'Failed to login at %s' % config['saml_endpoint'])

        arns = self._get_role_and_principal_arn(assertion)

        self._assume_role_kwargs = {
            'PrincipalArn': arns['PrincipalArn'],
            'RoleArn': arns['RoleArn'],
            'SAMLAssertion': assertion
        }
        return self._assume_role_kwargs

    def _parse_roles(self, assertion):
        attribute = '{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'
        attr_value = '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'
        awsroles = []
        root = ET.fromstring(base64.b64decode(assertion).decode('ascii'))
        for attr in root.iter(attribute):
            if attr.get('Name') == \
                    'https://aws.amazon.com/SAML/Attributes/Role':
                for value in attr.iter(attr_value):
                    parts = [p.strip() for p in value.text.split(',')]
                    # Deals with "role_arn,pricipal_arn" or its reversed order
                    if 'saml-provider' in parts[0]:
                        role = {'PrincipalArn': parts[0], 'RoleArn': parts[1]}
                    else:
                        role = {'PrincipalArn': parts[1], 'RoleArn': parts[0]}
                    awsroles.append(role)
        return awsroles
