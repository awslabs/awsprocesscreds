import base64
from datetime import datetime, timedelta

import mock
import pytest
from dateutil.tz import tzlocal


@pytest.fixture
def client_creator():
    # Create a mock sts client that returns a specific response
    # for assume_role_with_saml.
    client = mock.Mock()
    expiration = datetime.now(tzlocal()) + timedelta(days=1)
    client.assume_role_with_saml.return_value = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': expiration.isoformat()
        },
    }
    return mock.Mock(return_value=client)


@pytest.fixture
def prompter():
    return mock.Mock(return_value='mypassword')


@pytest.fixture
def login_form():
    return (
        '<html>'
        '<form action="login">'
        '<input name="username"/>'
        '<input name="password"/>'
        '</form>'
        '</html>'
    )


def create_assertion(roles):
    saml_assertion = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">'
        '<saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">'
    )
    for role in roles:
        partial = '<saml2:AttributeValue>%s</saml2:AttributeValue>' % role
        saml_assertion += partial
    saml_assertion += (
        '</saml2:Attribute>'
        '</saml2:Assertion>'
        '</saml2p:Response>'
    )
    return base64.b64encode(saml_assertion.encode('ascii'))


@pytest.fixture(params=[
    {'reversed': False},
    {'reversed': True}
])
def assertion(request):
    provider_arn = 'arn:aws:iam::123456789012:saml-provider/Example'
    role_arn = 'arn:aws:iam::123456789012:role/monty'
    is_reversed = request.param.get('reversed', False)
    if not is_reversed:
        config_string = '%s,%s' % (provider_arn, role_arn)
    else:
        config_string = '%s,%s' % (role_arn, provider_arn)
    return create_assertion([config_string])
