from datetime import datetime, timedelta

import mock
import pytest
from dateutil.tz import tzlocal

from tests import create_assertion


@pytest.fixture
def mock_botocore_client():
    return mock.Mock()


@pytest.fixture
def client_creator(mock_botocore_client):
    # Create a mock sts client that returns a specific response
    # for assume_role_with_saml.
    expiration = datetime.now(tzlocal()) + timedelta(days=1)
    mock_botocore_client.assume_role_with_saml.return_value = {
        'Credentials': {
            'AccessKeyId': 'foo',
            'SecretAccessKey': 'bar',
            'SessionToken': 'baz',
            'Expiration': expiration
        },
    }
    return mock.Mock(return_value=mock_botocore_client)


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
