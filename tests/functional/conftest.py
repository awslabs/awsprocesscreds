import mock

import pytest
import requests


@pytest.fixture(autouse=True)
def mock_requests_session(monkeypatch):
    session = mock.Mock(spec=requests.Session)
    session_cls = mock.Mock(return_value=session)
    monkeypatch.setattr("requests.Session", session_cls)
    return session
