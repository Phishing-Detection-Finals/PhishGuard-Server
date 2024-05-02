import pytest
from PhishGuard.__init__ import create_test_app  # Import the Flask app
# from PhishGuard.src.db.phishguard_db_connection import PhishGuardDBConnection
from .user_test_utils import UserTestUtils
from .test_constants import TestConstants
from http import HTTPStatus
import pdb


@pytest.fixture
def client():
    app = create_test_app()
    with app.test_client() as client:
        yield client


def test_auth_sanity(client):
    # pdb.set_trace()
    # create user
    response = UserTestUtils.create_test_user(client=client, test_user=TestConstants.TEST_USER_1)
    assert response.status_code == HTTPStatus.CREATED

    user_email = response.get_json().get("user_email")
    assert user_email

    response = UserTestUtils.login_test_user(client=client, test_user=TestConstants.TEST_USER_1)
    assert response.status_code == HTTPStatus.OK

    # retrive tokens
    tokens = response.get_json().get("tokens")
    assert tokens and isinstance(tokens, dict)

    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    assert access_token and refresh_token
