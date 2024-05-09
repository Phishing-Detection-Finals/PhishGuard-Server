import pytest
from PhishGuard.__init__ import create_test_app  # Import the Flask app
from .test_constants import TestConstants
from .user_test_utils import UserTestUtils
from flask.testing import FlaskClient
from http import HTTPStatus


@pytest.fixture
def client():
    app = create_test_app()
    with app.test_client() as client:
        yield client


@pytest.mark.parametrize("invalid_email", TestConstants.INVALID_EMAIL_LIST)
def test_email_validation_using_signup(client: FlaskClient, invalid_email: str):
    # assigning invalid email to the user
    user = TestConstants.TEST_USER_1
    user["email"] = invalid_email
    response = UserTestUtils.create_test_user(client=client, test_user=user)
    assert response.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.parametrize("invalid_password", TestConstants.INVALID_PASSWORD_LIST)
def test_password_validation_using_signup(client: FlaskClient, invalid_password: str):
    # assigning invalid password to the user
    user = TestConstants.TEST_USER_1
    user["password"] = invalid_password
    response = UserTestUtils.create_test_user(client=client, test_user=user)
    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_username_validation_using_signup(client: FlaskClient):
    user = TestConstants.TEST_USER_1

    # assinging none as username
    user["username"] = None
    response = UserTestUtils.create_test_user(client=client, test_user=user)
    assert response.status_code == HTTPStatus.BAD_REQUEST

    # assigning empty string as username
    user["username"] = ""
    response = UserTestUtils.create_test_user(client=client, test_user=user)
    assert response.status_code == HTTPStatus.BAD_REQUEST
