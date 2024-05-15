import pytest
from PhishGuard.__init__ import create_test_app  # Import the Flask app
from .test_constants import TestConstants
from .user_test_utils import UserTestUtils
from flask.testing import FlaskClient
from http import HTTPStatus
import copy


@pytest.fixture
def client():
    app = create_test_app()
    with app.test_client() as client:
        yield client


@pytest.mark.parametrize("invalid_email", TestConstants.INVALID_EMAIL_LIST)
def test_email_validation_using_signup(client: FlaskClient, invalid_email: str):
    # assigning invalid email to the user
    user = copy.deepcopy(TestConstants.TEST_USER_1)
    user["email"] = invalid_email
    response = UserTestUtils.create_test_user(client=client, test_user=user)
    assert response.status_code == HTTPStatus.BAD_REQUEST


@pytest.mark.parametrize("invalid_password", TestConstants.INVALID_PASSWORD_LIST)
def test_password_validation_using_signup(client: FlaskClient, invalid_password: str):
    # assigning invalid password to the user
    user = copy.deepcopy(TestConstants.TEST_USER_1)
    user["password"] = invalid_password
    response = UserTestUtils.create_test_user(client=client, test_user=user)
    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_username_validation_using_signup(client: FlaskClient):
    user = copy.deepcopy(TestConstants.TEST_USER_1)

    # assinging none as username
    user["username"] = None
    response = UserTestUtils.create_test_user(client=client, test_user=user)
    assert response.status_code == HTTPStatus.BAD_REQUEST

    # assigning empty string as username
    user["username"] = ""
    response = UserTestUtils.create_test_user(client=client, test_user=user)
    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_email_validation_using_login(client: FlaskClient):
    # assigning invalid email to the user
    user = copy.deepcopy(TestConstants.TEST_USER_1)
    user["email"] = TestConstants.INVALID_EMAIL_1
    response = UserTestUtils.login_test_user(client=client, test_user=user)
    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_required_input_signup(client: FlaskClient):
    # trying to create an empty user
    response = UserTestUtils.create_test_user(client=client, test_user=TestConstants.TEST_INVALID_USER_INPUT_NO_DATA)
    assert response.status_code == HTTPStatus.BAD_REQUEST

    # trying to create None user
    response = UserTestUtils.create_test_user(client=client, test_user=TestConstants.TEST_INVALID_USER_INPUT_NONE_DATA)
    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_required_input_login(client: FlaskClient):
    # trying to login to an empty user
    response = UserTestUtils.login_test_user(client=client, test_user=TestConstants.TEST_INVALID_USER_INPUT_NO_DATA)
    assert response.status_code == HTTPStatus.BAD_REQUEST

    # trying to login to a None user
    response = UserTestUtils.login_test_user(client=client, test_user=TestConstants.TEST_INVALID_USER_INPUT_NONE_DATA)
    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_required_input_update_data(client: FlaskClient):
    # create test user and retrive jwt tokens
    access_token, refresh_token = UserTestUtils.create_user_login_and_retrive_tokens(client=client,
                                                                                     test_user=TestConstants.TEST_USER_1)

    # trying to update password to an empty password
    response = UserTestUtils.update_test_user_password(client=client, jwt_access_token=access_token, new_password="")
    assert response.status_code == HTTPStatus.BAD_REQUEST

    # trying to update password to a None password
    response = UserTestUtils.update_test_user_password(client=client, jwt_access_token=access_token, new_password=None)
    assert response.status_code == HTTPStatus.BAD_REQUEST

    # trying to update email to an empty email
    response = UserTestUtils.update_test_user_email(client=client, jwt_access_token=access_token, new_email="")
    assert response.status_code == HTTPStatus.BAD_REQUEST

    # trying to update email to a None email
    response = UserTestUtils.update_test_user_email(client=client, jwt_access_token=access_token, new_email=None)
    assert response.status_code == HTTPStatus.BAD_REQUEST

    # trying to update username to an empty username
    response = UserTestUtils.update_test_user_username(client=client, jwt_access_token=access_token, new_username="")
    assert response.status_code == HTTPStatus.BAD_REQUEST

    # trying to update username to a None username
    response = UserTestUtils.update_test_user_username(client=client, jwt_access_token=access_token, new_username=None)
    assert response.status_code == HTTPStatus.BAD_REQUEST

    # deleting test user
    response = UserTestUtils.delete_test_user(client=client, jwt_access_token=access_token)
    assert response.status_code == HTTPStatus.OK
