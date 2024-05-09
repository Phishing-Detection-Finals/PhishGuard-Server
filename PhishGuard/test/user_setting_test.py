import pytest
from PhishGuard.__init__ import create_test_app  # Import the Flask app
from flask.testing import FlaskClient
from .test_constants import TestConstants
from .user_test_utils import UserTestUtils
from http import HTTPStatus
import copy


@pytest.fixture
def client():
    app = create_test_app()
    with app.test_client() as client:
        yield client


def test_delete_user(client: FlaskClient):
    test_user = TestConstants.TEST_USER_1

    # create test user and login
    access_token, refresh_token = UserTestUtils.create_user_login_and_retrive_tokens(client=client, test_user=test_user)

    # deleting test user
    response = UserTestUtils.delete_test_user(client=client, jwt_access_token=access_token)
    assert response.status_code == HTTPStatus.OK

    # trying to get deleted user
    response = UserTestUtils.get_test_user_details(client=client, jwt_access_token=access_token)
    assert response.status_code == HTTPStatus.NOT_FOUND


def test_update_password(client: FlaskClient):
    test_user = TestConstants.TEST_USER_1

    # create test user and login
    access_token, refresh_token = UserTestUtils.create_user_login_and_retrive_tokens(client=client, test_user=test_user)

    # trying to update to invalid password
    response = UserTestUtils.update_test_user_password(client=client, jwt_access_token=access_token,
                                                       new_password=TestConstants.INVALID_PASSWORD_1)
    assert response.status_code == HTTPStatus.BAD_REQUEST

    # trying to update to current password
    response = UserTestUtils.update_test_user_password(client=client, jwt_access_token=access_token,
                                                       new_password=test_user.get("password"))
    assert response.status_code == HTTPStatus.BAD_REQUEST

    # trying to update to valid password
    response = UserTestUtils.update_test_user_password(client=client, jwt_access_token=access_token,
                                                       new_password=TestConstants.TEST_STRONG_PASSWORD_2)
    assert response.status_code == HTTPStatus.OK

    # trying to login using old password
    response = UserTestUtils.login_test_user(client=client, test_user=test_user)
    assert response.status_code == HTTPStatus.UNAUTHORIZED

    # login using new password
    test_user = copy.deepcopy(TestConstants.TEST_USER_1)
    test_user["password"] = TestConstants.TEST_STRONG_PASSWORD_2
    response = UserTestUtils.login_test_user(client=client, test_user=test_user)
    assert response.status_code == HTTPStatus.OK

    # deleting user
    response = UserTestUtils.delete_test_user(client=client, jwt_access_token=access_token)
    assert response.status_code == HTTPStatus.OK


def test_update_email(client: FlaskClient):
    test_user = TestConstants.TEST_USER_1

    test_user_2 = TestConstants.TEST_USER_2

    # create test user and login
    access_token, refresh_token = UserTestUtils.create_user_login_and_retrive_tokens(client=client, test_user=test_user)

    # trying to update to invalid email
    response = UserTestUtils.update_test_user_email(client=client, jwt_access_token=access_token,
                                                    new_email=TestConstants.INVALID_EMAIL_1)
    assert response.status_code == HTTPStatus.BAD_REQUEST

    # trying to update to current email
    response = UserTestUtils.update_test_user_email(client=client, jwt_access_token=access_token,
                                                    new_email=test_user.get("email"))
    assert response.status_code == HTTPStatus.BAD_REQUEST

    # trying to update to exists user's email

    # creating test_user_2
    access_token_2, refresh_token_2 = UserTestUtils.create_user_login_and_retrive_tokens(client=client, test_user=test_user_2)

    # changing user 1 email to user 2 email
    response = UserTestUtils.update_test_user_email(client=client, jwt_access_token=access_token,
                                                    new_email=test_user_2.get("email"))

    assert response.status_code == HTTPStatus.CONFLICT

    # deleting test_user_2
    response = UserTestUtils.delete_test_user(client=client, jwt_access_token=access_token_2)
    assert response.status_code == HTTPStatus.OK

    # trying to update to valid email
    response = UserTestUtils.update_test_user_email(client=client, jwt_access_token=access_token,
                                                    new_email=TestConstants.TEST_EMAIL_2)
    assert response.status_code == HTTPStatus.OK

    # trying to login using old email
    response = UserTestUtils.login_test_user(client=client, test_user=test_user)
    assert response.status_code == HTTPStatus.NOT_FOUND

    # login using new email
    test_user = copy.deepcopy(TestConstants.TEST_USER_1)
    test_user["email"] = TestConstants.TEST_EMAIL_2
    response = UserTestUtils.login_test_user(client=client, test_user=test_user)

    # retriving access token
    tokens = response.get_json().get("tokens")
    assert tokens and isinstance(tokens, dict)
    access_token = tokens.get("access_token")

    # deleting user
    response = UserTestUtils.delete_test_user(client=client, jwt_access_token=access_token)
    assert response.status_code == HTTPStatus.OK


def test_update_username(client: FlaskClient):
    test_user = TestConstants.TEST_USER_1

    # create test user and login
    access_token, refresh_token = UserTestUtils.create_user_login_and_retrive_tokens(client=client, test_user=test_user)

    # trying to update to invalid username
    response = UserTestUtils.update_test_user_username(client=client, jwt_access_token=access_token,
                                                       new_username=TestConstants.INVALID_USERNAME_1)
    assert response.status_code == HTTPStatus.BAD_REQUEST

    # trying to update to current username
    response = UserTestUtils.update_test_user_username(client=client, jwt_access_token=access_token,
                                                       new_username=test_user.get("username"))
    assert response.status_code == HTTPStatus.BAD_REQUEST

    new_username = TestConstants.TEST_USERNAME_2

    # trying to update to valid username
    response = UserTestUtils.update_test_user_username(client=client, jwt_access_token=access_token, new_username=new_username)
    assert response.status_code == HTTPStatus.OK

    # getting username and checking for equal usernames
    response_username = UserTestUtils.get_test_username(client=client, jwt_access_token=access_token)

    assert response_username == new_username

    # deleting user
    response = UserTestUtils.delete_test_user(client=client, jwt_access_token=access_token)
    assert response.status_code == HTTPStatus.OK


def test_get_user_details(client: FlaskClient):
    test_user = TestConstants.TEST_USER_1

    # create test user and login
    access_token, refresh_token = UserTestUtils.create_user_login_and_retrive_tokens(client=client, test_user=test_user)
    response = UserTestUtils.get_test_user_details(client=client, jwt_access_token=access_token)
    assert response.status_code == HTTPStatus.OK

    # comparing user values
    user_response = response.get_json()
    assert user_response.get("username") == test_user.get("username")
    assert user_response.get("email") == test_user.get("email").lower()  # lower() is to make sure input email normalized

    # deleting test user
    response = UserTestUtils.delete_test_user(client=client, jwt_access_token=access_token)
    assert response.status_code == HTTPStatus.OK
