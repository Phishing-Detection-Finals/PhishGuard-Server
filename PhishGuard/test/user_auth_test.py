import pytest
from PhishGuard.__init__ import create_test_app  # Import the Flask app
from flask.testing import FlaskClient
from .user_test_utils import UserTestUtils
from .test_constants import TestConstants
from http import HTTPStatus
# import pdb


@pytest.fixture
def client():
    app = create_test_app()
    with app.test_client() as client:
        yield client


def test_auth_sanity(client: FlaskClient):
    test_user = TestConstants.TEST_USER_1
    # pdb.set_trace()
    access_token, refresh_token = UserTestUtils.create_user_login_and_retrive_tokens(client=client, test_user=test_user)

    # trying to create exist user
    response = UserTestUtils.create_test_user(client=client, test_user=test_user)
    assert response.status_code == HTTPStatus.CONFLICT

    # deleting the user
    response = UserTestUtils.delete_test_user(client=client, jwt_access_token=access_token)
    assert response.status_code == HTTPStatus.OK

    # trying to login to deleted user
    response = UserTestUtils.login_test_user(client=client, test_user=test_user)
    assert response.status_code == HTTPStatus.NOT_FOUND

    # creating the same user
    response = UserTestUtils.create_test_user(client=client, test_user=test_user)
    assert response.status_code == HTTPStatus.CREATED

    # deleting the user
    response = UserTestUtils.delete_test_user(client=client, jwt_access_token=access_token)
    assert response.status_code == HTTPStatus.OK


def test_auth_jwt_tokens_sanity(client: FlaskClient):
    test_user = TestConstants.TEST_USER_1
    # pdb.set_trace()
    access_token, refresh_token = UserTestUtils.create_user_login_and_retrive_tokens(client=client, test_user=test_user)

    # trying to refresh the access token, using wrong token
    response = UserTestUtils.refresh_tokens_test_user(client=client, jwt_refresh_token=TestConstants.TEST_WRONG_JWT_TOKEN)
    assert response.status_code == HTTPStatus.FORBIDDEN

    # trying to refresh the access token, using access token (and not the refresh token)
    response = UserTestUtils.refresh_tokens_test_user(client=client, jwt_refresh_token=access_token)
    assert response.status_code == HTTPStatus.FORBIDDEN

    # refreshing access token
    response = UserTestUtils.refresh_tokens_test_user(client=client, jwt_refresh_token=refresh_token)
    assert response.status_code == HTTPStatus.OK

    # retriving new access token
    new_access_token = response.get_json().get("access_token")
    assert new_access_token != access_token

    # deleting the user using the new access token
    response = UserTestUtils.delete_test_user(client=client, jwt_access_token=new_access_token)
    assert response.status_code == HTTPStatus.OK


def test_auth_jwt_required_with_no_header(client: FlaskClient):
    test_user = TestConstants.TEST_USER_1

    access_token, refresh_token = UserTestUtils.create_user_login_and_retrive_tokens(client=client, test_user=test_user)

    # trying to refresh token without auth header
    response = client.get(TestConstants.REFRESH_USER_ACCESS_TOKEN_ROUTE)
    assert response.status_code == HTTPStatus.UNAUTHORIZED

    # deleting the user
    response = UserTestUtils.delete_test_user(client=client, jwt_access_token=access_token)
    assert response.status_code == HTTPStatus.OK
