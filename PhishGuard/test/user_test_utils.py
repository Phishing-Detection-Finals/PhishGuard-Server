from flask.testing import FlaskClient
from werkzeug.test import TestResponse
# from PhishGuard.src.data.user import User
from .test_constants import TestConstants
from http import HTTPStatus


class UserTestUtils():

    @staticmethod
    def create_test_user(client: FlaskClient, test_user: dict) -> TestResponse:
        return client.post(TestConstants.SIGNUP_USER_ROUTE, json=test_user)

    @staticmethod
    def login_test_user(client: FlaskClient, test_user: dict) -> TestResponse:
        return client.post(TestConstants.LOGIN_USER_ROUTE, json=test_user)

    @staticmethod
    def refresh_tokens_test_user(client: FlaskClient, jwt_refresh_token: dict) -> TestResponse:
        return client.get(TestConstants.REFRESH_USER_ACCESS_TOKEN_ROUTE,
                          headers=UserTestUtils.generate_authorization_header(jwt_token=jwt_refresh_token))

    @staticmethod
    def delete_test_user(client: FlaskClient, jwt_access_token: str) -> TestResponse:
        return client.delete(TestConstants.DELETE_USER_ROUTE,
                             headers=UserTestUtils.generate_authorization_header(jwt_token=jwt_access_token))

    @staticmethod
    def update_test_user_password(client: FlaskClient, jwt_access_token: str, new_password: str) -> TestResponse:
        return client.put(TestConstants.UPDATE_PASSWORD_ROUTE, json={"password": new_password},
                          headers=UserTestUtils.generate_authorization_header(jwt_token=jwt_access_token))

    @staticmethod
    def update_test_user_email(client: FlaskClient, jwt_access_token: str, new_email: str):
        return client.put(TestConstants.UPDATE_EMAIL_ROUTE, json={"email": new_email},
                          headers=UserTestUtils.generate_authorization_header(jwt_token=jwt_access_token))

    @staticmethod
    def update_test_user_username(client: FlaskClient, jwt_access_token: str, new_username: str):
        return client.put(TestConstants.UPDATE_USERNAME_ROUTE, json={"username": new_username},
                          headers=UserTestUtils.generate_authorization_header(jwt_token=jwt_access_token))

    @staticmethod
    def get_test_user_details(client: FlaskClient, jwt_access_token: str) -> TestResponse:
        return client.get(TestConstants.GET_USER_ROUTE,
                          headers=UserTestUtils.generate_authorization_header(jwt_token=jwt_access_token))

    @staticmethod
    def create_user_login_and_retrive_tokens(client: FlaskClient, test_user: dict) -> tuple[str, str]:
        response = UserTestUtils.create_test_user(client=client, test_user=test_user)
        assert response.status_code == HTTPStatus.CREATED

        response = UserTestUtils.login_test_user(client=client, test_user=test_user)
        assert response.status_code == HTTPStatus.OK

        tokens = response.get_json().get("tokens")
        assert tokens and isinstance(tokens, dict)

        access_token = tokens.get("access_token")
        refresh_token = tokens.get("refresh_token")
        assert access_token and refresh_token

        return access_token, refresh_token

    @staticmethod
    def get_test_username(client: FlaskClient, jwt_access_token: str) -> str:
        response = UserTestUtils.get_test_user_details(client=client, jwt_access_token=jwt_access_token)
        assert response.status_code == HTTPStatus.OK

        return response.get_json().get("username")

    @staticmethod
    def generate_authorization_header(jwt_token: str) -> dict:
        return {"Authorization": TestConstants.AUTH_HEADER_TEMPLATE.format(jwt_token=jwt_token)}

    # def dict_to_user(user_dict: dict) -> User:

    #     # Extract user attributes from the dictionary
    #     _id = user_dict.get('_id')
    #     username = user_dict.get('username')
    #     email = user_dict.get('email')
    #     password_hash = user_dict.get('password_hash')

    #     # Create a User instance with the extracted attributes
    #     user = User(
    #         _id=_id,
    #         username=username,
    #         email=email,
    #         password_hash=password_hash
    #     )

    #     return user
