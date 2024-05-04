from flask.testing import FlaskClient
from werkzeug.test import TestResponse
# from PhishGuard.src.data.user import User
from .test_constants import TestConstants


class UserTestUtils():

    @staticmethod
    def create_test_user(client: FlaskClient, test_user: dict) -> TestResponse:
        return client.post(TestConstants.SIGNUP_USER_ROUTE, json=test_user)

    @staticmethod
    def login_test_user(client: FlaskClient, test_user: dict) -> TestResponse:
        return client.post(TestConstants.LOGIN_USER_ROUTE, json=test_user)

    @staticmethod
    def refresh_tokens_test_user(client: FlaskClient, test_user: dict) -> TestResponse:
        return client.post(TestConstants.LOGIN_USER_ROUTE, json=test_user)

    @staticmethod
    def delete_test_user(client: FlaskClient, jwt_access_token: str) -> TestResponse:
        return client.delete(TestConstants.DELETE_USER_ROUTE,
                             headers=UserTestUtils.generate_authorization_header(jwt_token=jwt_access_token))

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
