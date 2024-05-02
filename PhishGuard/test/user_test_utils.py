from flask.testing import FlaskClient, TestResponse
from PhishGuard.src.data.user import User
from test_constants import TestConstants


class UserTestUtils():

    @staticmethod
    def create_test_user(client: FlaskClient, test_user: dict) -> TestResponse:
        return client.post(TestConstants.SIGNUP_ROUTE, json=test_user)

    @staticmethod
    def login_test_user(client: FlaskClient, test_user: dict) -> TestResponse:
        return client.post(TestConstants.LOGIN_ROUTE, json=test_user)

    @staticmethod
    def login_test_user(client: FlaskClient, test_user: dict) -> TestResponse:
        return client.post(TestConstants.LOGIN_ROUTE, json=test_user)

    @staticmethod
    def generate_authorization_header(jwt_token: str):
        return {"Authorization": TestConstants.AUTH_HEADER_TEMPLATE.format(jwt_token=jwt_token)}



    def dict_to_user(user_dict: dict) -> User:

        # Extract user attributes from the dictionary
        _id = user_dict.get('_id')
        username = user_dict.get('username')
        email = user_dict.get('email')
        password_hash = user_dict.get('password_hash')
        
        # Create a User instance with the extracted attributes
        user = User(
            _id=_id,
            username=username,
            email=email,
            password_hash=password_hash
        )
        
        return user