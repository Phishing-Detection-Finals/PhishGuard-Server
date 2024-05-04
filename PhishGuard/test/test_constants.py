class TestConstants():
    SIGNUP_USER_ROUTE = '/auth/signup'
    LOGIN_USER_ROUTE = '/auth/login'
    REFRESH_USER_ACCESS_TOKEN_ROUTE = '/auth/refresh'

    DELETE_USER_ROUTE = '/setting/user'
    GET_USER_ROUTE = '/setting/user'

    TEST_USERNAME_1 = "test1"
    TEST_EMAIL_1 = "test1@gmail.com"
    TEST_PASSWORD = "password"
    TEST_WRONG_JWT_TOKEN = "wrong-token"

    TEST_USER_1 = {
        "username": TEST_USERNAME_1,
        "email": TEST_EMAIL_1,
        "password": TEST_PASSWORD
    }

    AUTH_HEADER_TEMPLATE = "Bearer {jwt_token}"
