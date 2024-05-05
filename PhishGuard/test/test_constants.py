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

    # Constants for invalid email test cases
    INVALID_EMAIL_1 = "usernameexample.com"  # Missing @ Symbol
    INVALID_EMAIL_2 = "user@@name@example.com"  # Multiple @ Symbols
    INVALID_EMAIL_3 = "username@exa!mple.com"  # Special Characters in Domain
    INVALID_EMAIL_4 = "user..name@example.com"  # Consecutive Dots
    INVALID_EMAIL_5 = "username@-example.com"  # Domain Starts with a Hyphen
    INVALID_EMAIL_6 = "user[name@example.com"  # Brackets in Local Part
    INVALID_EMAIL_7 = "username@example"  # Missing Top-Level Domain
    INVALID_EMAIL_8 = "username@192.168.1.1"  # IP Address as Domain
    INVALID_EMAIL_9 = "username.@example.com"  # Local Part Ending with Dot
    INVALID_EMAIL_10 = "user name@example.com"  # Spaces in Address
    INVALID_EMAIL_11 = "username"  # Single Word
    INVALID_EMAIL_12 = ""  # Empty String
    INVALID_EMAIL_13 = "username@12345"  # All Numbers in Domain

    INVALID_EMAIL_LIST = [INVALID_EMAIL_1, INVALID_EMAIL_2, INVALID_EMAIL_3, INVALID_EMAIL_4, INVALID_EMAIL_5,
                          INVALID_EMAIL_6, INVALID_EMAIL_7, INVALID_EMAIL_8, INVALID_EMAIL_9, INVALID_EMAIL_10,
                          INVALID_EMAIL_11, INVALID_EMAIL_12, INVALID_EMAIL_13]
