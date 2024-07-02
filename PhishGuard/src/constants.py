class Constants:

    MONGODB_URI_TEMPLATE = (
        "mongodb+srv://{username}:{password}@"
        "phishguard.gwxyfdr.mongodb.net/"
        "?retryWrites=true&w=majority&appName=PhishGuard"
    )

    MONGODB_UUID_REPRESENTATION = 'standard'

    SUCCESSFULLY_LOGIN_MESSAGE = "{user_email}, connected successfully"

    SUCCESSFULLY_DELETED_USER_MESSAGE = "user deleted successfully."

    SUCCESSFULLY_UPDATED_USERNAME_MESSAGE = "username updated successfully, new username - {username}"

    SUCCESSFULLY_UPDATED_EMAIL_MESSAGE = "email updated successfully, new email - {email}"

    SUCCESSFULLY_UPDATED_PASSWORD_MESSAGE = "password updated successfully"

    JWT_TOKEN_EXPIRED_MESSAGE = "Token expired."

    JWT_TOKEN_INVALID_MESSAGE = "Invalid Token."

    JWT_TOKEN_MISSING_MESSAGE = "Token Missing."

    MONGODB_DB_NAME = "PhishGuard"

    MONGODB_DB_TEST_NAME = "TEST-PhishGuard"

    USERS_MONGODB_COLLECTION_NAME = "Users"

    AUTHENTICATION_ROUTE_PREFIX = "/auth"

    USER_SETTING_ROUTE_PREFIX = "/setting/user"

    PHISH_GUARD_ROUTE_PREFIX = "/phish"

    SPECIAL_CHARACTERS = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', ',', '.', '?', '"', ':', '{', '}', '|', '<', '>']

    LOGIN_REQUIRED_FIELDS = ["email", "password"]
    SIGNUP_REQUIRED_FIELDS = ["email", "password", "username"]
    PHISH_CHECK_BY_URL_FIELDS = ["url"]

    USERNAME_MIN_CHARS = 6
    USERNAME_MAX_CHARS = 20

    MIN_MAX_CHARS_USERNAME_EXCEPTION_MESSAGE = (
        f"Username must be between {USERNAME_MIN_CHARS} and "
        f"{USERNAME_MAX_CHARS} characters long."
    )
