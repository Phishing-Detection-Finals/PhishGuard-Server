class Constants:

    MONGODB_URI_TEMPLATE = (
        "mongodb+srv://{username}:{password}@"
        "phishguard.gwxyfdr.mongodb.net/"
        "?retryWrites=true&w=majority&appName=PhishGuard"
    )

    SUCCESSFULLY_LOGIN_MESSAGE = "{user_email}, connected successfully"

    SUCCESSFULLY_DELETED_USER_MESSAGE = "user deleted successfully."

    SUCCESSFULLY_UPDATED_USERNAME_MESSAGE = "username updated successfully, new username - {username}"

    JWT_TOKEN_EXPIRED_MESSAGE = "Token expired."

    JWT_TOKEN_INVALID_MESSAGE = "Invalid Token."

    JWT_TOKEN_MISSING_MESSAGE = "Token Missing."

    MONGODB_DB_NAME = "PhishGuard"

    USERS_MONGODB_COLLECTION_NAME = "Users"

    AUTHENTICATION_ROUTE_PREFIX = "/auth"

    USER_SETTING_ROUTE_PREFIX = "/setting"
