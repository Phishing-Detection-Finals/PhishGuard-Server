class Constants:

    MONGODB_URI_TEMPLATE = (
        "mongodb+srv://{username}:{password}@"
        "phishguard.gwxyfdr.mongodb.net/"
        "?retryWrites=true&w=majority&appName=PhishGuard"
    )

    SUCCESSFULLY_LOGIN_MESSAGE = "{user_email}, connected successfully"

    JWT_TOKEN_EXPIRED_MESSAGE = "Token expired."

    JWT_TOKEN_INVALID_MESSAGE = "Invalid Token."

    JWT_TOKEN_MISSING_MESSAGE = "Token Missing."

    MONGODB_DB_NAME = "PhishGuard"

    USERS_MONGODB_COLLECTION_NAME = "Users"

    AUTHENTICATION_ROUTE_PREFIX = "/auth"

    CREATED_STATUS_CODE = 201

    CONFLICT_STATUS_CODE = 409

    UNAUTHORIZED_STATUS_CODE = 401

    FORBIDDEN_STATUS_CODE = 403

    INTERNAL_ERROR = 500
