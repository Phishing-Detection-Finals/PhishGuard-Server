class Constants:

    MONGODB_URI_TEMPLATE = (
        "mongodb+srv://{username}:{password}@"
        "phishguard.gwxyfdr.mongodb.net/"
        "?retryWrites=true&w=majority&appName=PhishGuard"
    )

    MONGODB_DB_NAME = "PhishGuard"

    AUTHENTICATION_ROUTE_PREFIX = "/auth"

    CREATED_STATUS_CODE = 201

    CONFLICT_STATUS_CODE = 409

    INTERNAL_ERROR = 500
