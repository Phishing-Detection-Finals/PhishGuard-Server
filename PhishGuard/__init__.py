from flask import Flask

from PhishGuard.src.controllers.phish_guard_controller import PhishGuardController
from PhishGuard.src.controllers.authentication_controller import AuthenticationController
from PhishGuard.src.controllers.user_setting_controller import UserSettingController
from dotenv import load_dotenv
import os
from flask_jwt_extended import JWTManager
from PhishGuard.src.utils.jwt_utils import JWTUtils
import logging
from .src.utils.logging_utils import setup_logging

load_dotenv()
from PhishGuard.src.db.phishguard_db_connection import PhishGuardDBConnection  # noqa 402

jwt = JWTManager()


def create_app(is_test: bool = False):
    # Set up logging
    setup_logging()

    app = Flask(__name__)

    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    jwt.init_app(app)
    logging.info("JWT Manager initialized with secret key.")

    if is_test:
        register_test_request_handlers(app=app)
        logging.info("Test request handlers registered.")
    else:
        # Register before_request and teardown_request handlers
        register_request_handlers(app)
        logging.info("Request handlers registered.")

    connect_blueprints(app=app)
    logging.info("Blueprints registered.")

    # register jwt errors handler
    JWTUtils.register_jwt_error_handlers(jwt=jwt)
    logging.info("JWT error handlers registered.")

    return app


def create_test_app():
    return create_app(is_test=True)


def register_request_handlers(app: Flask):
    # Initialize database connection
    phishguard_db_connector = PhishGuardDBConnection()
    logging.debug("Database connection handler initialized.")

    @app.before_request
    def before_request():
        phishguard_db_connector.connect_to_db()
        logging.info("Connected to the main database.")

    @app.teardown_request
    def teardown_request():
        phishguard_db_connector.disconnect_from_db()
        logging.info("Disconnected from the main database.")


def register_test_request_handlers(app: Flask):
    # Initialize database connection
    phishguard_db_connector = PhishGuardDBConnection()
    logging.debug("Database connection handler initialized for test.")

    @app.before_request
    def before_request():
        phishguard_db_connector.connect_to_test_db()
        logging.info("Connected to the test database.")

    @app.teardown_request
    def teardown_request():
        phishguard_db_connector.disconnect_from_db()
        logging.info("Disconnected from the test database.")


def connect_blueprints(app: Flask):
    app.register_blueprint(AuthenticationController().as_blueprint())
    app.register_blueprint(UserSettingController().as_blueprint())
    app.register_blueprint(PhishGuardController().as_blueprint())
    logging.info("Blueprints registered: Authentication, User Setting, Phish Guard.")


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
    app.run(host='0.0.0.0')
    logging.info("Flask application started.")
