from flask import Flask
from .src.controllers.authentication_controller import AuthenticationController
from .src.controllers.user_setting_controller import UserSettingController
from dotenv import load_dotenv
import os
from flask_jwt_extended import JWTManager
from .src.utils.jwt_utils import JWTUtils
load_dotenv()
from .src.db.phishguard_db_connection import PhishGuardDBConnection  # noqa 402


jwt = JWTManager()


def create_app(is_test: bool = False):
    app = Flask(__name__)

    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    jwt.init_app(app)

    if (is_test):
        register_test_request_handlers(app=app)
    else:
        # Register before_request and teardown_request handlers
        register_request_handlers(app)

    connect_blueprints(app=app)

    # register jwt errors handler
    JWTUtils.register_jwt_error_handlers(jwt=jwt)

    return app


def create_test_app():
    return create_app(is_test=True)


def register_request_handlers(app: Flask):
    # Initialize database connection
    phishguard_db_connector = PhishGuardDBConnection()

    @app.before_request
    def before_request():
        phishguard_db_connector.connect_to_db()

    @app.teardown_request
    def teardown_request(exception=None):
        phishguard_db_connector.disconnect_from_db()


def register_test_request_handlers(app: Flask):
    # Initialize database connection
    phishguard_db_connector = PhishGuardDBConnection()

    @app.before_request
    def before_request():
        phishguard_db_connector.connect_to_test_db()

    @app.teardown_request
    def teardown_request(exception=None):
        phishguard_db_connector.disconnect_from_db()


def connect_blueprints(app: Flask):
    app.register_blueprint(AuthenticationController().as_blueprint())
    app.register_blueprint(UserSettingController().as_blueprint())


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
    app.run(host='0.0.0.0')
