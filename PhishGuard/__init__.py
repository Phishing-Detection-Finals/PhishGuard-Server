from flask import Flask
from .src.controllers.authentication_controller import AuthenticationController
from dotenv import load_dotenv
import os
from flask_jwt_extended import JWTManager
from .src.utils.jwt_utils import JWTUtils
load_dotenv()
from .src.db.phishguard_db_connection import PhishGuardDBConnection  # noqa 402


jwt = JWTManager()


def create_app():
    app = Flask(__name__)

    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    jwt.init_app(app)

    # Register before_request and teardown_request handlers
    register_request_handlers(app)

    connect_blueprints(app=app)

    # register jwt errors handler
    JWTUtils.register_jwt_error_handlers(jwt=jwt)

    return app


def register_request_handlers(app: Flask):
    # Initialize database connection
    phishguard_db_connector = PhishGuardDBConnection()

    @app.before_request
    def before_request():
        phishguard_db_connector.connect_to_db()

    @app.teardown_request
    def teardown_request(exception=None):
        phishguard_db_connector.disconnect_from_db()


def connect_blueprints(app: Flask):
    app.register_blueprint(AuthenticationController().as_blueprint())


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
    # app.run(host='0.0.0.0')
