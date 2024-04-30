from flask import Flask
from .src.controllers.authentication_controller import AuthenticationController
from dotenv import load_dotenv
import os
load_dotenv()
from .src.db.phishguard_db_connection import PhishGuardDBConnection  # noqa 402


def create_app():
    app = Flask(__name__)

    connect_blueprints(app=app)
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    return app


def connect_blueprints(app: Flask):
    app.register_blueprint(AuthenticationController().as_blueprint())


def connect_to_db() -> PhishGuardDBConnection:
    phishguard_db_connector = PhishGuardDBConnection()
    phishguard_db_connector.connect_to_db()
    return phishguard_db_connector


if __name__ == '__main__':
    try:
        phishguard_db_connector = connect_to_db()
        app = create_app()
        app.run(debug=True)
        # app.run(host='0.0.0.0')
    finally:
        phishguard_db_connector.disconnect_from_db()
