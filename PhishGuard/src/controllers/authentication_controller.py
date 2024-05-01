from flask import Blueprint, jsonify, request
from ..constants import Constants
from ..services.user_service import UserService
from ..exceptions.user_already_exists_exception import UserAlreadyExistsException
from ..exceptions.wrong_password_or_email_exception import WrongPasswordsOrEmail
# from ..exceptions.user_not_exists_exception import UserNotExistsException
# from flask_jwt_extended import JWTManager
# TODO continue handling jwt video number 4 - 9:00


class AuthenticationController:
    def __init__(self):
        self.blueprint = Blueprint('authentication', __name__, url_prefix=Constants.AUTHENTICATION_ROUTE_PREFIX)
        # self.jwt = JWTManager()

        # self.questions_service = QuestionsService()

        # Register routes
        self.register_routes()

    def register_routes(self):
        self.blueprint.route('/login', methods=['POST'])(self.login)
        self.blueprint.route('/signup', methods=['POST'])(self.signup)

    def login(self):
        try:
            return jsonify(UserService().login_user(user_json=request.json)), 200
        except WrongPasswordsOrEmail as e:
            return jsonify({"error": str(e)}), Constants.UNAUTHORIZED_STATUS_CODE
        except Exception as e:
            return jsonify({"error": str(e)}), Constants.INTERNAL_ERROR

    def signup(self):
        try:
            new_user_data = UserService().signup_user(user_json=request.json)
            return jsonify(new_user_data), Constants.CREATED_STATUS_CODE

        except UserAlreadyExistsException as e:
            return jsonify({"error": str(e)}), Constants.CONFLICT_STATUS_CODE

        except Exception as e:
            return jsonify({"error": str(e)}), Constants.INTERNAL_ERROR

    def as_blueprint(self):
        return self.blueprint
