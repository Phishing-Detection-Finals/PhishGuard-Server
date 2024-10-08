from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..constants import Constants
from http import HTTPStatus
from ..services.user_service import UserService
from ..exceptions.user_already_exists_exception import UserAlreadyExistsException
from ..exceptions.wrong_password_exception import WrongPasswordException
from ..exceptions.user_not_exists_exception import UserNotExistsException
from ..exceptions.password_strength_exception import PasswordStrengthException
from ..exceptions.username_not_valid_exception import UsernameNotValidException
from ..exceptions.missing_required_fields_exception import MissingRequiredFieldsException
from ..validator import Validator
from email_validator import EmailNotValidError
from ..utils.exceptions_handler import ExceptionsHandler
import logging


class AuthenticationController:
    def __init__(self):
        self.blueprint = Blueprint('authentication', __name__, url_prefix=Constants.AUTHENTICATION_ROUTE_PREFIX)
        logging.debug("Initialized AuthenticationController with Blueprint")

        # self.questions_service = QuestionsService()

        # Register routes
        self.register_routes()

    def register_routes(self):
        self.blueprint.route('/login', methods=['POST'])(self.login)
        self.blueprint.route('/signup', methods=['POST'])(self.signup)
        self.blueprint.route('/refresh', methods=['GET'])(self.refresh_access_token)
        logging.debug("Routes registered: /login, /signup, /refresh")

    @ExceptionsHandler.handle_exceptions({
        MissingRequiredFieldsException: HTTPStatus.BAD_REQUEST,
        WrongPasswordException: HTTPStatus.UNAUTHORIZED,
        UserNotExistsException: HTTPStatus.NOT_FOUND,
        EmailNotValidError: HTTPStatus.BAD_REQUEST
    })
    def login(self):
        logging.debug("Login request received")
        Validator.validate_required_fields(data=request.json, required_fields=Constants.LOGIN_REQUIRED_FIELDS)
        login_result = UserService().login_user(user_json=request.json)
        logging.info("Login successful for user")
        return jsonify(login_result), HTTPStatus.OK

    @ExceptionsHandler.handle_exceptions({
        MissingRequiredFieldsException: HTTPStatus.BAD_REQUEST,
        UserAlreadyExistsException: HTTPStatus.CONFLICT,
        PasswordStrengthException: HTTPStatus.BAD_REQUEST,
        UsernameNotValidException: HTTPStatus.BAD_REQUEST,
        EmailNotValidError: HTTPStatus.BAD_REQUEST
    })
    def signup(self):
        logging.debug("Signup request received")
        Validator.validate_required_fields(data=request.json, required_fields=Constants.SIGNUP_REQUIRED_FIELDS)
        signup_response = UserService().signup_user(user_json=request.json)
        logging.info("Signup successful for user")
        return jsonify(signup_response), HTTPStatus.CREATED

    @jwt_required(refresh=True)
    def refresh_access_token(self):
        identity = get_jwt_identity()
        logging.debug(f"Refresh access token request received for identity: {identity}")
        refresh_token_response = UserService().refresh_user_access(identity)
        logging.info("Access token refreshed successfully")
        return jsonify(refresh_token_response), HTTPStatus.OK

    def as_blueprint(self):
        return self.blueprint
