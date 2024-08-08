from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..constants import Constants
from ..services.user_service import UserService
from http import HTTPStatus
from ..exceptions.user_already_exists_exception import UserAlreadyExistsException
from ..exceptions.password_strength_exception import PasswordStrengthException
from ..exceptions.previous_user_data_exception import PreviousUserDataException
from ..exceptions.user_not_exists_exception import UserNotExistsException
from ..exceptions.username_not_valid_exception import UsernameNotValidException
from ..exceptions.missing_required_fields_exception import MissingRequiredFieldsException
from email_validator import EmailNotValidError
from ..validator import Validator
from ..utils.exceptions_handler import ExceptionsHandler
import logging


class UserSettingController:
    def __init__(self):
        self.blueprint = Blueprint('user_setting', __name__, url_prefix=Constants.USER_SETTING_ROUTE_PREFIX)
        logging.debug("Initialized UserSettingController with Blueprint")

        # Register routes
        self.register_routes()

    def register_routes(self):
        self.blueprint.route('', methods=['DELETE'])(self.delete_user)
        self.blueprint.route('/username', methods=['PUT'])(self.update_username)
        self.blueprint.route('/email', methods=['PUT'])(self.update_email)
        self.blueprint.route('/password', methods=['PUT'])(self.update_password)
        self.blueprint.route('', methods=['PATCH'])(self.update_user)
        self.blueprint.route('', methods=['GET'])(self.get_user_details)
        logging.debug("Routes registered: DELETE /, PUT /username, PUT /email, PUT /password, PATCH /, GET /")

    @jwt_required()
    @ExceptionsHandler.handle_exceptions({
        UserNotExistsException: HTTPStatus.NOT_FOUND
    })
    def delete_user(self):
        user_identity = get_jwt_identity()
        logging.debug(f"Received request to delete user: {user_identity}")
        user_delete_response = UserService().delete_user(identity=user_identity)
        logging.info(f"User {user_identity} successfully deleted")
        return jsonify(user_delete_response), HTTPStatus.OK

    @jwt_required()
    @ExceptionsHandler.handle_exceptions({
        UserNotExistsException: HTTPStatus.NOT_FOUND
    })
    def get_user_details(self):
        user_email = get_jwt_identity()
        logging.debug(f"Received request to get details for user: {user_email}")
        user_details = UserService().get_user_details_by_email(email=user_email)
        logging.info(f"Retrieved details for user: {user_details}")
        return jsonify(user_details), HTTPStatus.OK

    @jwt_required()
    @ExceptionsHandler.handle_exceptions({
        MissingRequiredFieldsException: HTTPStatus.BAD_REQUEST,
        PreviousUserDataException: HTTPStatus.BAD_REQUEST,
        PasswordStrengthException: HTTPStatus.BAD_REQUEST,
        UserNotExistsException: HTTPStatus.NOT_FOUND
    })
    def update_password(self):
        Validator.validate_required_fields(data=request.json, required_fields=["password"])
        user_identity = get_jwt_identity()
        logging.debug(f"Received request to update password for user: {user_identity}")
        payload_data = request.get_json()
        user_update_password_response = UserService().update_password(identity=user_identity,
                                                                      new_password=payload_data.get("password"))
        logging.info(f"Password for user {user_identity} successfully updated")
        return jsonify(user_update_password_response), HTTPStatus.OK

    @jwt_required()
    @ExceptionsHandler.handle_exceptions({
        MissingRequiredFieldsException: HTTPStatus.BAD_REQUEST,
        UserAlreadyExistsException: HTTPStatus.CONFLICT,
        EmailNotValidError: HTTPStatus.BAD_REQUEST,
        UserNotExistsException: HTTPStatus.NOT_FOUND,
        PreviousUserDataException: HTTPStatus.BAD_REQUEST
    })
    def update_email(self):
        Validator.validate_required_fields(data=request.json, required_fields=["email"])
        user_identity = get_jwt_identity()
        logging.debug(f"Received request to update email for user: {user_identity}")
        payload_data = request.get_json()
        user_update_email_response = UserService().update_email(identity=user_identity,
                                                                new_email=payload_data.get("email"))
        logging.info(f"Email for user {user_identity} successfully updated")
        return jsonify(user_update_email_response)

    @jwt_required()
    @ExceptionsHandler.handle_exceptions({
        MissingRequiredFieldsException: HTTPStatus.BAD_REQUEST,
        UserNotExistsException: HTTPStatus.NOT_FOUND,
        UsernameNotValidException: HTTPStatus.BAD_REQUEST,
        PreviousUserDataException: HTTPStatus.BAD_REQUEST
    })
    def update_username(self):
        Validator.validate_required_fields(data=request.json, required_fields=["username"])
        user_identity = get_jwt_identity()
        logging.debug(f"Received request to update username for user: {user_identity}")
        payload_data = request.get_json()
        user_update_username_response = UserService().update_username(identity=get_jwt_identity(),
                                                                      new_username=payload_data.get("username"))
        logging.info(f"Username for user {user_identity} successfully updated")
        return jsonify(user_update_username_response), HTTPStatus.OK

    @jwt_required()
    @ExceptionsHandler.handle_exceptions({
        MissingRequiredFieldsException: HTTPStatus.BAD_REQUEST,
        UserNotExistsException: HTTPStatus.NOT_FOUND,
        UsernameNotValidException: HTTPStatus.BAD_REQUEST,
        PreviousUserDataException: HTTPStatus.BAD_REQUEST,
        UserAlreadyExistsException: HTTPStatus.CONFLICT,
        EmailNotValidError: HTTPStatus.BAD_REQUEST,
        PasswordStrengthException: HTTPStatus.BAD_REQUEST,
    })
    def update_user(self):
        user_identity = get_jwt_identity()
        logging.debug(f"Received request to update settings for user: {user_identity}")
        payload_data = request.get_json()
        user_update_response = UserService().update_settings(identity=get_jwt_identity(),
                                                             updates=payload_data)
        logging.info(f"Settings for user {user_identity} successfully updated")
        return jsonify(user_update_response), HTTPStatus.OK

    def as_blueprint(self):
        return self.blueprint
