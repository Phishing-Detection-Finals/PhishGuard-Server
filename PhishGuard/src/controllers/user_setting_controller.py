from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..constants import Constants
from ..services.user_service import UserService
from http import HTTPStatus
from ..exceptions.user_already_exists_exception import UserAlreadyExistsException
from ..exceptions.password_strength_exception import PasswordStrengthException
from ..exceptions.previous_user_data_exception import PreviousUserDataException
from ..exceptions.user_not_exists_exception import UserNotExistsException
# from ..exceptions.offensive_username_exception import OffensiveUsernameException  # TODO decide later if we will use it
from ..exceptions.username_not_valid_exception import UsernameNotValidException
from ..exceptions.missing_required_fields_exception import MissingRequiredFieldsException
from email_validator import EmailNotValidError
from ..validator import Validator


class UserSettingController:
    def __init__(self):
        self.blueprint = Blueprint('user_setting', __name__, url_prefix=Constants.USER_SETTING_ROUTE_PREFIX)

        # Register routes
        self.register_routes()

    def register_routes(self):
        self.blueprint.route('', methods=['DELETE'])(self.delete_user)
        self.blueprint.route('/username', methods=['PUT'])(self.update_username)
        self.blueprint.route('/email', methods=['PUT'])(self.update_email)
        self.blueprint.route('/password', methods=['PUT'])(self.update_password)
        self.blueprint.route('', methods=['GET'])(self.get_user_details)

    @jwt_required()
    def delete_user(self):
        try:
            return jsonify(UserService().delete_user(identity=get_jwt_identity())), HTTPStatus.OK

        except UserNotExistsException as e:
            return jsonify({"error": str(e)}), HTTPStatus.NOT_FOUND

        except Exception as e:
            return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR

    @jwt_required()
    def get_user_details(self):
        try:
            user_email = get_jwt_identity()
            user_dict = UserService().get_user_details_by_email(email=user_email)
            return jsonify(user_dict), HTTPStatus.OK

        except UserNotExistsException as e:
            return jsonify({"error": str(e)}), HTTPStatus.NOT_FOUND

        except Exception as e:
            return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR

    @jwt_required()
    def update_password(self):
        try:
            Validator.validate_required_fields(data=request.json, required_fields=["password"])
            payload_data = request.get_json()
            return jsonify(UserService.update_password(identity=get_jwt_identity(),
                                                       new_password=payload_data.get("password"))), HTTPStatus.OK

        except MissingRequiredFieldsException as e:
            return jsonify({"error": str(e)}), HTTPStatus.BAD_REQUEST

        except PreviousUserDataException as e:
            return jsonify({"error": str(e)}), HTTPStatus.BAD_REQUEST

        except PasswordStrengthException as e:
            return jsonify({"error": str(e)}), HTTPStatus.BAD_REQUEST

        except UserNotExistsException as e:
            return jsonify({"error": str(e)}), HTTPStatus.NOT_FOUND

        except Exception as e:
            return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR

    @jwt_required()
    def update_email(self):
        try:
            Validator.validate_required_fields(data=request.json, required_fields=["email"])
            payload_data = request.get_json()
            return jsonify(UserService.update_email(identity=get_jwt_identity(),
                                                    new_email=payload_data.get("email")))

        except MissingRequiredFieldsException as e:
            return jsonify({"error": str(e)}), HTTPStatus.BAD_REQUEST

        except UserAlreadyExistsException as e:
            return jsonify({"error": str(e)}), HTTPStatus.CONFLICT

        except EmailNotValidError as e:
            return jsonify({"error": str(e)}), HTTPStatus.BAD_REQUEST

        except UserNotExistsException as e:
            return jsonify({"error": str(e)}), HTTPStatus.NOT_FOUND

        except PreviousUserDataException as e:
            return jsonify({"error": str(e)}), HTTPStatus.BAD_REQUEST

        except Exception as e:
            return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR

    @jwt_required()
    def update_username(self):
        try:
            Validator.validate_required_fields(data=request.json, required_fields=["username"])
            payload_data = request.get_json()
            return jsonify(UserService().update_username(identity=get_jwt_identity(),
                                                         new_username=payload_data.get("username"))), HTTPStatus.OK

        except MissingRequiredFieldsException as e:
            return jsonify({"error": str(e)}), HTTPStatus.BAD_REQUEST

        except UserNotExistsException as e:
            return jsonify({"error": str(e)}), HTTPStatus.NOT_FOUND

        except UsernameNotValidException as e:
            return jsonify({"error": str(e)}), HTTPStatus.BAD_REQUEST

        # TODO - make a decision, might be deleted
        # except OffensiveUsernameException as e:
        #     return jsonify({"error": str(e)}), HTTPStatus.BAD_REQUEST

        except PreviousUserDataException as e:
            return jsonify({"error": str(e)}), HTTPStatus.BAD_REQUEST

        except Exception as e:
            return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR

    def as_blueprint(self):
        return self.blueprint
