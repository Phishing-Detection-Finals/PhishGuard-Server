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
from ..exceptions.offensive_username_exception import OffensiveUsernameException
from email_validator import EmailNotValidError


class AuthenticationController:
    def __init__(self):
        self.blueprint = Blueprint('authentication', __name__, url_prefix=Constants.AUTHENTICATION_ROUTE_PREFIX)

        # self.questions_service = QuestionsService()

        # Register routes
        self.register_routes()

    def register_routes(self):
        self.blueprint.route('/login', methods=['POST'])(self.login)
        self.blueprint.route('/signup', methods=['POST'])(self.signup)
        self.blueprint.route('/refresh', methods=['GET'])(self.refresh_access_token)
        # self.blueprint.route('/all', methods=['GET'])(self.get_all_users)  # TODO delete later - for testing jwt auth tokens

    def login(self):
        try:
            return jsonify(UserService().login_user(user_json=request.json)), HTTPStatus.OK

        except WrongPasswordException as e:
            return jsonify({"error": str(e)}), HTTPStatus.UNAUTHORIZED

        except UserNotExistsException as e:
            return jsonify({"error": str(e)}), HTTPStatus.NOT_FOUND

        except EmailNotValidError as e:
            return jsonify({"error": str(e)}), HTTPStatus.BAD_REQUEST

        except Exception as e:
            return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR

    def signup(self):
        try:
            new_user_data = UserService().signup_user(user_json=request.json)
            return jsonify(new_user_data), HTTPStatus.CREATED

        except UserAlreadyExistsException as e:
            return jsonify({"error": str(e)}), HTTPStatus.CONFLICT

        except PasswordStrengthException as e:
            return jsonify({"error": str(e)}), HTTPStatus.BAD_REQUEST

        except UsernameNotValidException as e:
            return jsonify({"error": str(e)}), HTTPStatus.BAD_REQUEST

        except OffensiveUsernameException as e:
            return jsonify({"error": str(e)}), HTTPStatus.BAD_REQUEST

        except EmailNotValidError as e:
            return jsonify({"error": str(e)}), HTTPStatus.BAD_REQUEST

        except Exception as e:
            return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR

    # TODO delete - used for testing jwt token
    # @jwt_required()
    # def get_all_users(self):
    #     claims = get_jwt()
    #     return jsonify({"message": "nice",
    #                     "claims": claims}), 200

    @jwt_required(refresh=True)
    def refresh_access_token(self):
        identity = get_jwt_identity()

        return jsonify(UserService().refresh_user_access(identity)), HTTPStatus.OK

    def as_blueprint(self):
        return self.blueprint
