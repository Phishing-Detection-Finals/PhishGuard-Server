from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..constants import Constants
from ..services.user_service import UserService
from http import HTTPStatus
# from ..exceptions.user_not_exists_exception import UserNotExistsException
# from flask_jwt_extended import JWTManager


# TODO - add test for what we have done until nowS
class UserSettingController:
    def __init__(self):
        self.blueprint = Blueprint('user_setting', __name__, url_prefix=Constants.USER_SETTING_ROUTE_PREFIX)

        # Register routes
        self.register_routes()

    def register_routes(self):
        self.blueprint.route('/user', methods=['DELETE'])(self.delete_user)
        self.blueprint.route('/username', methods=['PUT'])(self.update_username)
        self.blueprint.route('/user', methods=['GET'])(self.get_user_details)

    @jwt_required()
    def delete_user(self):
        try:
            return jsonify(UserService().delete_user(user_email=get_jwt_identity())), HTTPStatus.OK
        except Exception as e:
            return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR

    @jwt_required()
    def update_username(self):
        try:
            payload_data = request.get_json()
            return jsonify(UserService().update_username(user_email=get_jwt_identity(), payload_data=payload_data)), HTTPStatus.OK  # noqa501
        except Exception as e:
            return jsonify({"error": str(e)}), HTTPStatus.INTERNAL_SERVER_ERROR

    @jwt_required()
    def get_user_details(self):
        user_email = get_jwt_identity()
        user_dict = UserService().get_user_details_by_email(email=user_email)
        return jsonify(user_dict), HTTPStatus.OK

    def as_blueprint(self):
        return self.blueprint
