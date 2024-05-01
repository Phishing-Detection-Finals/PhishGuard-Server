from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..constants import Constants
from ..services.user_service import UserService
# from ..exceptions.user_not_exists_exception import UserNotExistsException
# from flask_jwt_extended import JWTManager


class UserSettingController:
    def __init__(self):
        self.blueprint = Blueprint('user_setting', __name__, url_prefix=Constants.USER_SETTING_ROUTE_PREFIX)

        # Register routes
        self.register_routes()

    def register_routes(self):
        self.blueprint.route('/delete', methods=['DELETE'])(self.delete_user)
        self.blueprint.route('/update/username', methods=['PUT'])(self.update_username)

    @jwt_required()
    def delete_user(self):
        try:
            return jsonify(UserService().delete_user(user_email=get_jwt_identity())), Constants.OK_STATUS_CODE
        except Exception as e:
            return jsonify({"error": str(e)}), Constants.INTERNAL_ERROR

    @jwt_required()
    def update_username(self):
        try:
            payload_data = request.get_json()
            return jsonify(UserService().update_username(user_email=get_jwt_identity(), payload_data=payload_data)), Constants.OK_STATUS_CODE  # noqa501
        except Exception as e:
            return jsonify({"error": str(e)}), Constants.INTERNAL_ERROR

    def as_blueprint(self):
        return self.blueprint
