from flask_jwt_extended import JWTManager
from flask import jsonify
from ..constants import Constants
from http import HTTPStatus
import logging


class JWTUtils:

    @staticmethod
    def register_jwt_error_handlers(jwt: JWTManager):
        # jwt error handlers
        @jwt.expired_token_loader
        def expired_token_callback(jwt_header, jwt_data):
            logging.warning("JWT token has expired.")
            expired_response = {"message": Constants.JWT_TOKEN_EXPIRED_MESSAGE}

            return jsonify(expired_response), HTTPStatus.UNAUTHORIZED

        @jwt.invalid_token_loader
        def invalid_token_callback(error):
            logging.error(f"Invalid JWT token: {error}")
            invalid_response = {"message": Constants.JWT_TOKEN_INVALID_MESSAGE}
            return jsonify(invalid_response), HTTPStatus.FORBIDDEN

        @jwt.unauthorized_loader
        def missing_token_callback(error):
            logging.error(f"Unauthorized request: {error}")
            missing_response = {"message": Constants.JWT_TOKEN_MISSING_MESSAGE}
            return jsonify(missing_response), HTTPStatus.UNAUTHORIZED

    # example of adding data to user's jwt
    # @staticmethod
    # def additional_claims(jwt: JWTManager):

    #     @jwt.additional_claims_loader
    #     def make_additional_claims(identity):
    #         if identity == "gilazani1@gmail.com":
    #             return {"is_admin": True}
