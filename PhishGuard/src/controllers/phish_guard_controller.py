from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from PhishGuard.src.services.phish_service import PhishService
from ..constants import Constants
from http import HTTPStatus
from ..exceptions.user_not_exists_exception import UserNotExistsException
from ..exceptions.missing_required_fields_exception import MissingRequiredFieldsException
from ..exceptions.url_not_valid_exception import UrlNotValidException
from ..utils.exceptions_handler import ExceptionsHandler
from ..validator import Validator


class PhishGuardController:
    def __init__(self):
        self.blueprint = Blueprint('phish_guard', __name__, url_prefix=Constants.PHISH_GUARD_ROUTE_PREFIX)

        # Register routes
        self.register_routes()

    def register_routes(self):
        self.blueprint.route('/by-url', methods=['GET'])(self.check_url_for_phishing)

    @jwt_required()
    @ExceptionsHandler.handle_exceptions({
        MissingRequiredFieldsException: HTTPStatus.BAD_REQUEST,
        UrlNotValidException: HTTPStatus.BAD_REQUEST,
        UserNotExistsException: HTTPStatus.NOT_FOUND
    })
    def check_url_for_phishing(self):
        Validator.validate_required_fields(data=request.json, required_fields=Constants.PHISH_CHECK_BY_URL_FIELDS)
        return jsonify(PhishService().check_phish_by_url(url=request.json.get("url"))), HTTPStatus.OK

    def as_blueprint(self):
        return self.blueprint
