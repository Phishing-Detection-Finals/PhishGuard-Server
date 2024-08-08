from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required
from PhishGuard.src.services.phish_service import PhishService
from ..constants import Constants
from http import HTTPStatus
from ..exceptions.user_not_exists_exception import UserNotExistsException
from ..exceptions.missing_required_fields_exception import MissingRequiredFieldsException
from ..exceptions.webpage_inaccessible_exception import WebpageInaccessibleException
from ..exceptions.url_not_valid_exception import UrlNotValidException
from ..utils.exceptions_handler import ExceptionsHandler
from ..validator import Validator
import logging


class PhishGuardController:
    def __init__(self):
        self.blueprint = Blueprint('phish_guard', __name__, url_prefix=Constants.PHISH_GUARD_ROUTE_PREFIX)
        logging.debug("Initialized PhishGuardController with Blueprint")

        # Register routes
        self.register_routes()

    def register_routes(self):
        self.blueprint.route('/by-url', methods=['GET'])(self.check_url_for_phishing)
        logging.debug("Route registered: /by-url")

    @jwt_required()
    @ExceptionsHandler.handle_exceptions({
        MissingRequiredFieldsException: HTTPStatus.BAD_REQUEST,
        UrlNotValidException: HTTPStatus.BAD_REQUEST,
        UserNotExistsException: HTTPStatus.NOT_FOUND,
        WebpageInaccessibleException: HTTPStatus.BAD_REQUEST
    })
    def check_url_for_phishing(self):
        logging.debug("Phishing check request received")
        Validator.validate_required_fields(data=request.args, required_fields=Constants.PHISH_CHECK_BY_URL_FIELDS)
        url = request.args.get("url")
        logging.debug(f"Checking URL for phishing: {url}")
        phishing_result = PhishService().check_phish_by_url(url=url)
        logging.info("Phishing check completed successfully")
        return jsonify(phishing_result), HTTPStatus.OK

    def as_blueprint(self):
        return self.blueprint
