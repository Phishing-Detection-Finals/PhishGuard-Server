from flask import Blueprint, jsonify


class AuthenticationController:
    def __init__(self):
        self.blueprint = Blueprint('authentication', __name__)

        # self.questions_service = QuestionsService()

        # Register routes
        self.register_routes()

    def register_routes(self):
        self.blueprint.route('/login', methods=['GET'])(self.login)
        self.blueprint.route('/signup', methods=['GET'])(self.signup)

    def login(self):

        return jsonify({"login": "helloworld"}), 200

    def signup(self):

        return jsonify({"signup": "helloWorld"}), 200

    def as_blueprint(self):
        return self.blueprint
