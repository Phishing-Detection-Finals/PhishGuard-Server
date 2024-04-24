from flask import Blueprint, jsonify


class AuthenticationController:
    def __init__(self):
        self.blueprint = Blueprint('authentication', __name__)

        # self.questions_service = QuestionsService()

        # Register routes
        self.register_routes()

    def register_routes(self):
        self.blueprint.route('/helloworld', methods=['GET'])(self.get_questions)

    def get_questions(self):

        return jsonify({"hello": "helloworld"}), 200  # noqa501

    def as_blueprint(self):
        return self.blueprint
