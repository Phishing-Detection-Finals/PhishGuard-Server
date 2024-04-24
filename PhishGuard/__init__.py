from flask import Flask
from .src.controllers.authentication_controller import AuthenticationController
# from .src.db.question_db_connection import QuestionDBConnection


app = Flask(__name__)

# questions_service = QuestionsService()
# return questions_service.get_questions(genre=genre, amount=amount, difficulty=difficulty)
# question_db_connector = QuestionDBConnection()

auth_controller = AuthenticationController()
app.register_blueprint(auth_controller.as_blueprint())


if __name__ == '__main__':
    # try:
    # question_db_connector.connect_to_db()   # Connect to MongoDB
    app.run(host='0.0.0.0')
    # finally:
    # question_db_connector.disconnect_from_db()  # Disconnect from MongoDB