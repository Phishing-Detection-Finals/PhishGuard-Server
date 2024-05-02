from dotenv import load_dotenv
import os
from mongoengine import connect, disconnect
from ..constants import Constants

load_dotenv()


class PhishGuardDBConnection:
    def __init__(self):

        mongodb_username = os.getenv('MONGODB_USERNAME')
        mongodb_password = os.getenv('MONGODB_PASSWORD')

        self.mongodb_uri = Constants.MONGODB_URI_TEMPLATE.format(username=mongodb_username, password=mongodb_password)

    def connect_to_db(self):
        connect(host=self.mongodb_uri, db=Constants.MONGODB_DB_NAME)

    def connect_to_test_db(self):
        connect(host=self.mongodb_uri, db=Constants.MONGODB_DB_TEST_NAME)

    def disconnect_from_db(self):
        disconnect()
