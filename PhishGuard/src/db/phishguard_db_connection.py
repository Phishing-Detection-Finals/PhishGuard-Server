from dotenv import load_dotenv
import os
from mongoengine import connect, disconnect
from ..constants import Constants
import logging

load_dotenv()


class PhishGuardDBConnection:
    def __init__(self):
        logging.debug("Initializing PhishGuardDBConnection")
        mongodb_username = os.getenv('MONGODB_USERNAME')
        mongodb_password = os.getenv('MONGODB_PASSWORD')

        if not mongodb_username or not mongodb_password:
            logging.error("MongoDB username or password is not set in environment variables.")
            raise ValueError("MongoDB credentials must be provided.")

        self.mongodb_uri = Constants.MONGODB_URI_TEMPLATE.format(username=mongodb_username, password=mongodb_password)
        # logging.debug(f"MongoDB URI: {self.mongodb_uri}")  // Delete? shows env values of username and password.

    def connect_to_db(self):
        logging.debug("Connecting to MongoDB")
        connect(host=self.mongodb_uri, db=Constants.MONGODB_DB_NAME,
                uuidRepresentation=Constants.MONGODB_UUID_REPRESENTATION)
        logging.info("Successfully connected to the database.")

    def connect_to_test_db(self):
        logging.debug("Connecting to MongoDB test database")
        connect(host=self.mongodb_uri, db=Constants.MONGODB_DB_TEST_NAME,
                uuidRepresentation=Constants.MONGODB_UUID_REPRESENTATION)
        logging.info("Successfully connected to the test database.")

    def disconnect_from_db(self):
        logging.debug("Disconnecting from MongoDB")
        disconnect()
        logging.info("Successfully disconnected from the database.")
