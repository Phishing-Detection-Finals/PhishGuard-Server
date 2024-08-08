from mongoengine import EmailField, StringField, ObjectIdField, Document
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from ..constants import Constants
import logging


class User(Document):
    _id = ObjectIdField(primary_key=True, default=lambda: str(ObjectId()))
    username = StringField(required=True)
    email = EmailField(required=True, unique=True)
    password_hash = StringField(required=True)
    meta = {'collection': Constants.USERS_MONGODB_COLLECTION_NAME}

    def set_hash_password(self, password: str) -> None:
        logging.debug(f"Setting hash password for user with email: {self.email}")
        self.password_hash = User.get_password_hash(password=password)
        logging.info(f"Password hash set for user with email: {self.email}")

    @staticmethod
    def get_password_hash(password: str) -> str:
        logging.debug("Generating password hash.")
        password_hash = generate_password_hash(password)
        logging.info("Password hash generated successfully.")
        return password_hash

    def check_password_hash(self, password: str) -> bool:
        logging.debug(f"Checking password hash for user with email: {self.email}")
        is_valid = check_password_hash(pwhash=self.password_hash, password=password)
        if is_valid:
            logging.info(f"Password hash check successful for user with email: {self.email}")
        else:
            logging.warning(f"Password hash check failed for user with email: {self.email}")
        return is_valid

    def to_dict(self) -> dict:
        user_dict = {
            "_id": str(self._id),
            "username": self.username,
            "email": self.email,
            # we don't include the password hash in the dictionary for security reasons
        }
        logging.debug(f"User data converted to dictionary for user with email: {self.email}")
        return user_dict
