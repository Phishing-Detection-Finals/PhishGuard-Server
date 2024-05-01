from mongoengine import EmailField, StringField, ObjectIdField, Document
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from ..constants import Constants


class User(Document):
    _id = ObjectIdField(primary_key=True, default=lambda: str(ObjectId()))
    username = StringField(required=True)
    email = EmailField(required=True, unique=True)
    password_hash = StringField(required=True)
    meta = {'collection': Constants.USERS_MONGODB_COLLECTION_NAME}

    def set_hash_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password_hash(self, password: str):
        return check_password_hash(pwhash=self.password_hash, password=password)

    def to_dict(self) -> dict:
        user_dict = {
            "_id": str(self._id),
            "username": self.username,
            "email": self.email,
            # we don't include the password hash in the dictionary for security reasons
        }
        return user_dict
