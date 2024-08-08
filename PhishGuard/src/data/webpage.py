from mongoengine import StringField, ObjectIdField, Document
from ..constants import Constants
from bson import ObjectId


class Webpage(Document):
    _id = ObjectIdField(primary_key=True, default=lambda: str(ObjectId()))
    url = StringField(required=True)
    # dom_minhash = StringField(required=True)
    title_hash = StringField(required=True)
    header_hash = StringField(required=True)
    footer_hash = StringField(required=True)
    body_hash = StringField(required=True)
    # cert_hash = StringField(required=True)
    meta = {'collection': Constants.WEBPAGE_MONGODB_COLLECTION_NAME}
