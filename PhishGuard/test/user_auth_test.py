import pytest
from PhishGuard.__init__ import app  # Import the Flask app
from PhishGuard.src.db.phishguard_db_connection import PhishGuardDBConnection
from user_test_utils import UserTestUtils
from test_constants import TestConstants


@pytest.fixture
def client():
    # Setup (run before tests)
    connection = PhishGuardDBConnection()
    connection.connect_to_test_db()
    with app.test_client() as client:
        yield client

    connection.disconnect_from_db()

def test_auth_sanity(client):
    response = UserTestUtils.create_test_user(client=client, test_user=TestConstants.TEST_USER_1)
    assert response
