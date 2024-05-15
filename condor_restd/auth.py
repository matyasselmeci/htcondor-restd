from __future__ import absolute_import

import logging

import typing as t

Scalar = t.Union[None, bool, int, float, str]

import flask
from flask import request
from flask_restful import Resource
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth
from werkzeug.security import generate_password_hash, check_password_hash

# Schedd.user_login() is only in the v1 bindings
import htcondor as htcondor1

try:
    import classad2 as classad
    import htcondor2 as htcondor
except ImportError:
    import classad
    import htcondor


LOGIN_TIMEOUT = 30
MAX_USERNAME_LENGTH = 64
TESTUSER = "testuser"
C2BUSER = "c2buser"
MOCK_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsImtpZCI6IlBPT0wifQ.eyJleHAiOjE3MTU2NDQ2OTgs"
    "ImlhdCI6MTcxNTY0NDY5NywiaXNzIjoibWluaWNvbmRvciIsImp0aSI6IjViZjJ"
    "kNGE5NDIzNmQyYjRmZDFiMWFkMTEwZDdiZDM4Iiwic2NvcGUiOiJjb25kb3I6XC"
    "9SRUFEIGNvbmRvcjpcL1dSSVRFIiwic3ViIjoidGVzdHVzZXJAcmVzdGQifQ.v9"
    "cYO-8iuj0MmcyjwC_Zf0x8WMie9ZEX9rgjmGGIhhY"
)
AUTH_METHOD_TOKEN = "Token"
AUTH_METHOD_BASIC = "Basic"


basic_auth = HTTPBasicAuth()
basic_optional_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth("Bearer")
multi_auth = MultiAuth(token_auth, basic_auth)
multi_optional_auth = MultiAuth(token_auth, basic_optional_auth)

_log = logging.getLogger(__name__)


# TESTING: Test credentials
users = {
    TESTUSER: generate_password_hash("testpassword"),
}


@basic_auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username


@basic_optional_auth.verify_password
def verify_password_optional(username, password):
    if not username:
        return True
    if username in users and check_password_hash(users.get(username), password):
        return username


def get_auth_method(a_request: flask.Request) -> str:
    """
    Return the authentication method used in a request.
    """
    if "Authorization" in a_request.headers:
        auth_header = a_request.headers.get("Authorization")
        if auth_header.startswith("Bearer "):
            return AUTH_METHOD_TOKEN
        elif auth_header.startswith("Basic "):
            return AUTH_METHOD_BASIC
    return ""


def make_json_error(message: str, status_code: int) -> flask.Response:
    """
    Return a JSON error response -- this is a response with type application/json
    that just has a 'message' attribute with the error message.
    """
    response = flask.jsonify({"message": message})
    response.status_code = status_code
    return response


class AuthRequiredResource(Resource):
    """
    Base class for resources that require authentication.
    """

    auth = multi_auth
    method_decorators = [auth.login_required]


class AuthOptionalResource(Resource):
    """
    Base class for resources that where authenticating provides additional
    features but is not required.
    """

    auth = multi_optional_auth
    method_decorators = [auth.login_required]


class V1AuthRequiredTestResource(AuthRequiredResource):
    """
    Endpoint for testing authentication
    """

    def get(self):
        return {
            "message": "Authenticated as %s using %s"
            % (self.auth.current_user(), get_auth_method(request))
        }


class V1AuthOptionalTestResource(AuthOptionalResource):
    """
    Endpoint for testing optional authentication
    """

    def get(self):
        user = self.auth.current_user()
        if user:
            return {
                "message": "Authenticated as %s using %s"
                % (user, get_auth_method(request))
            }
        else:
            return {"message": "Not authenticated"}


def request_user_login(username: str) -> str:
    """
    Request a token from the schedd for the specified username.
    Return the token.
    """
    token = htcondor1.Schedd().user_login(username)
    return token


class V1UserLoginResource(AuthOptionalResource):
    """
    Endpoint for authenticating to an AP to request a Placement Token
    """

    def post(self):
        """
        Ask HTCondor for a token for the authenticated user.  Accepts JSON
        with a "claimtobe" field to claim to be the test user, and a "mock"
        boolean for just returning a fake token instead of calling out to
        HTCondor.
        """
        #
        # Parse the JSON request (if there is one)
        #
        claimtobe = None
        mock = False
        if request.content_type == "application/json":
            claimtobe = request.json.get("claimtobe")
            if claimtobe and not isinstance(claimtobe, str):
                return make_json_error("claimtobe must be a string", 400)
            mock = request.json.get("mock")
            if mock and not isinstance(mock, bool):
                return make_json_error("mock must be a boolean", 400)

        #
        # Get the user to auth as, run some checks
        #
        if claimtobe:
            if claimtobe != C2BUSER:
                return make_json_error("you can only claim to be %s" % C2BUSER, 401)
            auth_user = claimtobe
        else:
            auth_user = self.auth.current_user()
        if not auth_user:
            return make_json_error("Not authenticated", 401)
        if len(auth_user) > MAX_USERNAME_LENGTH:
            return make_json_error("username too long", 400)

        #
        # Return the mock token if that's what we were asked for
        #
        if mock:
            _log.info("Returning mock token")
            return flask.jsonify(token=MOCK_TOKEN)

        #
        # Otherwise, get a token from the schedd.
        #
        try:
            token = request_user_login(auth_user)
            return flask.jsonify(token=token)
        except htcondor1.HTCondorIOError as err:
            _log.exception("Error getting token: %s", err)
            if "errmsg=SCHEDD:3" in str(err):
                return make_json_error("No accounts available, try again later", 503)
            elif "errmsg=SECMAN:" in str(err):
                return make_json_error("RESTD cannot authenticate to schedd: %s" % err, 503)
            return make_json_error("Error getting token: %s" % err, 500)
        except Exception as err:
            _log.exception("Unexpected error getting token: %s", err)
            return make_json_error("Unexpected error getting token", 500)
