from __future__ import absolute_import

import logging
import subprocess

import typing as t

Scalar = t.Union[None, bool, int, float, str]

import flask
from flask import request
from flask_restful import Resource
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth
from werkzeug.security import generate_password_hash, check_password_hash

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
MOCK_TOKEN = ("eyJhbGciOiJIUzI1NiIsImtpZCI6IlBPT0wifQ.eyJleHAiOjE3MTU2NDQ2OTgs"
              "ImlhdCI6MTcxNTY0NDY5NywiaXNzIjoibWluaWNvbmRvciIsImp0aSI6IjViZjJ"
              "kNGE5NDIzNmQyYjRmZDFiMWFkMTEwZDdiZDM4Iiwic2NvcGUiOiJjb25kb3I6XC"
              "9SRUFEIGNvbmRvcjpcL1dSSVRFIiwic3ViIjoidGVzdHVzZXJAcmVzdGQifQ.v9"
              "cYO-8iuj0MmcyjwC_Zf0x8WMie9ZEX9rgjmGGIhhY")


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
            return "Bearer"
        elif auth_header.startswith("Basic "):
            return "Basic"
    return ""


def make_error(message: str, status_code: int) -> flask.Response:
    """
    Return an error response.
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
        return {"message": "Authenticated as %s" % self.auth.current_user()}


class V1AuthOptionalTestResource(AuthOptionalResource):
    """
    Endpoint for testing optional authentication
    """

    def get(self):
        user = self.auth.current_user()
        if user:
            return {"message": "Authenticated as %s" % user}
        else:
            return {"message": "Not authenticated"}


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
        # Parse the JSON request (if there is one)
        claimtobe = None
        mock = False
        if request.content_type == "application/json":
            claimtobe = request.json.get("claimtobe")
            if not isinstance(claimtobe, str):
                return make_error("claimtobe must be a string", 400)
            mock = request.json.get("mock")
            if not isinstance(mock, bool):
                return make_error("mock must be a boolean", 400)

        auth_user = self.auth.current_user()

        # Build the command to run to call out to HTCondor; run this even if we're mocking
        # to test authentication.
        cmd = ["condor_user_login"]
        if claimtobe:
            if claimtobe != C2BUSER:
                return make_error("you can only claim to be %s" % C2BUSER, 401)
            cmd += [claimtobe]
        elif auth_user:
            if len(auth_user) > MAX_USERNAME_LENGTH:
                return make_error("username too long", 400)
            cmd += [auth_user]
        else:
            return make_error("Not authenticated", 401)

        if mock:
            return flask.jsonify(token=MOCK_TOKEN)

        try:
            ret = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=LOGIN_TIMEOUT,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as err:
            _log.exception("OSError running condor_user_login: %s", err)
            return make_error("Login failed", 500)
        except subprocess.TimeoutExpired:
            # 504 gateway timeout seems appropriate since the RESTD is a gateway between HTTP and HTCondor
            return make_error("Requesting login timed out", 504)

        if ret.returncode != 0 or not ret.stdout:
            return make_error("Login failed: %s" % ret.stderr, 401)
        else:
            return flask.jsonify(token=ret.stdout)
