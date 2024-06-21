from __future__ import absolute_import

import logging
import re
import subprocess as sp
import typing as t

Scalar = t.Union[None, bool, int, float, str]

import flask
from flask import request
from flask_restful import Resource
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth
from werkzeug.security import generate_password_hash, check_password_hash
import jwt

# Schedd.user_login() is only in the v1 bindings
import htcondor as htcondor1

try:
    import classad2 as classad
    import htcondor2 as htcondor
except ImportError:
    import classad
    import htcondor


if not hasattr(jwt, "decode"):
    raise ImportError("Wrong JWT library -- we need 'PyJWT' not 'jwt'")


LOGIN_TIMEOUT = 30
MAX_USERNAME_LENGTH = 64
TESTUSER = "testuser"
AUTH_METHOD_TOKEN = "Token"
AUTH_METHOD_BASIC = "Basic"

PLACEMENTD_USE_BINDINGS = False

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

mock_user_list = [
    {
        "username": "testuser",
        "localAccount": "local01",
        "accountCreated": 1719205200,  # Mon Jun 24 12:00:00 AM CDT 2024
        "tokenExpires": 1719291600,  # Tue Jun 25 12:00:00 AM CDT 2024
    }
]


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
    Request a token from the Schedd or PlacementD for the specified username.
    Return the token.
    """
    if PLACEMENTD_USE_BINDINGS:
        token = htcondor1.Schedd().user_login(username)
    else:
        proc = sp.run(["condor_login", "add", username], stdout=sp.PIPE, stderr=sp.PIPE, check=True)
        token = proc.stdout.strip()

    return token


def request_user_list(constraints: t.Sequence[str]) -> t.List[t.Dict]:
    """
    Get back a list of users that have been mapped with the PlacmenetD.
    """
    if PLACEMENTD_USE_BINDINGS:
        raise NotImplementedError("We don't have bindings for the PlacementD yet")
    else:
        # proc = sp.run(["condor_login", "list"], stdout=sp.PIPE, stderr=sp.PIPE, check=True)
        # ^^ and parse this
        return mock_user_list


class V1UserLoginResource(AuthRequiredResource):
    """
    Endpoint for authenticating to an AP to request a Placement Token
    """

    def post(self):
        """
        Ask HTCondor for a token for the authenticated user.
        Requires JSON with a "username" field for the username to request the
        token for.
        """
        # auth_user = self.auth.current_user()
        # ^^ in the future use auth_user to see if the user has the right to request a token (and for whom)

        #
        # Get the user to request the token for, run some checks
        #
        json = request.get_json(cache=False, force=True)
        try:
            username = json.get("username")
        except AttributeError:
            return make_json_error("No or invalid JSON data in request", 400)

        if not username or not isinstance(username, str):
            return make_json_error("username not specified or not a string", 400)
        elif len(username) > MAX_USERNAME_LENGTH:
            return make_json_error("username too long", 400)
        elif not re.match(r"[a-zA-Z0-9][^/]*$", username):  # username must start with a letter or number
            return make_json_error("invalid username", status_code=400)

        #
        # Get a token from the schedd.
        #
        try:
            token = request_user_login(username)
            details = jwt.decode(token, options={"verify_signature": False})
            return flask.jsonify(token=token, details=details)
        except htcondor1.HTCondorIOError as err:
            _log.exception("Error getting token: %s", err)
            if "errmsg=SCHEDD:3" in str(err):
                return make_json_error("No accounts available, try again later", 503)
            elif "errmsg=SECMAN:" in str(err):
                return make_json_error("RESTD cannot authenticate to schedd: %s" % err, 503)
            else:
                return make_json_error("Error getting token: %s" % err, 500)
        except sp.CalledProcessError as err:
            _log.exception("Error getting token: %s", err)
            return make_json_error("Error getting token: %s" % err.stderr, 500)
        except jwt.exceptions.DecodeError as err:
            _log.exception("Error decoding token: %s", err)
            return make_json_error("Schedd returned invalid token: %s" % err, 500)
        except Exception as err:
            _log.exception("Unexpected error getting token: %s", err)
            return make_json_error("Unexpected error getting token", 500)


class V1UserListResource(AuthRequiredResource):
    """
    Endpoint for requesting a list of user accounts from the AP
    """
    def get(self):
        """
        Ask HTCondor for the list of users that have been created by the
        placement daemon.
        """
        try:
            user_list = request_user_list([])
            return flask.jsonify(user_list)
        except sp.CalledProcessError as err:
            _log.exception("Error getting user list: %s", err)
            return make_json_error("Error getting user list: %s" % err.stderr, 500)
        except Exception as err:
            _log.exception("Unexpected error getting user list: %s", err)
            return make_json_error("Unexpected error getting user list", 500)
