from __future__ import absolute_import

from functools import partialmethod

try:
    from typing import Dict, List, Optional, Union

    Scalar = Union[None, bool, int, float, str]
except ImportError:
    pass

import six

from flask_restful import Resource, abort, reqparse
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth
from werkzeug.security import generate_password_hash, check_password_hash

try:
    import classad2 as classad
    import htcondor2 as htcondor
except ImportError:
    import classad
    import htcondor

from .errors import (
    BAD_ATTRIBUTE,
    BAD_PROJECTION,
    BAD_GROUPBY,
    FAIL_QUERY,
    NO_JOBS,
    NO_ATTRIBUTE,
    ScheddNotFound,
)
from . import utils


basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth("Bearer")
multi_auth = MultiAuth(basic_auth, token_auth)
multi_auth.login_optional = partialmethod(multi_auth.login_required, optional=True)


# TESTING: Test credentials
users = {
    "testuser": generate_password_hash("testpassword"),
}


@basic_auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username


class AuthRequiredResource(Resource):
    """
    Base class for resources that require authentication.
    """
    method_decorators = [multi_auth.login_required]


class AuthOptionalResource(Resource):
    """
    Base class for resources that where authenticating provides additional
    features but is not required.
    """
    method_decorators = [multi_auth.login_optional]


class V1AuthRequiredTestResource(AuthRequiredResource):
    """
    Endpoint for testing authentication
    """

    def get(self):
        return {"message": "Authenticated as %s" % multi_auth.current_user()}


class V1AuthOptionalTestResource(AuthOptionalResource):
    """
    Endpoint for testing optional authentication
    """

    def get(self):
        user = multi_auth.current_user()
        if user:
            return {"message": "Authenticated as %s" % user}
        else:
            return {"message": "Not authenticated"}
