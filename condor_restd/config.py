from __future__ import absolute_import

from flask_restful import Resource, reqparse, abort

from htcondor import DaemonTypes, Collector, RemoteParam

import htcondor

from .errors import BAD_ATTRIBUTE_OR_PROJECTION, NO_ATTRIBUTE
from . import utils


class V1ConfigResource(Resource):
    """Endpoints for accessing condor config; implements the /v1/config
    endpoints.

    """

    DAEMON_TYPES_MAP = {
        "collector": DaemonTypes.Collector,
        "master": DaemonTypes.Master,
        "negotiator": DaemonTypes.Negotiator,
        "schedd": DaemonTypes.Schedd,
        "startd": DaemonTypes.Startd,
    }

    def get(self, attribute=None):
        """GET handler"""
        parser = reqparse.RequestParser(trim=True)
        parser.add_argument("daemon", choices=list(self.DAEMON_TYPES_MAP.keys()))
        args = parser.parse_args()

        if args.daemon:
            daemon_ad = Collector().locate(self.DAEMON_TYPES_MAP[args.daemon])
            param = RemoteParam(daemon_ad)
        else:
            htcondor.reload_config()
            param = htcondor.param

        param_lower = utils.deep_lcasekeys(param)

        if attribute:
            if not utils.validate_attribute(attribute):
                abort(400, message=BAD_ATTRIBUTE_OR_PROJECTION)

        if attribute:
            try:
                return param_lower[attribute.lower()]
            except KeyError:
                abort(404, message=NO_ATTRIBUTE)

        return param_lower