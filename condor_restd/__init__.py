# -*- coding=utf-8 -*-
"""*** condor_restd.py ***
REST-based API for HTCondor, based on the HTCondor Python bindings.

Allows read-only queries for jobs (in-queue and historical),
configuration, and machine status.
"""
from __future__ import absolute_import
import re
import json

try:
    from typing import Dict, List, Optional
except ImportError:
    pass

import classad
import htcondor
from htcondor import AdTypes, Collector, DaemonTypes, RemoteParam

from flask import Flask
from flask_restful import Resource, Api, abort, reqparse

from . import utils

app = Flask(__name__)
api = Api(app)


def validate_attribute(attribute):
    """Return True if the given attribute is a valid classad attribute name"""
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", attribute))


def validate_projection(projection):
    """Return True if the given projection has a valid format, i.e.
    is a comma-separated list of valid attribute names.
    """
    return all(validate_attribute(x) for x in projection.split(","))


class JobsBaseResource(Resource):
    """Base class for endpoints for accessing current and historical job
    information. This class must be overridden to specify `executable`.

    """

    querytype = None

    def _query_common(self, id_requirements, constraint, projection):
        # type: (str, str, str) -> List[Dict]
        schedd = utils.get_schedd()
        projection_list = []
        if projection:
            if not validate_projection(projection):
                abort(400, message="Invalid attribute or projection")
            projection_list = list(set(["clusterid", "procid"] + projection.split(",")))

        if self.querytype == "history":
            method = schedd.history
        elif self.querytype == "xquery":
            method = schedd.xquery
        else:
            assert False, "Invalid querytype %r" % self.querytype

        requirements = id_requirements or "true"
        if constraint:
            requirements += " && " + constraint
        classads = method(requirements=requirements, projection=projection_list)
        if id_requirements and not classads:
            # No classads found.  Did the constraint not match or does the cluster.proc
            # not exist in the first place?
            id_classads = method(requirements=id_requirements, projection=[])
            if not id_classads:
                abort(404, message="No matching jobs")

        return utils.classads_to_dicts(classads)

    def query_multi(self, clusterid=None, constraint=None, projection=None):
        # type: (int, str, str) -> List[Dict]
        id_requirements = ""
        if clusterid is not None:
            id_requirements = "clusterid==%d" % clusterid
        ad_dicts = self._query_common(id_requirements, constraint, projection)

        data = []
        for ad in ad_dicts:
            data.append(
                dict(classad=ad, jobid="%s.%s" % (ad["clusterid"], ad["procid"]))
            )

        return data

    def query_single(self, clusterid, procid, constraint=None, projection=None):
        # type: (int, int, str, str) -> Optional[Dict]
        id_requirements = "clusterid==%d && procid==%d" % (clusterid, procid)
        ad_dicts = self._query_common(id_requirements, constraint, projection)
        if ad_dicts:
            ad = ad_dicts[0]
            return dict(classad=ad, jobid="%s.%s" % (ad["clusterid"], ad["procid"]))

    def query_attribute(self, clusterid, procid, attribute, constraint=None):
        # type: (int, int, str, str) -> Optional[str]
        q = self.query_single(clusterid, procid, constraint, projection=attribute)
        if not q:
            abort(404, message="No matching jobs")
        l_attribute = attribute.lower()
        if l_attribute in q["classad"]:
            return q["classad"][l_attribute]
        else:
            abort(404, message="No such attribute")

    def get(self, clusterid=None, procid=None, attribute=None):
        parser = reqparse.RequestParser(trim=True)
        parser.add_argument("projection", default="")
        parser.add_argument("constraint", default="true")
        args = parser.parse_args()
        if attribute:
            return self.query_attribute(
                clusterid, procid, attribute, constraint=args.constraint
            )
        if procid is not None:
            return self.query_single(
                clusterid,
                procid,
                constraint=args.constraint,
                projection=args.projection,
            )
        return self.query_multi(
            clusterid, constraint=args.constraint, projection=args.projection
        )


class V1JobsResource(JobsBaseResource):
    """Endpoints for accessing information about jobs in the queue

    This implements the following endpoint:

        GET /v1/jobs{/clusterid}{/procid}{/attribute}{?projection,constraint}

        If `clusterid`, `procid`, and `attribute` are specified, then it
        returns the value of that attribute, or null if the attribute is
        missing or undefined.

        If `attribute` is not specified, job object(s) will be returned,
        which have the form:

            {
              "jobid": "123.45",
              "classad": { (json-encoded classad object) }
            }

        If `clusterid` and `procid` are specified, then the result will be a
        single job.  If only `clusterid` is specified, then the result will
        be an array of all jobs within that cluster.  If none of these are
        specified, the result will be an of all jobs in the queue.

        `projection` is one or more comma-separated attributes; if specified,
        only those attributes, plus `clusterid` and `procid` will be in the
        `classad` object of each job.  `projection` is ignored if `attribute`
        is specified.

        `constraint` is a classad expression restricting which jobs to include
        in the result.  The constraint is always applied, even if `clusterid`
        and `procid` are specified.

    """

    querytype = "xquery"


class V1HistoryResource(JobsBaseResource):
    """Endpoints for accessing historical job information

    This implements the following endpoint:

        GET /v1/history{/clusterid}{/procid}{/attribute}{?projection,constraint}

        If `clusterid`, `procid`, and `attribute` are specified, then it
        returns the value of that attribute.  Otherwise it returns an array
        of one or more objects of the form:

            {
              "jobid": "123.45",
              "classad": { (classad object) }
            }

        If `clusterid` and `procid` are specified, then the array will contain
        a single job.

        If only `clusterid` is specified, then the array will
        contain all jobs within that cluster.  If none of these are specified,
        the array will contain all jobs in the history.

        `projection` is one or more comma-separated attributes; if specified,
        only those attributes, plus `clusterid` and `procid` will be in the
        `classad` object of each job.  `projection` is ignored if `attribute`
        is specified.

        `constraint` is a classad expression restricting which jobs to include
        in the result.  The constraint is always applied, even if `clusterid`
        and `procid` are specified.

    """

    querytype = "history"


class V1StatusResource(Resource):
    """Endpoints for accessing condor_status information

    This implements the following endpoint:

        GET /v1/status{?projection,constraint,query}

        This returns an array of objects of the following form:

            {
              "name": "<name classad attribute>",
              "classad": { <classad object> }
            }

        `name` is a specific host or slot to query.  If not specified, all
        matching ads are returned.

        `query` is the type of ad to query; see the "Query options" in the
        condor_status(1) manpage.  "startd" is the default.

        `projection` is one or more comma-separated attributes; if specified,
        only those attributes, plus `name` and `procid` will be in the
        `classad` object of each job.

        `constraint` is a classad expression restricting which ads to include
        in the result.

        Returns 404 if no matching ads are found.  This includes zero ads
        matching the constraint.

    """

    AD_TYPES_MAP = {
        "accounting": AdTypes.Accounting,
        "any": AdTypes.Any,
        "collector": AdTypes.Collector,
        "credd": AdTypes.Credd,
        "defrag": AdTypes.Defrag,
        "generic": AdTypes.Generic,
        "grid": AdTypes.Grid,
        "had": AdTypes.HAD,
        "license": AdTypes.License,
        "master": AdTypes.Master,
        "negotiator": AdTypes.Negotiator,
        "schedd": AdTypes.Schedd,
        "startd": AdTypes.Startd,
        "submitter": AdTypes.Submitter,
        "submitters": AdTypes.Submitter,  # Original API & command-line tools used "submitters"
    }

    def get(self, name=None):
        """GET handler"""
        parser = reqparse.RequestParser(trim=True)
        parser.add_argument("projection", default="")
        parser.add_argument("constraint", default="")
        parser.add_argument(
            "query", choices=list(self.AD_TYPES_MAP.keys()), default="any"
        )
        args = parser.parse_args()

        collector = Collector()
        ad_type = self.AD_TYPES_MAP[args.query]
        projection = []

        if args.projection:
            if not validate_projection(args.projection):
                abort(
                    400,
                    message="Invalid projection: must be a comma-separated list of classad attributes",
                )
            projection = ",".split(args.projection)

        constraint = args.constraint
        if name:
            constraint = '(name == "%s")' % name
            if args.constraint:
                constraint += " && (%s)" % args.constraint

        classads = []  # type: List[classad.ClassAd]
        try:
            classads = collector.query(
                ad_type, constraint=constraint, projection=projection
            )
        except RuntimeError as err:
            abort(400, message=str(err))  # LAZY

        data = [
            {"name": ad["name"], "classad": ad}
            for ad in utils.classads_to_dicts(classads)
        ]

        return data


class V1ConfigResource(Resource):
    """Endpoints for accessing condor config

    This implements the following endpoint:

        GET /v1/config{/attribute}{?daemon}

        If `attribute` is specified, returns the value of the specific
        attribute in the condor config.  If not specified, returns an object
        of the form:

            {
              "attribute1": "value1",
              "attribute2": "value2",
              ...
            }

        If `daemon` is specified, query the given running daemon; otherwise,
        query the static config files.

        Returns 404 if `attribute` is specified but the attribute is undefined.

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
            if not validate_attribute(attribute):
                abort(400, message="Invalid attribute")

        if attribute:
            try:
                return param_lower[attribute.lower()]
            except KeyError as err:
                abort(404, message=str(err))

        return param_lower


class RootResource(Resource):
    def get(self):
        return {}


api.add_resource(RootResource, "/")


api.add_resource(
    V1JobsResource,
    "/v1/jobs",
    "/v1/jobs/<int:clusterid>",
    "/v1/jobs/<int:clusterid>/<int:procid>",
    "/v1/jobs/<int:clusterid>/<int:procid>/<attribute>",
)
api.add_resource(
    V1HistoryResource,
    "/v1/history",
    "/v1/history/<int:clusterid>",
    "/v1/history/<int:clusterid>/<int:procid>",
    "/v1/history/<int:clusterid>/<int:procid>/<attribute>",
)
api.add_resource(V1StatusResource, "/v1/status", "/v1/status/<name>")
api.add_resource(V1ConfigResource, "/v1/config", "/v1/config/<attribute>")

PUBLIC_ENDPOINTS = [
    "V1JobsResource",
    "V1ConfigResource",
    "V1HistoryResource",
    "V1StatusResource",
]