#!python
from flask import Flask, jsonify, request, abort
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

import logging
import json

app = Flask(__name__)

gunicorn_error_logger = logging.getLogger("gunicorn.error")
app.logger.handlers.extend(gunicorn_error_logger.handlers)
app.logger.setLevel(logging.DEBUG)


def requests_retry_session(
    retries=3,
    backoff_factor=0.3,
    status_forcelist=(408, 500, 502, 503, 504),
    session=None,
):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        method_whitelist=frozenset(
            ["HEAD", "TRACE", "GET", "PUT", "OPTIONS", "DELETE", "POST"]
        ),
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


@app.route("/api/v1.0/hook-relay", methods=["POST"])
@app.route("/passthehook", methods=["POST"])
def relay():

    app.logger.debug(request)
    app.logger.debug(request.data)
    app.logger.debug(request.json)
    try:

        http_event_collector_host = request.args.get("server", default="unknown")
        http_event_collector_port = request.args.get("port", default="443")
        http_event_collector_key = request.args.get("hec_token", default="unknown")
        if (
            http_event_collector_host == "unknown"
            or http_event_collector_key == "unknown"
        ):
            abort(400)

        protocol = "https"
        input_url = "/event"
        server_uri = "%s://%s:%s/services/collector%s" % (
            protocol,
            http_event_collector_host,
            http_event_collector_port,
            input_url,
        )
        headers = {"Authorization": "Splunk " + http_event_collector_key}

        event = {
            "index": request.args.get("index", default="main"),
            "sourcetype": request.args.get("sourcetype", default="webhook"),
            "host": "relayserver",
            "event": request.json,
        }

        response = requests_retry_session().post(
            server_uri, data=json.dumps(event
            ), headers=headers
        )
        app.logger.info(f"Response {response}")
    except Exception as e:
        app.log_exception(e)

    return "OK"


if __name__ == "__main__":
    app.run(debug=True)
