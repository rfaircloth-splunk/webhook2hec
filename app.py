#!python
from flask import Flask, jsonify, request, abort
import requests
from splunk_http_event_collector import http_event_collector
import logging

app = Flask(__name__)

gunicorn_error_logger = logging.getLogger("gunicorn.error")
app.logger.handlers.extend(gunicorn_error_logger.handlers)
app.logger.setLevel(logging.DEBUG)


@app.route("/api/v1.0/hook-relay", methods=["POST"])
@app.route("/passthehook", methods=["POST"])
def relay():

    app.logger.debug(request.json)
    http_event_collector_host = request.args.get("server", default="unknown")
    http_event_collector_port = request.args.get("port", default="443")
    http_event_collector_key = request.args.get("hec_token", default="unknown")
    if http_event_collector_host == "unknown" or http_event_collector_key == "unknown":
        abort(400)

    hec = http_event_collector(
        http_event_collector_key,
        http_event_collector_host,
        http_event_port=http_event_collector_port,
    )
    hec.popNullFields = True
    hec.log = app.logger

    hec_payload = {}
    hec_event = {}

    hec.index = request.args.get("index", default="main")
    hec.sourcetype = request.args.get("sourcetype", default="webhook")
    hec.host = "relayserver"
    hec_payload.update({"event": request.json})
    try:
        hec.sendEvent(hec_payload)
    except Exception as e:
        app.log_exception(e)

    return "OK"


if __name__ == "__main__":
    app.run(debug=True)
