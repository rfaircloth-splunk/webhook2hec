#!python
from flask import Flask, jsonify, request, abort
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import dateutil.parser
import logging
import json
import jwt
import os

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


def send_event(
    http_event_collector_host,
    http_event_collector_port,
    http_event_collector_key,
    event,
):
    try:

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

        response = requests_retry_session().post(
            server_uri, data=json.dumps(event), headers=headers
        )
        app.logger.info(f"Response {response}")
    except Exception as e:
        app.log_exception(e)


@app.route("/api/v1.0/generichook", methods=["POST"])
@app.route("/passthehook", methods=["POST"])
def relay():

    app.logger.debug(request)
    app.logger.debug(request.headers)
    app.logger.debug(request.data)
    app.logger.debug(request.json)

    http_event_collector_host = request.args.get("server", default="unknown")
    http_event_collector_port = request.args.get("port", default="443")
    http_event_collector_key = request.args.get("hec_token", default="unknown")

    event = {
        "index": request.args.get("index", default="main"),
        "sourcetype": request.args.get("sourcetype", default="webhook"),
        "host": "relayserver",
        "event": request.json,
    }
    send_event(
        http_event_collector_host,
        http_event_collector_port,
        http_event_collector_key,
        event,
    )

    return "OK"


def get_token_from_client_credentials(endpoint, client_id, client_secret):
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "resource": "https://manage.office.com",
    }
    response = requests.post(endpoint, data=payload).json()

    return response["access_token"]


@app.route("/api/v1.0/microsoft/office365", methods=["POST"])
def microsoft_office_365():
    # [
    #     {
    #         "clientId": "da6d25b8-e150-4448-81c3-a0e67f8b2907",
    #         "contentCreated": "2020-04-11T23:58:38.774Z",
    #         "contentExpiration": "2020-04-18T23:49:23.939Z",
    #         "contentId": "20200411234923939118090$20200411234923939118090$audit_azureactivedirectory$Audit_AzureActiveDirectory$na0018$na0018",
    #         "contentType": "Audit.AzureActiveDirectory",
    #         "contentUri": "https://manage.office.com/api/v1.0/5786c99c-eb12-4b3b-a84d-df06a2e4516d/activity/feed/audit/20200411234923939118090$20200411234923939118090$audit_azureactivedirectory$Audit_AzureActiveDirectory$na0018$na0018",
    #         "tenantId": "5786c99c-eb12-4b3b-a84d-df06a2e4516d"
    #     }
    # ]
    app.logger.debug(request.json)

    jwt_secret = os.environ["SECRET"]
    jwt_value = request.args.get("token", default="unknown")

    # {
    #   "sourcetype": "o365",
    #   "index": "main",
    #   "client_id": "xxxxxx",
    #   "client_secret": "xxxxx"
    #   "tenant_name": "xxxx.onmicrosoft.com"
    # }

    clear = jwt.decode(jwt_value, jwt_secret, algorithms=["HS512", "HS384", "HS256"],)
    app.logger.debug(clear)
    tenant = clear["tenant_name"]
    tenant = "5786c99c-eb12-4b3b-a84d-df06a2e4516d"

    app.logger.debug(f"tenant {tenant}")
    app.logger.debug(f"type {type(request.json)}")
    if isinstance(request.json, list):
        event = {
            "index": request.args.get("index", default="main"),
            "sourcetype": request.args.get(
                "sourcetype", default="o365:management:notifcation"
            ),
            "source": "subscription",
            "host": "manage.office.com",
            "event": request.json,
        }
        send_event(
            clear["splunk_host"], "443", clear["splunk_token"], event,
        )
        auth_token = get_token_from_client_credentials(
            endpoint=f"https://login.microsoftonline.com/{tenant}/oauth2/token",
            client_id=clear["client_id"],
            client_secret=clear["client_secret"],
        )
        headers = {"Authorization": "Bearer " + auth_token}
        for item in request.json:

            app.logger.debug(f"Item {item}")
            response = requests_retry_session().get(item["contentUri"], headers=headers)

            source_events = response.json()
            splunk_events = []

            for source_event in source_events:
                ts = dateutil.parser.parse(source_event["CreationTime"]).strftime("%s")
                app.logger.debug(f"ts: {ts}")

                clean_event = dict(
                    filter(lambda item: item[1] is not None, source_event.items())
                )
                event = {
                    "time": ts,
                    "index": request.args.get("index", default="main"),
                    "sourcetype": request.args.get(
                        "sourcetype", default="o365:management:activity"
                    ),
                    "source": item["contentType"],
                    "host": "manage.office.com",
                    "event": clean_event,
                }
                splunk_events.append(event)
                app.logger.debug(f"splunk_event: {event}")

        send_event(
            clear["splunk_host"], "443", clear["splunk_token"], splunk_events,
        )
    else:
        event = {
            "index": request.args.get("index", default="main"),
            "sourcetype": request.args.get(
                "sourcetype", default="o365:management:subscription"
            ),
            "source": "subscription",
            "host": "manage.office.com",
            "event": request.json,
        }
        send_event(
            clear["splunk_host"], "443", clear["splunk_token"], event,
        )
    return "OK"


if __name__ == "__main__":
    app.run(debug=True)
