from azure.identity import ClientSecretCredential
from msgraph.core import GraphClient # msgraph-core==0.1.2
from app import flask_app, log
import sys, re, copy

# Find the autopilot device from the serial number
# https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$filter=contains(serialNumber,'R90QLUGX')

class Graph:
    client_credential: ClientSecretCredential
    client: GraphClient

    def __init__(self):
        # in Azure Directory Admin center, in the App Registration, in the app (Python Graph Tutorial), in  API permissions, make sure the TYPE of the permission is Application, NOT Delegated
        #  The required permissions can be found in the API reference, e.g. https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0&tabs=http
        client_id = flask_app.config['ENTRA_CLIENT_ID']
        tenant_id = flask_app.config['ENTRA_TENANT_ID']
        client_secret = flask_app.config['ENTRA_CLIENT_SECRET']
        self.user_id = flask_app.config["ENTRA_USER_ID"]
        self.client_credential = ClientSecretCredential(tenant_id, client_id, client_secret)
        self.client = GraphClient(credential=self.client_credential, scopes=['https://graph.microsoft.com/.default'])

    def send_mail(self, to_list, subject, content):
        url = f"/users/{self.user_id}/sendMail"
        if type(to_list) is not list:
            to_list = [to_list]
        recipients = []
        for to in to_list:
            if to is not None and to != "":
                recipients.append({"emailAddress": {"address": to}})
        if recipients:
            body = {
                "message": {"subject": subject, "body": {"contentType": "html", "content": content}, "toRecipients": recipients
                }
            }
            resp = self.client.post(url, json=body)
            if resp.status_code != 202:
                log.error(f'{sys._getframe().f_code.co_name}: {url} returned status_code {resp.text}')
                return False
        return True

entra = Graph()
