from email import header
import requests
from requests.auth import HTTPBasicAuth
import json
import base64

def search(search, API_KEY, userName, log):
    open_instances = []
    usrPass = userName + ':' + API_KEY
    encoded_u = base64.b64encode(usrPass.encode()).decode()
    url = "https://api.riskiq.net/pt/v2/ssl-certificate/history?"

    try:
        page_number = 0
        headers = {'Content-Type': 'application/json','API-Key': API_KEY,'Authorization': "Basic %s" % encoded_u,'field': 'sha1','order': 'desc','page': str(page_number),
'sort': 'firstSeen'}
        response = requests.request("GET", url+"&query="+search, headers=headers)
        response_json = response.json()
        
        # process page 1
        for result in response_json['results'][0]['ipAddresses']:
            open_instance = dict()
            log.debug("Found matching {0}".format(result)))
            open_instance ['ip'] = result

            if 'port' in result:
                        open_instance['port'] = result['port']
            else:
                open_instance['port'] = ''

    except Exception as e:
        log.info('RiskIQ Serial History error: {}'.format(e))
    return open_instances
