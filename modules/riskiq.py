from email import header
import requests
from requests.auth import HTTPBasicAuth
import json
import base64

def search(search, API_KEY, userName, log):
    open_instances = []
    usrPass = userName + ':' + API_KEY
    encoded_u = base64.b64encode(usrPass.encode()).decode()
    url = "https://api.riskiq.net/pt/v2/trackers/"

    try:
        page_number = 0
        headers = {'Content-Type': 'application/json','API-Key': API_KEY,'Authorization': "Basic %s" % encoded_u,'type': 'JarmFuzzyHash','order': 'desc','page': str(page_number),
'sort': 'firstSeen'}
        response = requests.request("GET", url+search+"/addresses", headers=headers)
        response_json = response.json()

        if 'totalRecords' in response_json:
            total_results = response_json['totalRecords']

        else:
            total_results = 0
            log.info('RiskIq total results: {0}'.format(total_results))
            return open_instances

        total_pages = round(total_results/100)
        log.info('RiskIQ total results: {0}'.format(total_results))
        log.info("Processing page: {0} out of {1}".format(page_number,total_pages))

        # process page 1
        for result in response_json['results']:
            open_instance = dict()
            log.debug("Found matching {0}".format(result['address']))
            open_instance ['ip'] = result['address']

            if 'port' in result:
                        open_instance['port'] = result['port']
            else:
                open_instance['port'] = ''


        # now paginate through the rest

        for page_number in range(0, total_results):
            if page_number != 0:

                log.info("Processing page: {0} out of {1}".format(page_number,total_pages))

                headers = {
                'Content-Type': 'application/json','API-Key': API_KEY,'Authorization':"Basic %s" % encoded_u,
                'type': 'JarmFuzzyHash',
                'order': 'desc',
                'page': str(page_number),
                'sort': 'firstSeen'
                }
                response = requests.request("GET", url+search+"/addresses", headers=headers)
                response_json = response.json()
                for r in response_json['results']:
                    open_instance = dict()
                    log.debug("Found matching {0}".format(r['address']))
                    open_instance ['ip'] = r['address']
                    open_instances.append(open_instance)
                    if 'port' in result:
                        open_instance['port'] = result['port']
                    else:
                        open_instance['port'] = ''



    except Exception as e:
        log.info('RiskIQ search error: {}'.format(e))
    return open_instances
