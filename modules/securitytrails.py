import requests
import json
API_URL = 'https://api.securitytrails.com/v1/query/scroll'

def search(search, API_KEY, log):
    open_instances = []
    data = {'query': search}
    headers = {'apikey': API_KEY, 'Content-Type': 'application/json'}
    r = requests.post(API_URL, headers=headers, data=json.dumps(data))
    r_json = r.json()

    page_number = 1
    total_results = r_json['total']['value']
    total_pages = round(total_results/100)
    # need to caculate pages from here
    log.info('securitytrails total results: {0}'.format(total_results))
    log.info("processing page: {0} out of {1}".format(page_number,total_pages))

    #print(json.dumps(r_json))

    for result in r_json['records']:
        open_instance = dict()
        if result['ports']['port']:
            log.debug("found matching {0}:{1}".format(result['address'],",".join(str(i) for i in result['ports']['port'])))
            open_instance ['ip'] = result['address']
            open_instance['port'] = ",".join(str(i) for i in result['ports']['port'])
            open_instances.append(open_instance)

    #for page_number in range(2, total_pages):
    #if (r_json['total']['value'] > 100):
    #    r = requests.get('https://api.securitytrails.com/v1/scroll/' + r_json['id'], headers=headers, data=json.dumps(data))
    #    r_json = r.json()
    #    print(r_json)
    return open_instances
