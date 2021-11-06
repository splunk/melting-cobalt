from zoomeye.sdk import ZoomEye
import time

def search(search, API_KEY, log):
    api = ZoomEye(api_key=API_KEY)
    open_instances = []

    try:
        page_number = 1
        results = api.dork_search(search, page=page_number)
        total_results = api.show_count()
        total_pages = round(total_results/20) # result always 20 per page

        # need to caculate pages from here
        log.info('ZoomEye total results: {0}'.format(total_results))
        log.info("Processing page: {0} out of {1}".format(page_number,total_pages))

        # processing page 1
        for r in results:
            open_instance = dict()
            log.debug("Found matching {0}:{1}".format(r['ip'],r['portinfo']['port']))
            open_instance ['ip'] = r['ip']
            open_instance['port'] = r['portinfo']['port']
            if 'domain' in r:
                open_instance['domains'] = r['domain']
            else:
                open_instance['domains'] = ''
                open_instance['hostnames'] = r['portinfo']['hostname']
                open_instance['timestamp'] = r['timestamp']
                
                # need parser for ssl cert
                #if 'ssl' in r:
                    #open_instance['ssl'] = r['ssl']['cert']['subject']
            open_instances.append(open_instance)

        # now paginate through the rest
        for page_number in range(2, total_pages):
            if page_number != 1:
                log.info("Processing page: {0} out of {1}".format(page_number,total_pages))
                results = api.dork_search(search, page=page_number)
                for r in results:
                    open_instance = dict()
                    log.debug("Found matching {0}:{1}".format(r['ip'],r['portinfo']['port']))
                    open_instance ['ip'] = r['ip']
                    open_instance['port'] = r['portinfo']['port']
                    if 'domain' in r:
                        open_instance['domains'] = r['domain']
                    else:
                        open_instance['domains'] = ''
                        open_instance['hostnames'] = r['portinfo']['hostname']
                        open_instance['timestamp'] = r['timestamp']
                    # need parser for ssl cert
                    #if 'ssl' in r:
                        #open_instance['ssl'] = r['ssl']['cert']['subject']

                    open_instances.append(open_instance)
            # avoiding timeout and rejected request, need to sleep        
            time.sleep(5)


    except Exception as e:
        log.info('ZoomEye search error: {}'.format(e))
    return open_instances
