import subprocess
import xmltodict
import json
import time
import sys


def parse_c2(c2s):
    c2s = c2s.split(",")
    # grab pairwise matches eg. (1,2), (3,4) to contruct domain,
    pairswise = zip(c2s[::2], c2s[1::2])
    parsed_c2s = []
    for pair in pairswise:
        parsed_c2s.append(''.join(pair))
    return parsed_c2s

def check(log):
# only support nix*  at the moment
    try:
        NMAP_PATH = subprocess.run(['which', 'nmap'], capture_output=True, text=True)
        if NMAP_PATH.stdout.rstrip() == "":
            log.error("Nmap not found, please make sure nmap is installed and accessible via path (which nmap)")
            sys.exit(1)
    except Exception as e:
        log.error("{0}, please make sure nmap is installed and accessible via path (which nmap).".format(e))
        sys.exit(1)
    return NMAP_PATH.stdout.rstrip()

def scan(open_instances, NSE_SCRIPT_PATH, NMAP_PATH, log):
    nmap_results = []
    for open_instance in open_instances:
        log.info("Reducing beacon from: {} on ports: {}".format(open_instance['ip'],open_instance['port']))
        if open_instance['port'] ==  '':
            cmd = [NMAP_PATH, open_instance['ip'], '--script', NSE_SCRIPT_PATH,'-vv','-d', '-n', '-F', '-T5', '-oX', '-']
            log.debug("Scanning with nmap: {}".format(' '.join(cmd)))
            result = subprocess.run(cmd, capture_output=True, text=True)

        else:
            cmd = [NMAP_PATH, open_instance['ip'], '-p', str(open_instance['port']), '--script', NSE_SCRIPT_PATH,'-vv','-d', '-n', '-T5', '-oX', '-']
            log.debug("Scanning with nmap: {}".format(' '.join(cmd)))
            result = subprocess.run(cmd, capture_output=True, text=True)
        json_result = dict()
        json_result = xmltodict.parse(result.stdout)
        parsed_result = parse(json_result, log)
        if parsed_result:
            nmap_results.append(parsed_result)
    return nmap_results

def parse(result, log):
    results = []
    match = dict()
    parsed_result = dict()
    # check if host is even up
    if result['nmaprun']['host']['status']['@state'] == 'up':
        # if it is up, lets dig out the beacon info and port info
        # we need to check if port is a array or dict since it changes depending on nmaps args
        # if -p used it will return a dict
        if isinstance(result['nmaprun']['host']['ports']['port'], list):
            for port in result['nmaprun']['host']['ports']['port']:
                if "script" in port:
                    log.debug("Parsing output: {0}".format(port['script']['@output']))
                    # we need to make sure that it is json, this has failed before
                    try:
                        match = json.loads(port['script']['@output'])
                        match['port'] = port
                    except Exception as e:
                        log.error('Nmap error: {0}, parsing output: {1}'.format(e, port['script']['@output']))
        else:
            if "script" in result['nmaprun']['host']['ports']['port']:
                port = result['nmaprun']['host']['ports']['port']
                log.debug("Parsing output: {0}".format(port['script']['@output']))
                # we need to make sure that it is json, this has failed before
                try:
                    match = json.loads(port['script']['@output'])
                    match['port'] = port
                except Exception as e:
                    log.info('Nmap error: {0}, parsing output: {1}'.format(e, port['script']['@output']))
    else:
        log.error("Failed to reduce beacon from {} it appears to be down".format(result['nmaprun']['host']['address']['@addr']))
        return
    # if we do have a match lets parse it into our own structure
    if match:
        parsed_result['timestamp'] = time.time()
        parsed_result['nmap_cmd'] = result['nmaprun']['@args']
        parsed_result['ip'] = result['nmaprun']['host']['address']['@addr']
        parsed_result['port'] = match['port']['@portid']
        parsed_result['protocol'] = match['port']['@protocol']
        parsed_result['service'] = match['port']['service']['@name']
        parsed_result['hostnames'] = result['nmaprun']['host']['hostnames']
        parsed_result['x64_sha1'] = match['x64']['sha1']
        parsed_result['x64_sha256'] = match['x64']['sha256']
        parsed_result['x64_md5'] = match['x64']['md5']
        parsed_result['x86_sha1'] = match['x86']['sha1']
        parsed_result['x86_sha256'] = match['x86']['sha256']
        parsed_result['x86_md5'] = match['x86']['md5']

        # values we need to make sure they are present
        # x64
        if 'Method 1' in match['x64']['config']:
            parsed_result['x64_config_method_1'] = match['x64']['config']['Method 1']
        if 'Method 2' in match['x64']['config']:
            parsed_result['x64_config_method_2'] = match['x64']['config']['Method 2']
        if 'Port' in match['x64']['config']:
            parsed_result['x64_config_port'] = match['x64']['config']['Port']
        if 'Spawn To x64' in match['x64']['config']:
            parsed_result['x64_config_spawn_to_x64'] = match['x64']['config']['Spawn To x64']
        else:
            log.error("Failed to reduce beacon from {}:{} it is missing x64_config_spawn_to_x64".format(result['nmaprun']['host']['address']['@addr'], match['port']['@portid']))
            return
        if 'Spawn To x86' in match['x64']['config']:
            parsed_result['x64_config_spawn_to_x86'] = match['x64']['config']['Spawn To x86']
        if 'Jitter' in match['x64']['config']:
            parsed_result['x64_config_jitter'] = match['x64']['config']['Jitter']
        if 'Max DNS' in match['x64']['config']:
            parsed_result['max_dns'] = match['x64']['config']['Max DNS']
        if 'DNS Idle' in match['x64']['config']:
            parsed_result['dns_idle'] = match['x64']['config']['DNS Idle']
        if 'DNS Sleep' in match['x64']['config']:
            parsed_result['dns_sleep'] = match['x64']['config']['DNS Sleep']
        if 'User Agent' in match['x64']['config']:
            parsed_result['user_agent'] = match['x64']['config']['User Agent']
        if 'CreateRemoteThread' in match['x64']['config']:
            parsed_result['createremotethread'] = match['x64']['config']['CreateRemoteThread']
        if 'Proxy Hostname' in match['x64']['config']:
            parsed_result['proxy_hostname'] = match['x64']['config']['Proxy Hostname']
        if 'Proxy Username' in match['x64']['config']:
            parsed_result['proxy_username'] = match['x64']['config']['Proxy Username']
        if 'Proxy Password' in match['x64']['config']:
            parsed_result['proxy_password'] = match['x64']['config']['Proxy Password']
        if 'Proxy Access Type' in match['x64']['config']:
            parsed_result['proxy_access_type'] = match['x64']['config']['Proxy Access Type']
        if 'Watermark' in match['x64']['config']:
            parsed_result['watermark'] = match['x64']['config']['Watermark']
        if 'C2 Host Header' in match['x64']['config']:
            parsed_result['c2_host_header'] = match['x64']['config']['C2 Host Header']
        if 'Polling' in match['x64']['config']:
            parsed_result['x64_config_polling'] = match['x64']['config']['Polling']
        if 'C2 Server' in match['x64']['config']:
            parsed_c2s = parse_c2(match['x64']['config']['C2 Server'])
            parsed_result['x64_config_c2_server'] = parsed_c2s
        if 'Beacon Type' in match['x64']['config']:
            parsed_result['x64_config_beacon_type'] = match['x64']['config']['Beacon Type']
        else:
            log.error("Failed to reduce beacon from {}:{} it is missing x64_config_beacon_type".format(result['nmaprun']['host']['address']['@addr'], match['port']['@portid']))
            return
        if 'HTTP Method Path 2' in match['x64']['config']:
            parsed_result['x64_config_http_method_path_2'] = match['x64']['config']['HTTP Method Path 2']
        if 'uri_queried' in match['x64']:
            parsed_result['x64_uri_queried'] = match['x64']['uri_queried']
        # x86
        if 'Method 1' in match['x86']['config']:
            parsed_result['x86_config_method_1'] = match['x64']['config']['Method 1']
        if 'Method 2' in match['x64']['config']:
            parsed_result['x86_config_method_2'] = match['x64']['config']['Method 2']
        if 'Port' in match['x86']['config']:
            parsed_result['x86_config_port'] = match['x64']['config']['Port']
        if 'Spawn To x64' in match['x86']['config']:
            parsed_result['x86_config_spawn_to_x64'] = match['x86']['config']['Spawn To x64']
        if 'Spawn To x86' in match['x86']['config']:
            parsed_result['x86_config_spawn_to_x86'] = match['x86']['config']['Spawn To x86']
        if 'Jitter' in match['x86']['config']:
            parsed_result['x86_config_jitter'] = match['x86']['config']['Jitter']
        if 'Polling' in match['x86']['config']:
            parsed_result['x86_config_polling'] = match['x86']['config']['Polling']
        if 'C2 Server' in match['x86']['config']:
            parsed_c2s = parse_c2(match['x86']['config']['C2 Server'])
            parsed_result['x86_config_c2_server'] = parsed_c2s
        if 'Beacon Type' in match['x86']['config']:
            parsed_result['x86_config_beacon_type'] = match['x86']['config']['Beacon Type']
        if 'HTTP Method Path 2' in match['x86']['config']:
            parsed_result['x86_config_http_method_path_2'] = match['x86']['config']['HTTP Method Path 2']
        if 'uri_queried' in match['x86']['config']:
            parsed_result['x86_uri_queried'] = match['x86']['uri_queried']

        log.debug("Parsed_result:\n{0}".format(json.dumps(parsed_result,indent=2)))
        log.info("Successfully reduced beacon from {}:{}".format(parsed_result['ip'], parsed_result['port']))

        return parsed_result

    return results
