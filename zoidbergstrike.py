#!/usr/bin/env python2

import argparse
import json
import yaml
import socket
import os
import sys
import time
from pathlib import Path
from modules.CustomConfigParser import CustomConfigParser
from modules import logger, shodan, nmap, securitytrails


VERSION = 1

def write_results(OUTPUT_FILE, results, log):
    # write parsed results to a files
    try:
        with open(OUTPUT_FILE, 'a') as outfile:
            json.dump(results, outfile)
        log.info("Wrote {0} beacon data to result file: {0}".format(len(results),OUTPUT_FILE))
    except Exection as e:
        log.error("Writing result file: {0}".format(str(e)))

def ips_from_inputfile(INPUT_FILE):
    cobalt_ips = []
    ips_file = open(INPUT_FILE,'r')
    for ip in ips_file.readlines():
        match = dict()
        try:
            socket.inet_aton(ip)
            match['ip'] = ip.rstrip()
            match['port'] = ''
            cobalt_ips.append(match)
        except socket.error:
            log.error("{0} Not a valid ip address on file {1}".format(ip, INPUT_FILE))
            sys.exit(1)
    return cobalt_ips

def read_searches(SEARCH_YML):
    searches = dict()
    with open(SEARCH_YML, 'r') as file:
        searches = yaml.full_load(file)
    return searches

def mine_cobalt(search, config, log):
    cobalt_ips = []
    if 'shodan' in search:
        for s in search['shodan']:
            log.info("Gathering all IPs from Shodan using search: {}".format(s))
            results = shodan.search(s, config['shodan_token'], log)
            log.info("Identified {} matching instances".format(len(results)))
            for ip in results:
                cobalt_ips.append(ip)
    if 'securitytrails' in search:
        for s in search['securitytrails']:
            log.info("Gathering all IPs from SecurityTrails using search: {}".format(s))
            results = securitytrails.search(s, config['securitytrails_token'], log)
            log.info("Identified {} matching instances".format(len(results)))
            for ip in results:
                cobalt_ips.append(ip)
            # sleep 1 second to not hit securitytrails api rate limit
            time.sleep(1)
    log.info("Cobalt Strike Team Servers found: {}".format(len(cobalt_ips)))
    return cobalt_ips


if __name__ == "__main__":

    # grab arguments
    parser = argparse.ArgumentParser(description="Scans for publicly accessible Cobalt Strike Team Servers and grabs the beacon configuration and writes it out as a json log to be analyzed by any analytic tools like Splunk, Elastic, and so forth.")
    parser.add_argument("-c", "--config", required=False, default="zoidbergstrike.conf", help="Path to configuration file. Default: zoidbergstrike.conf")
    parser.add_argument("-v", "--version", default=False, action="store_true", required=False, help="Shows current zoidbergstrike version")
    parser.add_argument("-i", "--input", required=False, default = "", help="Newline delimeted file of potential Cobalt Strike Team Servers IP's to grab beacon configurations from. Example - ips.txt")

    # parse them
    args = parser.parse_args()
    config = args.config
    ARG_VERSION = args.version
    INPUT_PATH = args.input

    # needs config parser here
    tool_config = Path(config)
    if tool_config.is_file():
        print("zoidbergstrike is using config at path {0}".format(tool_config))
        configpath = str(tool_config)
    else:
        print("ERROR: zoidbergstrike failed to find a config file at {0}..exiting".format(tool_config))
        sys.exit(1)

    # Parse config
    parser = CustomConfigParser()
    config = parser.load_conf(configpath)

    log = logger.setup_logging(config['log_path'], config['log_level'])
    log.info("INIT - zoidbergstrike v" + str(VERSION))

    if ARG_VERSION:
        log.info("version: {0}".format(VERSION))
        sys.exit(0)

    NMAP_PATH = nmap.check(log)
    SEARCH_YML = config['searches']
    NSE_SCRIPT_PATH = config['nse_script']

    if INPUT_PATH == "":
        log.info("Scanning for potential Cobalt Strike Team Server IPs")
        cobalt_ips = []
        abs_path = os.path.abspath(SEARCH_YML)
        searches = read_searches(abs_path)
        print(searches)
        cobalt_ips = mine_cobalt(searches, config, log)
    else:
        abs_path = os.path.abspath(INPUT_PATH)
        log.info("Reading from input file: {}".format(abs_path))
        cobalt_ips = ips_from_inputfile(abs_path)
        log.info("Scanning for {0} ips from file".format(len(cobalt_ips)))

    NSE_SCRIPT_PATH = os.path.abspath(NSE_SCRIPT_PATH)
    results = nmap.scan(cobalt_ips, NSE_SCRIPT_PATH, NMAP_PATH, log)
    if results:
        write_results(config['output'], results, log)
    else:
        log.debug("Returned no results, you might not be able to reach the server or they are down!")

    log.info("Finished successfully!")
