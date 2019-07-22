#!/usr/bin/env python3

import os
import sys
import time
import argparse
import logging
import pysip
import ace_api
import cbinterface
import yaml

#from cbapi import auth
from cbapi.response import CbResponseAPI, Process

from cbinterface.modules.helpers import as_configured_timezone, CONFIG
from cbinterface.modules.query import CBquery

from configparser import ConfigParser

BASE_DIR = os.path.dirname(os.path.realpath(__file__))

# configure logging #
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(name)s - [%(levelname)s] %(message)s')

# handle proxy configurations as specified
# for each system we connect to
HTTPS_PROXY = None
if 'https_proxy' in os.environ:
    HTTPS_PROXY = os.environ['https_proxy']

def handle_proxy(profile):
    if 'ignore_system_proxy' in profile and 'https_proxy' in os.environ:
        if profile.getboolean('ignore_system_proxy'):
            del os.environ['https_proxy']
        else:
            os.environ['https_proxy'] = HTTPS_PROXY
    return

def main():

    parser = argparse.ArgumentParser(description="SIP Indicator CbR Search and ACE Alert.")
    parser.add_argument('-d', '--debug', action="store_true", help="set logging to DEBUG", default=False)
    args = parser.parse_args()

    # load config
    config = ConfigParser()
    config.read('etc/config.ini')

    # load SIP indicator specs so we know how to get the indicators we want
    indicator_specs = {}
    with open(config['SIP']['indicator_specifications'], 'r') as stream:
        try:
            indicator_specs = yaml.safe_load(stream)
            logging.info("Successfully loaded indicator specifications: {}".format(indicator_specs))
        except yaml.YAMLError as e:
            logging.error("Couldn't load indicator specs : {}".format(e))
            return

    # Load ACE API
    ace_api.set_default_remote_host(config['ACE']['ace_address'])
    ace_api.set_default_ssl_ca_path(config['ACE']['ca_chain_path']) 

    # Create SIP Client and load indicators
    sip_ssl = config['SIP'].getboolean('ssl_verify')
    sc = pysip.Client(config['SIP']['sip_address'], config['SIP']['sip_api_key'], verify=sip_ssl)
    status = indicator_specs['status'] if 'status' in indicator_specs else 'Analyzed'
    indicators = {}
    for i_type in indicator_specs['type']:
        handle_proxy(config['SIP'])
        indicators[i_type] = sc.get('/indicators?type={}&status={}'.format(i_type, status))

    # load field mappings
    field_map = ConfigParser()
    field_map.read(config['GLOBAL']['field_mappings'])
    sip_cbr_map = field_map['SIP-TO-CBR']
    sip_ace_map = field_map['SIP-TO-ACE']
    cbr_ace_map = field_map['CBR-TO-ACE']

    submitted_alerts = []

    # Query Carbon Black Response for our indicators
    #cbq = CBquery(profile=config['CbR']['profile'])
    handle_proxy(config['CbR'])
    cb = CbResponseAPI(profile=config['CbR']['profile'])
    for i_type in indicator_specs['type']:
        for i in indicators[i_type]:
            query = '{}:"{}"'.format(sip_cbr_map[i_type],i['value'])
            logging.debug('Querying CbR for indicator:{} query:{}'.format(i['id'], query))
            procs = cb.select(Process).where(query).group_by('id')
            if procs:
                # alert ACE
                Alert = ace_api.Analysis(description='CbR - SIP:{}'.format(i['value']), analysis_mode='correlation', tool='SipCbrAce')
                print(Alert.description)
                Alert.add_indicator(i['id'])
                # get sip tags and tag Alert
                handle_proxy(config['SIP'])
                i_details = sc.get('/indicators/{}'.format(i['id']))
                handle_proxy(config['CbR'])
                for tag in i_details['tags']:
                    Alert.add_tag(tag)
                alert_details = {}
                alert_details['total_results'] = len(procs)
                max_results = config['GLOBAL'].getint('alert_max_results')
                alert_details['included_results'] = 0
                alert_details['process_details'] = []
                for proc in procs:
                    if alert_details['included_results'] > max_results:
                        break
                    alert_details['process_details'].append(str(proc))
                    alert_details['included_results'] += 1
                    Alert.add_hostname(proc.hostname)
                    Alert.add_md5(proc.process_md5)
                    Alert.add_ipv4(proc.comms_ip)
                    Alert.add_ipv4(proc.interface_ip)
                    Alert.add_process_guid(proc.id)
                    Alert.add_user(proc.username)
                    Alert.add_file_name(proc.process_name)
                    Alert.add_file_path(proc.path)
                    #Alert.add_file_location('{}@{}'.format(proc.hostname, proc.path)) 
                #Alert.submit_kwargs['details'] = alert_details
                handle_proxy(config['ACE'])
                print(Alert.description)
                submitted_alerts.append(Alert.submit())
                logger.info("Submitted alert to ACE: {UUID} - URL=https://{HOST}/ace/analysis?direct={UUID}".format(UUID=Alert.uuid, HOST=Alert.remote_host))

    print(submitted_alerts)
    

if __name__ == "__main__":
    main()
