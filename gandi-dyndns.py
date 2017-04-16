#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
gandi-dyndns
@author: AlessioCasco
"""

from bottle import route, run, request, response
from optparse import OptionParser
import logging as log
import xmlrpclib
import json
import sys
import re

gandi_fqdn_ip = {}


@route('/ping', method=['GET', 'POST'])
def ping():
    '''Function for monitoring/ping'''
    response.headers['Server'] = 'gandi-dyndns'
    response.status = 200
    return('I\'am alive!\n')


@route('/nic_update', method=['GET', 'POST'])
def gandi_dyndns():
    '''Main function'''
    response.headers['Server'] = 'gandi-dyndns'

    # dictionary gandi_fqdn_ip, has fqdn:ip key:value from all the legit requests
    global gandi_fqdn_ip
    # dictionar ynew_fqdn_ip, has fqdn:ip key:value from the current request
    new_fqdn_ip = {}
    # define the action to perform into the gandi_api function
    action = ''

    try:
        fqdn, new_ip, fqdn_match = fetch_parameters()
    except TypeError:
        response.status = 400
        return
    # create new dictionary with the info we got from the webserver
    new_fqdn_ip[fqdn] = new_ip
    # check if we need to fetch the ip from gandi
    try:
        if new_fqdn_ip[fqdn] != gandi_fqdn_ip[fqdn]:
            log.debug('Received IP differs from the one saved on Gandi, will update it')
            action = 'update'
            gandi_fqdn_ip = gandi_api(new_fqdn_ip, gandi_fqdn_ip, fqdn, fqdn_match, action)
            return
    except KeyError:
        log.debug('Do not know the current Gandi IP for fqdn %s, will fetch it' % fqdn)
        try:
            action = 'fetch'
            gandi_fqdn_ip = gandi_api(new_fqdn_ip, gandi_fqdn_ip, fqdn, fqdn_match, action)
            if new_fqdn_ip[fqdn] != gandi_fqdn_ip[fqdn]:
                action = 'update'
                gandi_fqdn_ip = gandi_api(new_fqdn_ip, gandi_fqdn_ip, fqdn, fqdn_match, action)
                return
        except ValueError:
            response.status = 404
            return
    log.debug('Nothing to do, received IP is same as the one configured on gandi for %s' % fqdn)
    return


def fetch_parameters():
    '''Fetch parameters from the GET request'''
    new_ip = ''
    method = request.environ.get('REQUEST_METHOD')
    # check for missing parameters
    if not request.params.ip and not request.params.fqdn:
        log.error('Received malformed request, both parameters (fqdn & ip) are missing. Got: \"%s\"' % request.url)
        return
    elif not request.params.ip:
        new_ip = request.environ.get('REMOTE_ADDR')
        log.debug('IP parameter is missing, will use client source one: %s' % new_ip)
    elif not request.params.fqdn:
        log.error('Received malformed request, fqdn parameter is missing. Got: \"%s\"' % request.url)
        return
    if not new_ip:
        new_ip = request.params.ip
    fqdn = request.params.fqdn
    # check if parameters have correct informations
    fqdn_match = re.match(r'^([a-zA-Z0-9][a-zA-Z0-9-]{1,61})\.([a-zA-Z0-9][a-zA-Z0-9-]{1,61}\.[a-zA-Z]{2,}$)', fqdn)
    ip_match = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', new_ip)
    priv_ip_match = re.match(r'^(?:10|127|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\..*', new_ip)
    if not fqdn_match and not ip_match:
        log.error('Received invalid values on both parameters. Got fqdn:\"%s\" & IP: %s' % (fqdn, new_ip))
        return
    elif not ip_match:
        log.error('Received invalid ip value. Got %s' % new_ip)
        return
    elif priv_ip_match:
        log.error('Received IP is not a public one. Got %s' % new_ip)
        return
    elif not fqdn_match:
        log.error('Received invalid fqdn value. Got \"%s\"' % fqdn)
        return
    log.debug('Received %s request: fqdn:\"%s\" & IP: %s' % (method, fqdn, new_ip))
    return fqdn, new_ip, fqdn_match


def gandi_api(new_fqdn_ip, gandi_fqdn_ip, fqdn, fqdn_match, action):
    '''Funcion for managing the Gandi API'''
    # define some variables about gandi
    api = xmlrpclib.ServerProxy('https://rpc.gandi.net/xmlrpc/')
    apikey = config['apikey']
    hostname = (fqdn_match.group(1))
    domain = (fqdn_match.group(2))
    # check if the domain is managed by the apikey provided
    if not (api.domain.list(apikey, {'~fqdn': domain})):
        log.error('Apikey provided does not manage %s domain' % domain)
        raise ValueError('Apikey provided does not manage %s domain' % domain)
    # check available zones
    zones = api.domain.zone.list(apikey)
    for zone in zones:
        if (zone['name']) == domain:
            zone_id = zone['id']
            log.debug('Zone id %s found, for domain %s' % (zone_id, domain))
            break
    else:
        log.error('Could not find zone file called %s, you must have a zone having same name as the domain you want to manage' % domain)
        raise ValueError('Could not find zone file called %s, you must have a zone having same name as the domain you want to manage' % domain)

    # check if we have to fetch the gandi api
    if action == 'fetch':
        # check & retrieve informations from recods in zone
        records = api.domain.zone.record.list(apikey, zone_id, 0)
        for record in records:
            if (record['name'] == hostname and record['type'].lower() == 'a'):
                # add fqdn/ip to the gandi_fqdn_ip dictionary
                gandi_fqdn_ip[fqdn] = record['value']
                log.debug('DNS \'A\' record found for subdomain \'%s\' having value %s' % (hostname, gandi_fqdn_ip[fqdn]))
                break
        else:
            log.error('Unable to find a DNS \'A\' record for subdomain \'%s\'' % hostname)
            raise ValueError('Unable to find a DNS \'A\' record for subdomain \'%s\'' % hostname)
        return gandi_fqdn_ip

    # check if we have to update the the ip
    elif action == 'update':
        # create a new zone from the existing one
        zone_version = api.domain.zone.version.new(apikey, zone_id)
        log.debug('New zone created, new version: %s' % zone_version)
        # delete the A record from the new version
        api.domain.zone.record.delete(apikey, zone_id, zone_version, {"type": ["A"], "name": [hostname]})
        log.debug('Deleted \'A\' record from new zone version %s' % zone_version)
        # add the A record we want
        new_record = api.domain.zone.record.add(apikey, zone_id, zone_version, {"type": "A", "name": hostname, "value": new_fqdn_ip[fqdn], "ttl": 300})
        log.debug('New \'A\' record added as follow: %s' % new_record)
        # active the new zone version
        if api.domain.zone.version.set(apikey, zone_id, zone_version):
            log.info('New IP %s for fqdn %s updated succesfully.' % (new_fqdn_ip[fqdn], fqdn))
        else:
            log.error('Unable to update IP %s for fqdn %s' % (new_fqdn_ip[fqdn], fqdn))
            return
        # update gandi_fqdn_ip with the value just saved in the new zone version
        gandi_fqdn_ip[fqdn] = new_fqdn_ip[fqdn]
        return gandi_fqdn_ip


def init_application():

    def get_options():
        '''Load options from the command line'''
        default_config = "config.json"
        parser = OptionParser(usage="usage: %prog [options]")
        parser.add_option(
            "-c",
            "--config",
            dest="configfile",
            default=default_config,
            help='Config file relative or absolute path. Default is %s' % default_config)
        (options, args) = parser.parse_args()
        if options.configfile is not None:
            options.configfile = options.configfile.strip(' ')
        return options

    def read_config_file(configfile):
        '''Loads the config file from disk'''
        try:
            with open(configfile) as f:
                config = validate_config(json.load(f))
                return config
        # catch if file doesn't exist
        except IOError:
            print('Config file %s not found' % configfile)
            sys.exit(1)
        # catch if json file is not formatted corectly
        except ValueError:
            print('Json file is not formatted properly')
            sys.exit(1)

    def validate_config(raw_config):
        '''Checks the config file.'''
        # check if required patameters are present inside the config
        if 'port' not in raw_config or 'bind' not in raw_config or 'apikey' not in raw_config or 'logging' not in raw_config:
            print('Config file has missing parameters')
            sys.exit(1)
        else:
            return raw_config

    def configure_logging(config):
        '''Configure logging'''
        if config['logging']['log_enable'] == "false":
            log.disable('CRITICAL')
            return
        elif config['logging']['log_enable'] == "true":
            try:
                log.basicConfig(
                    format='%(asctime)-15s [%(levelname)s] %(message)s',
                    filename=config['logging']['log_file'],
                    level=config['logging']['log_level'])
            except ValueError:
                print('Log level is not set with a correct value, check the README.md for the full list')
                sys.exit(1)
            except IOError:
                print('Unable to create the log file, check if gandi-dyndns has write permissions')
                sys.exit(1)
            return
        else:
            print('Bad congig file, log_enable is not set with a correct value, (true|false) are the two only options')
            sys.exit(1)

    options = get_options()
    config = read_config_file(options.configfile)
    configure_logging(config)
    return config


if __name__ == "__main__":
    config = init_application()
    # init webserver
    run(host=config["bind"], port=config["port"], quiet=True)
