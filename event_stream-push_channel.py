# -*- coding: utf-8 -*-
"""
--- Object ---
Push channel uses HTTP Long poll to receive VSD event / notification
Filter notification
Request state engine API

--- Author ---
DA COSTA Alexis <alexis.dacosta@bt.com>

--- Version history ---
2018-08-17 - 1.0
2018-09-23 - 1.0.1 : use ini file

--- Usage ---
Run 'python event_stream-push_channel.py -h' for an overview

--- Documentation ---
See README file

--- Examples ---

event_stream-push_channel.py --debug --ini-file my-nuage-pgsync.ini --log-file logs/my-event_stream.log

"""

import argparse
import sys
import requests
import nuage_pgsync_configuration
from time import sleep
try:
    # Try and import Nuage VSPK from the development release
    from vspk import v5_0 as vsdk
except ImportError:
    # If this fails, import the Nuage VSPK from the pip release
    from vspk.vsdk import v5_0 as vsdk

sys.path.append("./")

# imported parameters in .ini file :
# section
ini_nuage_vsd_section           = "NUAGE_VSD_CONNECTION"
# parameters in section
ini_nuage_deployment_mode       = "DeploymentMode"
ini_nuage_host1                 = "IpAddr1"
ini_nuage_host2                 = "IpAddr2"
ini_nuage_host3                 = "IpAddr3"
ini_nuage_port                  = "ApiPort"
# section
ini_nuage_api_section           = "NUAGE_REST_API_DETAILS"
# parameters in section
ini_nuage_username              = 'UserName'
ini_nuage_password              = 'Password'
ini_nuage_organization          = 'Organization'
# section
ini_state_engine_section        = "STATE_ENGINE_CONNECTION"
# parameters in section
ini_pgsync_api_port             = "StateEnginePort"
ini_pgsync_api_host             = "StateEngineAddr"


def main():
    # Handling arguments
    """
    args                = get_args()
    debug               = args.debug
    verbose             = args.verbose
    log_file            = args.logfile
    ini_file            = args.inifile
    """
    # Bouchonnage arguments
    debug = False
    verbose = True
    log_file = 'logs/event_stream.log'
    ini_file = 'nuage-pgsync.ini'

    # Logging settings
    global logger
    logger = setup_logging(debug, verbose, log_file)

    # Load configuration
    global config
    vault_config = nuage_pgsync_configuration.Enterprise(ini_file=ini_file,
                                                         logger=logger)
    vault_config.fetch()
    config = vault_config.config

    # Get parameters from INI file
    global vsd
    vsd = NuageVsd(ini_file)

    # Connection to Nuage
    session = None
    for host in vsd.nuage_host_list:
        try:
            session = login(nuage_host=host,
                            nuage_port=vsd.nuage_port,
                            nuage_username=vsd.nuage_username,
                            nuage_password=vsd.nuage_password,
                            nuage_organization=vsd.nuage_organization)
        except:
            # Try next VSD
            continue
        else:
            # Connected to VSD
            break
    if session is None:
        raise RuntimeError("Could not connect to Nuage")

    # now session contains a push center and the connected user
    session.reset()
    session.start()

    # Get the push center from the session
    push_center = session.push_center

    # Register the delegate function that will be called on each event
    push_center.add_delegate(did_receive_push)

    # Start the push_center
    push_center.start()
    logger.warning('event_stream is Running')

    # Create and destroy subscription to push_center before than the timeout of the session fired.
    # and wait for an event
    while True:
        sleep(3600)

        # Resetting the session will flush the stored API key. Expiry time out = 24h
        session.reset()
        session.start()
        logger.warning('New stored API key')


def setup_logging(debug, verbose, log_file):
    """ Setup logging level for Nuage instance

    """

    import logging
    from vspk.utils import set_log_level

    if debug:
        log_level = logging.DEBUG
    elif verbose:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    set_log_level(log_level)
    logging.basicConfig(filename=log_file, format='%(asctime)s %(levelname)s %(message)s', level=log_level)
    logger = logging.getLogger(__name__)
    return logger


def login(nuage_host, nuage_port, nuage_username, nuage_password, nuage_organization):
    """ Start Nuage connection

    """

    # Getting user password for Nuage connection
    if nuage_password is None:
        import getpass
        logger.debug('No command line Nuage password received, requesting Nuage password from user')
        nuage_password = getpass.getpass(prompt='Enter password for Nuage host %s for user %s: ' % (
            nuage_host,
            nuage_username))

    # Create a Nuage session
    logger.info('Connecting to Nuage server %s:%s with username %s' % (nuage_host, nuage_port, nuage_username))
    session = vsdk.NUVSDSession(username=nuage_username,
                                password=nuage_password,
                                enterprise=nuage_organization,
                                api_url="https://%s:%s" % (nuage_host, nuage_port))

    # Connecting to Nuage
    try:
        session.start()
    except:
        logger.error('Could not connect to Nuage host %s with user %s, enterprise %s and specified password' % (
            nuage_host, nuage_username, nuage_organization))
        raise

    return session


def get_args():
    """ Supports the command-line arguments listed below.

    """
    parser = argparse.ArgumentParser(description="Subscribe to VSD notification.")
    parser.add_argument('-d', '--debug',
                        required=False,
                        help='Enable debug output',
                        dest='debug',
                        action='store_true')
    parser.add_argument('-v', '--verbose',
                        required=False,
                        help='Enable verbose output',
                        dest='verbose',
                        action='store_true')
    parser.add_argument('-l', '--log-file',
                        required=False,
                        help='File to log to (default = stdout)',
                        dest='logfile',
                        type=str,
                        default="event_stream.log")
    parser.add_argument('-p', '--ini-file',
                        required=False,
                        help='File that contain parameters',
                        dest='inifile',
                        type=str,
                        default="nuage-pgsync.ini")
    args = parser.parse_args()
    return args


class NuageVsd(object):
    def __init__(self, ini_file):
        # Initialize Defaults
        self.ini_file = ini_file
        self.nuage_organization = None
        self.nuage_port = None
        self.nuage_password = None
        self.nuage_username = None
        self.nuage_deployment_mode = None
        self.nuage_host_list = []
        self.state_engine_host = None
        self.state_engine_port = None

        # Get attributes from .ini file
        self.parse_file()

    def parse_file(self):
        logger.info("INI file: get Nuage parameters")

        # NUAGE_VSD_CONNECTION section
        if config.has_section(ini_nuage_vsd_section):
            # DeploymentMode
            if config.has_option(ini_nuage_vsd_section, ini_nuage_deployment_mode):
                self.nuage_deployment_mode = config.get(ini_nuage_vsd_section, ini_nuage_deployment_mode)
            if self.nuage_deployment_mode == 'cluster':
                logger.info("VSD in Cluster mode, adding all 3 IP's")
                self.nuage_host_list.append(config.get(ini_nuage_vsd_section, ini_nuage_host1))
                self.nuage_host_list.append(config.get(ini_nuage_vsd_section, ini_nuage_host2))
                self.nuage_host_list.append(config.get(ini_nuage_vsd_section, ini_nuage_host3))
            else:
                logger.info("VSD in Standalone mode, adding only one IP")
                self.nuage_host_list.append(config.get(ini_nuage_vsd_section, ini_nuage_host1))
            # ApiPort
            if config.has_option(ini_nuage_vsd_section, ini_nuage_port):
                self.nuage_port = config.get(ini_nuage_vsd_section, ini_nuage_port)
        else:
            logger.error("No Nuage VSD's Connection Details Section")
        # API section
        if config.has_section(ini_nuage_api_section):
            # UserName
            if config.has_option(ini_nuage_api_section, ini_nuage_username):
                self.nuage_username = config.get(ini_nuage_api_section, ini_nuage_username)
            # Password
            if config.has_option(ini_nuage_api_section, ini_nuage_password):
                self.nuage_password = config.get(ini_nuage_api_section, ini_nuage_password)
            # Organization
            if config.has_option(ini_nuage_api_section, ini_nuage_organization):
                self.nuage_organization = config.get(ini_nuage_api_section, ini_nuage_organization)
        else:
            logger.error("No Nuage API's Connection Details Section")
        # STATE_ENGINE_CONNECTION section
        if config.has_section(ini_state_engine_section):
            # StateEngineAddr
            if config.has_option(ini_state_engine_section, ini_pgsync_api_port):
                self.state_engine_port = config.get(ini_state_engine_section, ini_pgsync_api_port)
            # StateEnginePort
            if config.has_option(ini_state_engine_section, ini_pgsync_api_host):
                self.state_engine_host = config.get(ini_state_engine_section, ini_pgsync_api_host)
        else:
            logger.error("No State Engine's Connection Details Section")


def did_receive_push(data):
    """ Receive delegate

        Notes:
            Nuage notifications used are those in relationship with policy group update.
            After a notification, an API request is done.
    """
    engine_host = 'http://' + vsd.state_engine_host + ':' + vsd.state_engine_port
    engine = None

    i = 0
    for event in data['events']:
        # log
        i += 1
        logger.debug("event %s parser: eventReceivedTime=%s; type=%s; entityType=%s; id=%s; parentType=%s" % (
            i,
            event['eventReceivedTime'],
            event['type'],
            event['entityType'],
            event['entities'][0]['ID'],
            event['entities'][0]['parentType']
        ))
        # policygrouptemplate
        if event['entityType'] == 'policygrouptemplate':
            data = {'ID': event['entities'][0]['ID'],
                    'name': event['entities'][0]['name'],
                    'parentID': event['entities'][0]['parentID'],
                    'parentType': event['entities'][0]['parentType'],
                    'sourceEnterpriseID': event['sourceEnterpriseID']
                    }
            # CREATE
            if event['type'] == 'CREATE':
                engine_url = engine_host + "/sensor/nuage/policygrouptemplate/CREATE"
                engine = requests.put(engine_url, data=data)
            # UPDATE
            elif event['type'] == 'UPDATE':
                engine_url = engine_host + "/sensor/nuage/policygrouptemplate/UPDATE"
                engine = requests.put(engine_url, data=data)
            # DELETE
            elif event['type'] == 'DELETE':
                engine_url = engine_host + "/sensor/nuage/policygrouptemplate/DELETE"
                engine = requests.put(engine_url, data=data)
        # policygroup
        elif event['entityType'] == 'policygroup':
            data = {'ID': event['entities'][0]['ID'],
                    'name': event['entities'][0]['name'],
                    'parentID': event['entities'][0]['parentID'],
                    'parentType': event['entities'][0]['parentType'],
                    'policyGroupID': event['entities'][0]['policyGroupID'],
                    'sourceEnterpriseID': event['sourceEnterpriseID']
                    }
            # CREATE
            if event['type'] == 'CREATE':
                engine_url = engine_host + "/sensor/nuage/policygroup/CREATE"
                engine = requests.put(engine_url, data=data)
            # UPDATE
            elif event['type'] == 'UPDATE':
                engine_url = engine_host + "/sensor/nuage/policygroup/UPDATE"
                engine = requests.put(engine_url, data=data)
            # DELETE
            elif event['type'] == 'DELETE':
                engine_url = engine_host + "/sensor/nuage/policygroup/DELETE"
                engine = requests.put(engine_url, data=data)
        # vminterface
        elif event['entityType'] == 'vminterface':
            data = {'IPAddress': event['entities'][0]['IPAddress'],
                    'VPortID': event['entities'][0]['VPortID'],
                    'domainID': event['entities'][0]['domainID']
                    }
            # CREATE
            if event['type'] == 'CREATE':
                engine_url = engine_host + "/sensor/nuage/vminterface/CREATE"
                engine = requests.put(engine_url, data=data)
            # DELETE
            elif event['type'] == 'DELETE':
                engine_url = engine_host + "/sensor/nuage/vminterface/DELETE"
                engine = requests.put(engine_url, data=data)
        # domaintemplate
        elif event['entityType'] == 'domaintemplate':
            data = {'ID': event['entities'][0]['ID'],
                    'name': event['entities'][0]['name'],
                    'sourceEnterpriseID': event['sourceEnterpriseID']
                    }
            # CREATE
            if event['type'] == 'CREATE':
                engine_url = engine_host + "/sensor/nuage/domaintemplate/CREATE"
                engine = requests.put(engine_url, data=data)
            # UPDATE
            elif event['type'] == 'UPDATE':
                engine_url = engine_host + "/sensor/nuage/domaintemplate/UPDATE"
                engine = requests.put(engine_url, data=data)
            # DELETE
            elif event['type'] == 'DELETE':
                engine_url = engine_host + "/sensor/nuage/domaintemplate/DELETE"
                engine = requests.put(engine_url, data=data)
        # domain
        elif event['entityType'] == 'domain':
            data = {'ID': event['entities'][0]['ID'],
                    'name': event['entities'][0]['name'],
                    'sourceEnterpriseID': event['sourceEnterpriseID']
                    }
            # CREATE
            if event['type'] == 'CREATE':
                engine_url = engine_host + "/sensor/nuage/domain/CREATE"
                engine = requests.put(engine_url, data=data)
            # UPDATE
            elif event['type'] == 'UPDATE':
                engine_url = engine_host + "/sensor/nuage/domain/UPDATE"
                engine = requests.put(engine_url, data=data)
            # DELETE
            elif event['type'] == 'DELETE':
                engine_url = engine_host + "/sensor/nuage/domain/DELETE"
                engine = requests.put(engine_url, data=data)
        # log
        elif engine is not None:
            logger.debug("engine_request: %s" % engine.url)
            logger.debug("engine_response: %s" % engine.text)


# Start program
if __name__ == "__main__":
    main()
