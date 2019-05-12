# -*- coding: utf-8 -*-
"""
--- Object ---
Subscribe to VSD notification with an Amqp client from activemq.
Filter notification
Request state engine API

--- Author ---
DA COSTA Alexis <alexis.dacosta@gmail.com>

--- Version history ---
2018-09-22 - 1.0

--- Usage ---
Run 'python event_stream-push_channel.py -h' for an overview

--- Documentation ---
See README file

--- Examples ---

python3.6 /root/nuage-pgsync/event_stream-amqp.py --verbose --ini-file /root/nuage-pgsync/nuage-pgsync.ini --log-file /root/nuage-pgsync/logs/event_stream.log

"""

import argparse
import sys
import requests
import nuage_pgsync_configuration
from proton.handlers import MessagingHandler,EndpointStateHandler
from proton.reactor import Container, DurableSubscription


# imported parameters in .ini file :
# section
ini_general_section      = "GENERAL"
# parameters in section
ini_nuage_enterprise          = "Enterprise"
# section
ini_nuage_amqp_section      = "NUAGE_AMQP_DETAILS"
# parameters in section
ini_nuage_username          = "UserName"
ini_nuage_password          = "Password"
ini_amqp_topic_name         = "TopicName"
ini_amqp_queue_name         = "QueueName"
ini_amqp_durable_subscription = "DurableSubscription"
# section
ini_nuage_vsd_section       = "NUAGE_VSD_CONNECTION"
# parameters in section
ini_nuage_deployment_mode   = "DeploymentMode"
ini_nuage_port              = "AmqpPort"
ini_nuage_host1             = "IpAddr1"
ini_nuage_host2             = "IpAddr2"
ini_nuage_host3             = "IpAddr3"
# section
ini_state_engine_section    = "STATE_ENGINE_CONNECTION"
# parameters in section
ini_pgsync_api_port         = "StateEnginePort"
ini_pgsync_api_host         = "StateEngineAddr"


def main():
    # Handling arguments
    args                    = get_args()
    debug                   = args.debug
    verbose                 = args.verbose
    log_file                = args.logfile
    ini_file                = args.inifile

    # Setup logger
    global logger
    logger = setup_logging(debug, verbose, log_file)

    global config
    vault_config = nuage_pgsync_configuration.Enterprise(ini_file=ini_file,
                                                         logger=logger)
    vault_config.fetch()
    config = vault_config.config

    logger.info("Starting event_stream")
    o_amqp_client = AmqpClient()
    logger.warning('event_stream is Running')
    Container(Recv(o_amqp_client), EndPointHandler()).run()


def get_args():
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
                        help='File to log to. Defaults to event_stream.log file',
                        dest='logfile',
                        type=str,
                        default="logs/event_stream.log")
    parser.add_argument('-p', '--ini-file',
                        required=False,
                        help='File that contain parameters',
                        dest='inifile',
                        type=str,
                        default="nuage-pgsync.ini")
    args = parser.parse_args()
    return args


def setup_logging(debug, verbose, log_file):
    """
    Setup logger
    :param debug: --debug argument
    :param verbose: --verbose argument
    :param log_file: --logfile argument
    :return: logger
    """
    import logging

    if debug:
        log_level = logging.DEBUG
    elif verbose:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    logger = logging.getLogger(__name__)
    hdlr = logging.FileHandler(log_file)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.propagate = False
    logger.setLevel(log_level)
    logging.basicConfig(filename=log_file, format='%(asctime)s %(levelname)s %(message)s', level=log_level)

    return logger


class AmqpClient:

    def __init__(self):
        # Initialize Defaults
        self.bClusterMode = None
        self.bDurableSubscription = None
        self.sClientId = "nuage-pgsync"
        self.sUserName = "username%40csp"
        self.sPassword = "password"
        self.sTopicName = "topic://topic/CNATopic"
        self.sQueueName = "queue://queue/CNAQueue"
        self.isTopic = False
        self.sPort = "5672"
        self.lUrls = []

        # Get attributes from .ini file
        self.parse_file()

    def parse_file(self):
        logger.info("INI file: get Amqp Details")

        # GENERAL
        if config.has_section(ini_general_section):
            # Enterprise
            if config.has_option(ini_general_section, ini_nuage_enterprise):
                self.sClientId = "nuage-pgsync_" + config.get(ini_general_section, ini_nuage_enterprise)
        else:
            logger.error("No General Section")

        # NUAGE_AMQP_DETAILS
        if config.has_section(ini_nuage_amqp_section):
            # UserName
            # If Username and password provided use them else use default
            if config.has_option(ini_nuage_amqp_section, ini_nuage_username):
                self.sUserName = config.get(ini_nuage_amqp_section, ini_nuage_username)
            # Password
            if config.has_option(ini_nuage_amqp_section, ini_nuage_password):
                self.sPassword = config.get(ini_nuage_amqp_section, ini_nuage_password)
            # TopicName
            if config.has_option(ini_nuage_amqp_section, ini_amqp_topic_name):
                self.sTopicName = "topic://" + config.get(ini_nuage_amqp_section, ini_amqp_topic_name)
                self.isTopic = True
            else:
                if config.has_option(ini_nuage_amqp_section, ini_amqp_queue_name):
                    self.sQueueName = "queue://" + config.get(ini_nuage_amqp_section, ini_amqp_queue_name)
            # DurableSubscription
            if config.has_option(ini_nuage_amqp_section, ini_amqp_durable_subscription):
                self.bDurableSubscription = config.get(ini_nuage_amqp_section, ini_amqp_durable_subscription)

        # NUAGE_VSD_CONNECTION
        if config.has_section(ini_nuage_vsd_section):
            # AmqpPort
            if config.has_option(ini_nuage_vsd_section, ini_nuage_port):
                self.sPort = config.get(ini_nuage_vsd_section, ini_nuage_port)
            # DeploymentMode
            if config.has_option(ini_nuage_vsd_section, ini_nuage_deployment_mode):
                self.bClusterMode = config.get(ini_nuage_vsd_section, ini_nuage_deployment_mode)
            if self.bClusterMode == 'cluster':
                logger.info("VSD in Cluster mode, adding all 3 IP's")
                self.lUrls.append(self.get_url(config.get(ini_nuage_vsd_section, ini_nuage_host1)))
                self.lUrls.append(self.get_url(config.get(ini_nuage_vsd_section, ini_nuage_host2)))
                self.lUrls.append(self.get_url(config.get(ini_nuage_vsd_section, ini_nuage_host3)))
            else:
                logger.info("VSD in Standalone mode, adding only one IP")
                self.lUrls.append(self.get_url(config.get(ini_nuage_vsd_section, ini_nuage_host1)))
        else:
            logger.error("No VSD's Connection Details Section")
        # log
        logger.info(
            "Starting ActiveMq Amqp client with Cluster Mode : %s, And durable subscription mode set to : %s" % (
                self.bClusterMode, self.bDurableSubscription))
        logger.info(
            "Connect to ActiveMQ using User Name: %s , Client Id: %s , Connecting to Topic: %s, URL: %s." % (
                self.sUserName, self.sClientId, self.sTopicName, self.lUrls))

    def get_url(self, ip_address):
        return self.sUserName + ":" + self.sPassword + "@" + ip_address + ":" + self.sPort


class Recv(MessagingHandler):
    def __init__(self, o_amqp_client):
        super(Recv, self).__init__()
        self.oAmqpClient = o_amqp_client
        self.received = 0
        self.sStateEnginePort = None
        self.sStateEngineAddr = None

        self.parse_file()

    def parse_file(self):
        logger.info("INI file : get State Engine Connection Details")

        # STATE_ENGINE_CONNECTION
        if config.has_section(ini_state_engine_section):
            # StateEnginePort
            if config.has_option(ini_state_engine_section, ini_pgsync_api_port):
                self.sStateEnginePort = config.get(ini_state_engine_section, ini_pgsync_api_port)
            # StateEngineAddr
            if config.has_option(ini_state_engine_section, ini_pgsync_api_host):
                self.sStateEngineAddr = config.get(ini_state_engine_section, ini_pgsync_api_host)
        else:
            logger.error("No State Engine's Connection Details Section")
        # logs
        logger.info(
            "Connect to State Engine using host=%s; port=%s" % (
                self.sStateEngineAddr,
                self.sStateEnginePort
            ))

    def on_start(self, event):
        # Set the client id So that It is easy to Identify.
        event.container.container_id = self.oAmqpClient.sClientId
        conn = event.container.connect(urls=self.oAmqpClient.lUrls, heartbeat=1000)

        if self.oAmqpClient.bDurableSubscription:
            durable = DurableSubscription()
            if self.oAmqpClient.isTopic:
                event.container.create_receiver(conn, self.oAmqpClient.sTopicName, options=durable)
            else:
                event.container.create_receiver(conn, self.oAmqpClient.sQueueName, options=durable)
        else:
            event.container.create_receiver(conn, self.oAmqpClient.sTopicName)

    def on_disconnected(self, event):
        logger.info("Amqp connection to %s disconnected.", event.connection.hostname)

    def on_message(self, event):
        logger.debug("Message Header: %s", event.message.properties)
        logger.debug("Message Received: %s", event.message.body)
        import json
        event_dict = json.loads(event.message.body)
        self.did_receive_push(event_dict)

    def did_receive_push(self, event):
        """
        Receive delegate

            Notes:
                Nuage notifications used here are those in relationship with policy group update.
                After a desired notification is received, an API request is done to a state_engine.
        :param event:
        :return:
        """
        engine_host = 'http://' + self.sStateEngineAddr + ':' + self.sStateEnginePort
        engine = None
        # log
        logger.info("event parser: eventReceivedTime=%s; type=%s; entityType=%s" % (
                     event['eventReceivedTime'],
                     event['type'],
                     event['entityType']
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
                    'templateID': event['entities'][0]['templateID'],
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

        # vport
        elif event['entityType'] == 'vport':
            data = {'ID': event['entities'][0]['ID'],
                    'name': event['entities'][0]['name'],
                    'type': event['entities'][0]['type'],
                    'domainID': event['entities'][0]['domainID'],
                    'sourceEnterpriseID': event['sourceEnterpriseID']
                    }
            # CREATE
            if event['type'] == 'CREATE':
                engine_url = engine_host + "/sensor/nuage/vport/CREATE"
                engine = requests.put(engine_url, data=data)
            # DELETE
            elif event['type'] == 'DELETE':
                engine_url = engine_host + "/sensor/nuage/vport/DELETE"
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
                    'templateID': event['entities'][0]['templateID'],
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


class EndPointHandler(EndpointStateHandler):
    def __init__(self):
        super(EndPointHandler, self).__init__()

    def on_connection_opened(self, event):
        logger.info("Amqp connection to %s connected.", event.connection.hostname)
        super(EndPointHandler, self).on_connection_opened(event)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt as e:
        logger.exception("Received Keyboard Interrupt exiting")
    except Exception as e:
        logger.exception("Exception Occured during execution %s", e)
        sys.exit(1)
    finally:
        logger.info("Exiting Finally")

