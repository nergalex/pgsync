# -*- coding: utf-8 -*-
"""
--- Object ---
Initialize an image of ip-policy_groups mapping from a Nuage VSD
API listener who wait for dag_sensor updates

--- Usage ---
Run 'python state_engine.py -h' for an overview

--- Documentation ---
TODO : issue PAN-77290, requirements PANORAMA OS v8.0.3+

--- Author ---
DA COSTA Alexis <alexis.dacosta@gmail.com>

--- Issue ---
TODO : sync F5 is currently a "sync all database" change to not sync to PAN

--- Roadmap ---

--- Request For Feature ---
TODO : geo-cluster active/backup
TODO : support multi enterprise
TODO : support container
"""

from flask import (Flask, make_response)
from flask_restful import (reqparse, abort, Api, Resource)
import argparse
from storage_engine import storage_engine_nuage, storage_engine_pan, storage_engine_f5
import nuage_pgsync_configuration
import json
import threading
import uuid
from time import sleep

try:
    # Try and import Nuage VSPK from the development release
    from vspk import v5_0 as vsdk
except ImportError:
    # If this fails, import the Nuage VSPK from the pip release
    from vspk.vsdk import v5_0 as vsdk


# imported parameters in .ini file :
# section
ini_general_section         = "GENERAL"
# parameters in section
ini_nuage_enterprise        = "Enterprise"
# section
ini_nuage_vsd_section       = "NUAGE_VSD_CONNECTION"
# parameters in section
ini_nuage_deployment_mode   = "DeploymentMode"
ini_nuage_port              = "ApiPort"
ini_nuage_host1             = "IpAddr1"
ini_nuage_host2             = "IpAddr2"
ini_nuage_host3             = "IpAddr3"
# section
ini_nuage_api_section       = "NUAGE_REST_API_DETAILS"
# parameters in section
ini_nuage_username          = 'UserName'
ini_nuage_password          = 'Password'
ini_nuage_organization      = 'Organization'
ini_nuage_domain_filter     = 'DomainFilter'
ini_nuage_pg_filter         = 'PolicyGroupFilter'
# section
ini_state_engine_section    = "STATE_ENGINE_CONNECTION"
# parameters in section
ini_pgsync_api_port         = "StateEnginePort"
ini_pgsync_api_host         = "StateEngineAddr"
# section
ini_api_section             = "API"
# parameters in section
ini_api_bind_address        = "BindAddr"
# section
ini_pan_section             = "PAN"
# parameters in section
ini_panorama_deployment_mode = "DeploymentMode"
ini_panorama_host1          = "PanoramaIpAddr1"
ini_panorama_host2          = "PanoramaIpAddr2"
ini_panorama_port           = "PanoramaPort"
ini_panorama_username       = 'PanoramaUserName'
ini_panorama_password       = 'PanoramaPassword'
# section
ini_f5_section              = 'F5'
# IpAddrX
# UserNameX
# PasswordX


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
    log_file = 'logs/state_engine.log'
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

    # Get parameters from config (.ini file)
    global se
    se = StateEngine()

    ### Init phase
    logger.info("Starting state_engine")
    # Step 1. Fetch Nuage storage engine = Master database
    logger.info("step 1. Fetch ip address / policy groups mapping table from Nuage")
    # Next Gen
    global nuage_db
    nuage_db = storage_engine_nuage.NuageDatabase(nuage_enterprise=se.nuage_enterprise,
                                                  nuage_domain_filter=se.nuage_domain_filter,
                                                  nuage_pg_filter=se.nuage_pg_filter,
                                                  logger=logger
                                                  )
    nuage_db.import_vsd_pool(name="non-PROD",
                             host_list=se.nuage_host_list,
                             username=se.nuage_username,
                             password=se.nuage_password,
                             organization=se.nuage_organization
                             )
    nuage_db.fetch()

    # Step 2. Fetch other storage engines = Slaves databases
    logger.info("step 2. Fetch storage engines")
    global storage_engine_list
    storage_engine_list = {}
    # PAN db
    global pan_db
    storage_engine_list['PAN'] = []

    pan_db = storage_engine_pan.PanDatabase(nuage_db=nuage_db,
                                            logger=logger)
    storage_engine_list['PAN'].append(pan_db)
    pan_db.import_panorama_pool(name="non-PROD",
                                host_list=se.panorama_host_list,
                                username=se.panorama_username,
                                password=se.panorama_password
                                )
    # load current configuration from devices managed by PANORAMA
    pan_db.fetch()
    # sync current configuration with Nuage
    pan_db.sync()

    # F5 db
    global f5_db
    f5_db = None
    storage_engine_list['F5'] = []

    """
    se.f5_host_list = ["10.5.26.110"]
    f5_db = storage_engine_f5.F5Database(nuage_db=nuage_db,
                                         logger=logger)
    storage_engine_list['F5'].append(f5_db)
    f5_db.import_devices(host_list=se.f5_host_list,
                         username_list=se.f5_username_list,
                         password_list=se.f5_password_list)
    f5_db.fetch()
    f5_db.sync()
    """

    # Step 3. Intialize the queue of syncing request
    global sync_queue
    sync_queue = []

    global sync_in_progress
    sync_in_progress = [0]

    # Step 4. Start API
    logger.info("step 3. Start API")
    logger.warning("state engine started")
    state_engine_listener.run(debug=debug,
                              host=se.state_engine_host,
                              port=se.state_engine_port,
                              use_reloader=False)
    # use_reloader - whether to reload and fork the process on exception


def get_args():
    """
    Supports the command-line arguments listed below.
    """

    parser = argparse.ArgumentParser(description="Run the state_engine.")
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
                        help='File to log to',
                        dest='logfile',
                        type=str,
                        default="state_engine.log")
    parser.add_argument('-p', '--ini-file',
                        required=False,
                        help='File that contain parameters',
                        dest='inifile',
                        type=str,
                        default="nuage-pgsync.ini")
    args = parser.parse_args()
    return args


def setup_logging(debug, verbose, log_file):
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
    return logging.getLogger(__name__)


class StateEngine(object):
    def __init__(self):
        # Initialize Defaults
        self.nuage_organization = 'csp'
        self.nuage_port = '8443'
        self.nuage_password = None
        self.nuage_username = 'csproot'
        self.nuage_deployment_mode = 'standalone'
        self.nuage_host_list = []
        self.nuage_enterprise = None
        self.nuage_domain_filter = None
        self.nuage_pg_filter = None
        self.state_engine_host = '127.0.0.1'
        self.state_engine_port = '80'
        self.panorama_deployment_mode = 'standalone'
        self.panorama_host_list = []
        self.panorama_port = None
        self.panorama_username = None
        self.panorama_password = None
        self.f5_host_list = []
        self.f5_port = '443'
        self.f5_username_list = []
        self.f5_password_list = []

        # Get attributes from .ini file
        self.parse_file()

    def parse_file(self):
        logger.info("INI file: get parameters")
        # GENERAL
        if config.has_section(ini_general_section):
            # Enterprise
            if config.has_option(ini_general_section, ini_nuage_enterprise):
                self.nuage_enterprise = config.get(ini_general_section, ini_nuage_enterprise)
            else:
                logger.error("No Enterprise in GENERAL Section")
                raise SyntaxError("No Enterprise in GENERAL Section")
        else:
            logger.error("No GENERAL Section")
            raise SyntaxError("No GENERAL Section")
        # NUAGE_VSD_CONNECTION
        if config.has_section(ini_nuage_vsd_section):
            # ApiPort
            if config.has_option(ini_nuage_vsd_section, ini_nuage_port):
                self.nuage_port = config.get(ini_nuage_vsd_section, ini_nuage_port)
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
        else:
            logger.error("No VSD's Connection Details Section")
            raise SyntaxError("No VSD's Connection Details Section")
        # NUAGE_REST_API_DETAILS
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
            # DomainFilter
            if config.has_option(ini_nuage_api_section, ini_nuage_domain_filter):
                self.nuage_domain_filter = config.get(ini_nuage_api_section, ini_nuage_domain_filter)
                if self.nuage_domain_filter == 'none':
                    # none is a specific keyword for no filter
                    self.nuage_domain_filter = None
            # PolicyGroupFilter
            if config.has_option(ini_nuage_api_section, ini_nuage_pg_filter):
                self.nuage_pg_filter = config.get(ini_nuage_api_section, ini_nuage_pg_filter)
                if self.nuage_pg_filter == 'none':
                    # none is a specific keyword for no filter
                    self.nuage_pg_filter = None
        else:
            logger.warning("No VSD's REST API Details Section")
        # STATE_ENGINE_CONNECTION
        if config.has_section(ini_state_engine_section):
            # StateEnginePort
            if config.has_option(ini_state_engine_section, ini_pgsync_api_port):
                self.state_engine_port = config.get(ini_state_engine_section, ini_pgsync_api_port)
        else:
            logger.error("No State Engine's Connection Details Section")
        # API
        if config.has_section(ini_api_section):
            # BindAddr
            if config.has_option(ini_api_section, ini_api_bind_address):
                self.state_engine_host = config.get(ini_api_section, ini_api_bind_address)
        else:
            logger.error("No State Engine's Connection Details Section")
        # PAN
        if config.has_section(ini_pan_section):
            # PanoramaPort
            if config.has_option(ini_pan_section, ini_panorama_port):
                self.panorama_port = config.get(ini_pan_section, ini_panorama_port)
            # DeploymentMode
            if config.has_option(ini_pan_section, ini_panorama_deployment_mode):
                self.panorama_deployment_mode = config.get(ini_pan_section, ini_panorama_deployment_mode)
            if self.panorama_deployment_mode == 'cluster':
                logger.info("PANORAMA in Cluster mode, adding all 2 IP's")
                self.panorama_host_list.append(config.get(ini_pan_section, ini_panorama_host1))
                self.panorama_host_list.append(config.get(ini_pan_section, ini_panorama_host2))
            else:
                logger.info("PANORAMA in Standalone mode, adding only one IP")
                self.panorama_host_list.append(config.get(ini_pan_section, ini_panorama_host1))
            # UserName
            if config.has_option(ini_pan_section, ini_panorama_username):
                self.panorama_username = config.get(ini_pan_section, ini_panorama_username)
            # Password
            if config.has_option(ini_pan_section, ini_panorama_password):
                self.panorama_password = config.get(ini_pan_section, ini_panorama_password)
        else:
            logger.warning("No PAN's Connection Details Section")
        # F5
        if config.has_section(ini_f5_section):
            i = 0
            f5_current_device = True

            while f5_current_device:
                i += 1
                ini_f5_current_host = "IpAddr" + str(i)
                ini_f5_current_username = "UserName" + str(i)
                ini_f5_current_password = "Password" + str(i)

                # IpAddr
                if config.has_option(ini_f5_section, ini_f5_current_host):
                    self.f5_host_list.append(config.get(ini_f5_section, ini_f5_current_host))
                else:
                    # no more F5 device
                    f5_current_device = False
                    continue
                # UserName
                if config.has_option(ini_f5_section, ini_f5_current_username):
                    self.f5_username_list.append(config.get(ini_f5_section, ini_f5_current_username))
                # Password
                if config.has_option(ini_f5_section, ini_f5_current_password):
                    self.f5_password_list.append(config.get(ini_f5_section, ini_f5_current_password))
        else:
            logger.warning("No F5's Connection Details Section")

    def get_json_format(self):
        data = {}
        data['NUAGE'] = {}
        data['NUAGE']['enterprise'] = self.nuage_enterprise
        data['NUAGE']['organization'] = self.nuage_organization
        data['NUAGE']['port'] = self.nuage_port
        data['NUAGE']['username'] = self.nuage_username
        data['NUAGE']['hosts'] = self.nuage_host_list
        data['NUAGE']['domain_filter'] = self.nuage_domain_filter
        data['NUAGE']['pg_filter'] = self.nuage_pg_filter
        data['API'] = {}
        data['API']['bind_address'] = self.state_engine_host
        data['API']['port'] = self.state_engine_port
        data['PANORAMA'] = {}
        data['PANORAMA']['hosts'] = self.panorama_host_list
        data['PANORAMA']['port'] = self.panorama_port
        data['PANORAMA']['username'] = self.panorama_username
        data['F5'] = {}
        data['F5']['hosts'] = self.f5_host_list
        data['F5']['port'] = self.f5_port
        data['F5']['username'] = self.f5_username_list
        return data


def output_txt_response_format(data, code, headers=None):
    resp = make_response(data, code)
    resp.headers.extend(headers or {})
    return resp


def output_json_response_format(data, code, headers=None):
    resp = make_response(json.dumps(data), code)
    resp.headers.extend(headers or {})
    return resp


class ApiHealthcheck(Resource):
    @staticmethod
    def get():
        return "OK", 200


class ApiConfig(Resource):
    @staticmethod
    def get():
        return se.get_json_format(), 200


class Generic:
    @staticmethod
    def sanity_check_enterprise(vsd_id):
        if vsd_id != nuage_db.id:
            logger.info("%s::%s: object's enterprise is out of scope: enterprise_id=%s" %
                        (__class__.__name__, __name__, vsd_id))
            return False
        else:
            return True

    @staticmethod
    def sanity_check_domain(vsd_id):
        cur_domain = storage_engine_nuage.NuageGenericDomain(vsd_id=vsd_id,
                                                             logger=logger)
        nuage_db.create_child(cur_domain)
        cur_domain.fetch()
        cur_domain_name = cur_domain.name
        cur_domain.delete()
        if cur_domain_name is None or ini_nuage_domain_filter not in cur_domain_name:
            # Domain is out of scope
            logger.info("%s::%s: object's domain is out of scope: name=%s; id=%s" %
                        (__class__.__name__, __name__, cur_domain_name, vsd_id))

            return False
        else:
            # Domain should be in database
            logger.error("%s::%s: unknown policy group's domain, reset database: name=%s; id=%s" %
                         (__class__.__name__, __name__, cur_domain_name, vsd_id))
            return True

    @staticmethod
    def reset_nuage_storage_database(vsd_id):
        logger.info("%s::%s: reset database, expected object to load: %s" % (__class__.__name__, __name__, vsd_id))
        nuage_db.flush()
        nuage_db.fetch()

    @staticmethod
    def log_object_not_found_in_nuage(name, vsd_id):
        logger.warning("%s::%s: Object not found in Nuage: name=%s; id=%s" %
                       (__class__.__name__, __name__, name, vsd_id))

    @staticmethod
    def log_nuage_storage_engine_already_synchronized(name, vsd_id):
        logger.warning("%s::%s: Nuage storage database already synchronized: name=%s; id=%s" %
                       (__class__.__name__, __name__, name, vsd_id))

    @staticmethod
    def sync_storage_databases():
        if len(sync_queue) <= 1:
            # value 0: no current sync in progress
            t = threading.Thread(target=Generic.thread_sync_storage_databases, name=str(uuid.uuid4()))
            sync_queue.append(t)
            logger.info("%s::%s: NEW THREAD, database changes will be sync by the new thread in sync_queue: id=%s" %
                        (__class__.__name__, __name__, t.name))

            t.start()
        else:
            # value 2+: the 2nd thread in queue will include changes for this sync_storage_databases request
            logger.info("%s::%s: PASS THREAD, sync_queue full: nb=%s" %
                        (__class__.__name__, __name__, len(sync_queue)))

    @staticmethod
    def thread_sync_storage_databases():
        """
        One sync at a time is possible.
        Only 2 threads are in sync_queue: #0 in current sync operation, #1 that will wait for its turn to sync
        :return:
        """
        try:
            # be in queue
            while len(sync_queue) == 2 and sync_in_progress[0] == 1:
                sleep(1)
                logger.info("%s::%s: WAIT THREAD, current sync in progress, thread is waiting in queue" %
                            (__class__.__name__, __name__))
        except Exception as e:
            logger.error("%s::%s: ERROR THREAD, error raised by the thread in queue. Error: %s" %
                         (__class__.__name__, __name__, e))
            sync_queue.pop(0)
            return

        # Start sync
        logger.info("%s::%s: START THREAD, thread chose to start" %
                    (__class__.__name__, __name__))
        sync_in_progress[0] = 1

        try:
            # sync
            logger.info("%s::%s: SYNC THREAD, thread start to sync all databases" %
                        (__class__.__name__, __name__))
            for storage_engine_type in storage_engine_list.values():
                for storage_engine in storage_engine_type:
                    storage_engine.sync()
        except Exception as e:
            logger.error("%s::%s: ERROR THREAD, error raised by the thread during sync. Error: %s" %
                         (__class__.__name__, __name__, e))
            sync_queue.pop(0)
            sync_in_progress[0] = 0
        else:
            # Ending normaly
            logger.info("%s::%s: STOP THREAD, thread ended to sync all databases" %
                        (__class__.__name__, __name__))
        # End sync
        sync_queue.pop(0)
        sync_in_progress[0] = 0

    @staticmethod
    def sync_f5_storage_databases():
        logger.info("%s::%s: synchronize F5 databases" % (__class__.__name__, __name__))
        Generic.sync_storage_databases()
        # TODO change to not sync to PAN
        """
        for storage_engine_type in storage_engine_list.values():
            for storage_engine in storage_engine_type:
                storage_engine.sync()
        """


class ApiNuagePolicyGroupTemplateCreate(Resource):
    @staticmethod
    def put():
        args = parser_generic.parse_args()
        pgt_vsd_id = args['ID']
        pgt_name = args['name']
        ent_vsd_id = args['sourceEnterpriseID']
        dt_vsd_id = args['parentID']

        # Sanity check on enterprise
        if not Generic.sanity_check_enterprise(ent_vsd_id):
            return "no database update needed", 200

        # load database
        db_pgt = nuage_db.get_policy_group_template(vsd_id=pgt_vsd_id)
        if db_pgt is None:
            # unknown policy group template
            db_dt = nuage_db.get_domain_template(vsd_id=dt_vsd_id)
            if db_dt is None:
                # unknown domain template
                Generic.reset_nuage_storage_database(dt_vsd_id)
                return "database updated", 201
            else:
                # Domain in db
                # new PolicyGroupTemplate
                db_pgt = storage_engine_nuage.NuagePolicyGroupTemplate(vsd_id=pgt_vsd_id,
                                                                       logger=logger)
                db_pgt.name = pgt_name
                db_dt.create_child(db_pgt)
                return "nuage database updated", 201
        else:
            # policy group template already exist
            Generic.log_nuage_storage_engine_already_synchronized(name=pgt_name, vsd_id=pgt_vsd_id)
            return "database already synchronized", 200


class ApiNuagePolicyGroupTemplateUpdate(Resource):
    @staticmethod
    def put():
        args = parser_generic.parse_args()
        pgt_vsd_id = args['ID']
        pgt_name = args['name']
        dt_vsd_id = args['parentID']
        ent_vsd_id = args['sourceEnterpriseID']

        # Sanity check on enterprise
        if not Generic.sanity_check_enterprise(ent_vsd_id):
            return "no database update needed", 200

        # load domain in database
        db_pgt = nuage_db.get_policy_group_template(vsd_id=pgt_vsd_id)
        if db_pgt is None:
            # unknown policy group template
            db_dt = nuage_db.get_domain_template(vsd_id=dt_vsd_id)
            if db_dt is None:
                # unknown domain template
                Generic.reset_nuage_storage_database(dt_vsd_id)
                return "database updated", 201
            else:
                # domain Template in db
                logger.info("%s: Unexpected state for policy group template '%s %s', fetch domain template '%s'" %
                            (__class__.__name__, pgt_vsd_id, pgt_name, dt_vsd_id))
                # update db from current config
                db_dt.fetch()
                # load policy_group from Nuage storage database
                db_pgt = storage_engine_nuage.NuagePolicyGroupTemplate(vsd_id=pgt_vsd_id,
                                                                       logger=logger)
                if db_pgt is None:
                    Generic.log_object_not_found_in_nuage(pgt_name, pgt_vsd_id)
                    return "no database update needed", 200
                else:
                    return "database updated", 201
        else:
            # check for name update
            if db_pgt.name != pgt_name:
                # Update Nuage storage database
                logger.info("%s: update name: pg_id=%s; old_pg_name=%s; new_pg_name=%s" %
                            (__class__.__name__, pgt_vsd_id, db_pgt.name, pgt_name))
                db_pgt.name = pgt_name
                return "database updated", 201
            else:
                return "no database update needed", 200


class ApiNuagePolicyGroupTemplateDelete(Resource):
    @staticmethod
    def put():
        args = parser_generic.parse_args()
        pgt_vsd_id = args['ID']
        pgt_name = args['name']
        ent_vsd_id = args['sourceEnterpriseID']

        # Sanity check on enterprise
        if not Generic.sanity_check_enterprise(ent_vsd_id):
            return "no database update needed", 200

        # load policy group template in database
        db_pgt = nuage_db.get_policy_group_template(vsd_id=pgt_vsd_id)
        if db_pgt is None:
            # unknown policy group template
            Generic.log_nuage_storage_engine_already_synchronized(name=pgt_name, vsd_id=pgt_vsd_id)
            return "database already synchronized", 201
        else:
            # existing policy group template
            db_pgt.delete()
            logger.info("%s::%s: database updated: name=%s; id=%s" %
                        (__class__.__name__, __name__, pgt_name, pgt_vsd_id))
            return "database updated", 201


class ApiNuagePolicyGroupCreate(Resource):
    @staticmethod
    def put():
        # get parameter in payload
        args = parser_policygroup.parse_args()
        name = str(args['name'])
        policy_group_id = str(args['policyGroupID'])
        pg_vsd_id = args['ID']
        domain_vsd_id = args['parentID']
        pgt_vsd_id = args['templateID']
        ent_vsd_id = args['sourceEnterpriseID']

        # Sanity check on enterprise
        if not Generic.sanity_check_enterprise(ent_vsd_id):
            return "no database update needed", 200

        # load policy_group from Nuage storage database
        db_pg = nuage_db.get_policy_group(vsd_id=pg_vsd_id)
        if db_pg is None:
            # unknown policy group
            db_domain = nuage_db.get_domain(vsd_id=domain_vsd_id)
            if db_domain is None:
                # unknown domain
                if not Generic.sanity_check_domain(domain_vsd_id):
                    return "no database update needed", 200
                else:
                    Generic.reset_nuage_storage_database(domain_vsd_id)
                    Generic.sync_f5_storage_databases()
                    return "database updated", 201
            else:
                # create policy group and fetch
                logger.info("%s::%s: create and fetch policy group: pg_id=%s; pg_name=%s; domain_id=%s" %
                            (__class__.__name__, __name__, policy_group_id, name, domain_vsd_id))
                cur_pg = storage_engine_nuage.NuagePolicyGroup(vsd_id=pg_vsd_id,
                                                               logger=logger
                                                               )
                cur_pg.name = name
                db_domain.create_child(cur_pg)

                # Associate policy_group_template
                if pgt_vsd_id != "null":
                    for domain_template in nuage_db.domain_templates:
                        if pgt_vsd_id in domain_template.children['policy_group_template'].keys() and \
                                pgt_vsd_id not in cur_pg.associated_objects['policy_group_template'].keys():
                            # known policy_group_template
                            # Create a relation with policy_group_template
                            cur_pg.assign(domain_template.children['policy_group_template'][pgt_vsd_id])

                        else:
                            # Policy Group Template not found
                            # Fetch domain_template
                            nuage_db.fetch()
                # Sync
                Generic.sync_f5_storage_databases()
                return "database updated", 201
        else:
            Generic.log_nuage_storage_engine_already_synchronized(name, pg_vsd_id)
            return "database already synchronized", 200


class ApiNuagePolicyGroupUpdate(Resource):
    @staticmethod
    def put():
        # get parameter in payload
        args = parser_policygroup.parse_args()
        name = str(args['name'])
        vsd_id = args['ID']
        domain_vsd_id = args['parentID']
        ent_vsd_id = args['sourceEnterpriseID']

        # Sanity check on enterprise
        if not Generic.sanity_check_enterprise(ent_vsd_id):
            return "no database update needed", 200

        # load policy_group from Nuage storage database
        pg_db = nuage_db.get_policy_group(vsd_id=vsd_id)
        if pg_db is None:
            # unknown pg
            domain_db = nuage_db.get_domain(vsd_id=domain_vsd_id)
            if domain_db is None:
                # unknown domain
                if not Generic.sanity_check_domain(vsd_id):
                    return "no database update needed", 200
                else:
                    # fetch database
                    nuage_db.flush()
                    nuage_db.fetch()
                    # load policy_group from Nuage storage database
                    pg_db = nuage_db.get_policy_group(vsd_id=vsd_id)
                    if pg_db is None:
                        Generic.log_object_not_found_in_nuage(name, vsd_id)
                        return "no database update needed", 200
            else:
                # pg in db
                # update db from current config
                pg_db.fetch()
                # Sync
                Generic.sync_storage_databases()
                return "database updated", 201

        # check for name update
        if pg_db.name != name:
            # Update Nuage storage database
            logger.info("%s: update name: pg_id=%s; old_pg_name=%s; new_pg_name=%s" %
                        (__class__.__name__, vsd_id, pg_db.name, name))
            pg_db.name = name
            Generic.sync_storage_databases()
            return "database updated", 201
        else:
            # check for associated ip_address update
            # compare ip_address list in current config and database
            # load old ip_address list from database
            old_ip_address_list = set(pg_db.get_ip_address_list())
            # clear associated vPorts
            for vport in list(pg_db.vports):
                pg_db.detach(vport)
            # fetch from current configuration
            logger.info("%s: fetch policy group: pg_id=%s; pg_name=%s" %
                        (__class__.__name__, vsd_id, name))
            pg_db.fetch()
            # load current ip_address list from database
            cur_ip_address_list = set(pg_db.get_ip_address_list())
            # compare new and current ip_address list
            if cur_ip_address_list == old_ip_address_list:
                Generic.log_nuage_storage_engine_already_synchronized(name, vsd_id)
                return "database already synchronized", 200
            else:
                # log new ip address
                ip_address_list_to_attach = list(cur_ip_address_list - old_ip_address_list)
                if len(ip_address_list_to_attach) > 0:
                    logger.info("%s: pg_id=%s ; pg_name=%s ; added ip_address=%s" %
                                (__class__.__name__, vsd_id, name, ip_address_list_to_attach))
                # log deleted ip address
                ip_address_list_to_detach = list(old_ip_address_list - cur_ip_address_list)
                if len(ip_address_list_to_detach) > 0:
                    logger.info("%s: pg_id=%s ; pg_name=%s ; deleted ip_address=%s" %
                                (__class__.__name__, vsd_id, name, ip_address_list_to_detach))
                # Sync
                Generic.sync_storage_databases()
                return "database updated", 201


class ApiNuagePolicyGroupUpdateDirectAttach(Resource):
    @staticmethod
    def put():
        """
        Used for unit tests only
        Same as ApiNuagePolicyGroupUpdate() but the associated vPort is already in the 'vport_vsd_id' parameter
        :return:
        """
        # ToDo error unknown policy group
        # get parameter in payload
        args = parser_policygroup_direct_attach.parse_args()
        name = str(args['name'])
        vsd_id = args['ID']
        domain_vsd_id = args['parentID']
        ent_vsd_id = args['sourceEnterpriseID']
        vport_vsd_id = args['vportID']

        # Sanity check on enterprise
        if not Generic.sanity_check_enterprise(ent_vsd_id):
            return "no database update needed", 200

        # load policy_group from Nuage storage database
        pg_db = nuage_db.get_policy_group(vsd_id=vsd_id)
        if pg_db is None:
            # unknown pg
            domain_db = nuage_db.get_domain(vsd_id=domain_vsd_id)
            if domain_db is None:
                # unknown domain
                return "error, unknown policy group and unknown domain", 404
            else:
                return "error, unknown policy group", 404
        else:
            # pg in db
            if vport_vsd_id in pg_db.associated_objects['vport'].keys():
                # already attached vport
                pass
            elif vport_vsd_id in pg_db.parent.children['vport'].keys():
                # existing vport in db and attached to the domain
                vport_db = pg_db.parent.children['vport'][vport_vsd_id]
                # attach vPort to policy group
                pg_db.assign(vport_db)
            else:
                # unknown vport in db
                return "error, unknown vport", 404
            # Sync
            Generic.sync_storage_databases()
            return "database updated", 201


class ApiNuagePolicyGroupDelete(Resource):
    @staticmethod
    def put():
        # get parameter in payload
        args = parser_policygroup.parse_args()
        name = str(args['name'])
        vsd_id = args['ID']

        # load policy_group from Nuage storage database
        db_pg = nuage_db.get_policy_group(vsd_id=vsd_id)
        if db_pg is None:
            # Database and current Nuage configuration already synchronized
            Generic.log_nuage_storage_engine_already_synchronized(name='unknown', vsd_id=vsd_id)
            return "database already synchronized", 200
        else:
            # existing policy group
            # delete policy group
            logger.info("%s: delete policy group: pg_id=%s; pg_name=%s" %
                        (__class__.__name__, vsd_id, name))
            db_pg.delete()
            # Sync
            Generic.sync_f5_storage_databases()
            return "database updated", 201


class ApiNuageVminterfaceCreate(Resource):
    @staticmethod
    def put():
        args = parser_vminterface.parse_args()
        ip_address = args['IPAddress']
        vport_vsd_id = args['VPortID']
        domain_vsd_id = args['domainID']

        # load vport current configuration
        cur_vport = nuage_db.get_vport(vsd_id=vport_vsd_id)
        if cur_vport is None:
            # unknown vport
            db_domain = nuage_db.get_domain(vsd_id=domain_vsd_id)
            if db_domain is None:
                # unknown domain
                if not Generic.sanity_check_domain(domain_vsd_id):
                    return "no database update needed", 200
                else:
                    Generic.reset_nuage_storage_database(domain_vsd_id)
                    cur_vport = nuage_db.get_vport(vsd_id=vport_vsd_id)
                    if cur_vport is None:
                        Generic.log_object_not_found_in_nuage(name=ip_address, vsd_id=vport_vsd_id)
                        return "no database update needed", 200
            else:
                # vport unknown but parent domain in db
                # fetch domain
                db_domain.fetch()
                cur_vport = nuage_db.get_vport(vsd_id=vport_vsd_id)
                if cur_vport is None:
                    Generic.log_object_not_found_in_nuage(name=ip_address, vsd_id=vport_vsd_id)
                    return "no database update needed", 200
                else:
                    Generic.sync_storage_databases()
                    return "database updated", 201
        else:
            # known vPort
            # add VM interface IP
            cur_vport.ip_address_list.append(ip_address)
            Generic.sync_storage_databases()
            return "database updated", 201


class ApiNuageVminterfaceDelete(Resource):
    @staticmethod
    def put():
        args = parser_vminterface.parse_args()
        ip_address = args['IPAddress']
        vsd_id = args['VPortID']

        # load vport in database
        db_vport = nuage_db.get_vport(vsd_id=vsd_id)
        if db_vport is None:
            # unknown vport
            Generic.log_nuage_storage_engine_already_synchronized(name=ip_address, vsd_id=vsd_id)
            return "database already synchronized", 201
        else:
            # existing vport
            db_vport.fetch()
            Generic.sync_f5_storage_databases()
            return "database updated", 201


class ApiNuageVportCreate(Resource):
    @staticmethod
    def put():
        args = parser_vport.parse_args()
        vsd_id = args['ID']
        domain_vsd_id = args['domainID']
        name = args['name']
        vport_type = args['type']

        # load vport current configuration
        cur_vport = nuage_db.get_vport(vsd_id=vsd_id)
        if cur_vport is None:
            # unknown vport
            db_domain = nuage_db.get_domain(vsd_id=domain_vsd_id)
            if db_domain is None:
                # unknown domain
                if not Generic.sanity_check_domain(domain_vsd_id):
                    return "no database update needed", 200
                else:
                    Generic.reset_nuage_storage_database(domain_vsd_id)
                    cur_vport = nuage_db.get_vport(vsd_id=vsd_id)
                    if cur_vport is None:
                        Generic.log_object_not_found_in_nuage(name=name, vsd_id=vsd_id)
                        return "no database update needed", 200
            else:
                # vport unknown but parent domain in db
                # attach to domain
                # new PolicyGroupTemplate
                db_vport = storage_engine_nuage.NuageVPort(vsd_id=vsd_id,
                                                           vport_type=vport_type,
                                                           logger=logger)
                db_domain.create_child(db_vport)
                return "no database update needed", 200

        else:
            # known vPort
            return "error, object already exists", 404


class ApiNuageVportDelete(Resource):
    @staticmethod
    def put():
        args = parser_vport.parse_args()
        vsd_id = args['ID']
        name = args['name']

        # load vport in database
        db_vport = nuage_db.get_vport(vsd_id=vsd_id)
        if db_vport is None:
            # unknown vport
            Generic.log_nuage_storage_engine_already_synchronized(name=name, vsd_id=vsd_id)
            return "database already synchronized", 201
        else:
            # existing vport
            db_vport.delete()
            return "no database update needed", 200


class ApiNuageDomainTemplateCreate(Resource):
    @staticmethod
    def put():
        args = parser_generic.parse_args()
        dt_vsd_id = args['ID']
        dt_name = args['name']
        ent_vsd_id = args['sourceEnterpriseID']

        # Sanity check on enterprise
        if not Generic.sanity_check_enterprise(ent_vsd_id):
            return "no database update needed", 200

        # load Domain current configuration
        db_dt = nuage_db.get_domain_template(vsd_id=dt_vsd_id)
        if db_dt is None:
            # new Domain
            db_dt = storage_engine_nuage.NuageDomainTemplate(vsd_id=dt_vsd_id,
                                                             domain_type='domaintemplate',
                                                             logger=logger)
            db_dt.name = dt_name
            nuage_db.create_child(db_dt)
            return "nuage database updated", 201
        else:
            # Domain already exist
            Generic.log_nuage_storage_engine_already_synchronized(name=dt_name, vsd_id=dt_vsd_id)
            return "Domain_template already exist in database", 200


class ApiNuageDomainTemplateUpdate(Resource):
    @staticmethod
    def put():
        args = parser_generic.parse_args()
        dt_vsd_id = args['ID']
        dt_name = args['name']
        ent_vsd_id = args['sourceEnterpriseID']

        # Sanity check on enterprise
        if not Generic.sanity_check_enterprise(ent_vsd_id):
            return "no database update needed", 200

        # load domain in database
        db_domain = nuage_db.get_domain_template(vsd_id=dt_vsd_id)
        if db_domain is None:
            # unknown domain
            Generic.reset_nuage_storage_database(dt_vsd_id)
            # Update storage db
            Generic.sync_storage_databases()
            return "database updated", 201
        else:
            # existing domain
            db_domain.fetch()
            logger.info("%s: database updated: name=%s; id=%s" %
                        (__class__.__name__, dt_name, dt_vsd_id))
            return "database updated", 201


class ApiNuageDomainTemplateDelete(Resource):
    @staticmethod
    def put():
        args = parser_generic.parse_args()
        dt_vsd_id = args['ID']
        dt_name = args['name']
        ent_vsd_id = args['sourceEnterpriseID']

        # Sanity check on enterprise
        if not Generic.sanity_check_enterprise(ent_vsd_id):
            return "no database update needed", 200

        # load domain in database
        db_domain = nuage_db.get_domain_template(vsd_id=dt_vsd_id)
        if db_domain is None:
            # unknown domain
            Generic.log_nuage_storage_engine_already_synchronized(name=dt_name, vsd_id=dt_vsd_id)
            return "database already synchronized", 201
        else:
            # existing domain
            db_domain.delete()
            logger.info("%s::%s: database updated: name=%s; id=%s" %
                        (__class__.__name__, __name__, dt_name, dt_vsd_id))
            return "database updated", 201


class ApiNuageDomainCreate(Resource):
    @staticmethod
    def put():
        args = parser_domain.parse_args()
        domain_vsd_id = args['ID']
        domain_name = args['name']
        domain_template_vsd_id = args['templateID']
        ent_vsd_id = args['sourceEnterpriseID']

        # Sanity check on enterprise
        if not Generic.sanity_check_enterprise(ent_vsd_id):
            return "no database update needed", 200

        # Domain belong to db's enterprise
        # load Domain current configuration
        cur_domain = nuage_db.get_domain(vsd_id=domain_vsd_id)
        if cur_domain is None:
            # new Domain
            logger.info("%s::%s: create new domain: "
                        "id=%s; name=%s; enterprise_id=%s" %
                        (__class__.__name__, __name__, domain_vsd_id, domain_name, ent_vsd_id))
            db_domain = storage_engine_nuage.NuageDomain(vsd_id=domain_vsd_id,
                                                         domain_type='domain',
                                                         logger=logger
                                                         )
            db_domain.name = domain_name
            nuage_db.create_child(db_domain)
            # Assign domain template
            if nuage_db.children['domain_template'][domain_template_vsd_id] is not None:
                db_domain.assign(nuage_db.children['domain_template'][domain_template_vsd_id])
            else:
                db_domain.fetch()
            return "no database update needed", 200
        else:
            # Domain already exist
            Generic.log_nuage_storage_engine_already_synchronized(name=domain_name, vsd_id=domain_vsd_id)
            return "database already synchronized", 200


class ApiNuageDomainUpdate(Resource):
    @staticmethod
    def put():
        args = parser_generic.parse_args()
        domain_vsd_id = args['ID']
        ent_vsd_id = args['sourceEnterpriseID']

        # Sanity check on enterprise
        if not Generic.sanity_check_enterprise(ent_vsd_id):
            return "no database update needed", 200

        # load domain in database
        db_domain = nuage_db.get_domain(vsd_id=domain_vsd_id)
        if db_domain is None:
            # unknown domain
            if not Generic.sanity_check_domain(domain_vsd_id):
                return "no database update needed", 200
            else:
                # fetch database
                Generic.reset_nuage_storage_database(domain_vsd_id)
                Generic.sync_storage_databases()
                return "database updated", 201
        else:
            # existing domain
            db_domain.fetch()
            # Sync
            Generic.sync_storage_databases()
            return "database updated", 201


class ApiNuageDomainDelete(Resource):
    @staticmethod
    def put():
        args = parser_generic.parse_args()
        domain_vsd_id = args['ID']
        domain_name = args['name']
        ent_vsd_id = args['sourceEnterpriseID']

        # Sanity check on enterprise
        if not Generic.sanity_check_enterprise(ent_vsd_id):
            return "no database update needed", 200

        # load domain in database
        db_domain = nuage_db.get_domain(vsd_id=domain_vsd_id)
        if db_domain is None:
            # unknown domain
            Generic.log_nuage_storage_engine_already_synchronized(domain_name, domain_vsd_id)
            return "database already synchronized", 201
        else:
            # domain in db
            db_domain.delete()
            Generic.sync_storage_databases()
            return "database updated", 201


class ApiNuageDbDump(Resource):
    @staticmethod
    def get():
        # set output format
        api.representations.update({'application/json': output_json_response_format})

        return nuage_db.dump_json_format(), 200


class ApiNuageDbFetch(Resource):
    @staticmethod
    def get():
        # set output format
        api.representations.update({'application/json': output_json_response_format})

        nuage_db.fetch()
        return "OK", 200


class ApiNuageDbFlush(Resource):
    @staticmethod
    def get():
        # set output format
        api.representations.update({'application/json': output_json_response_format})

        nuage_db.flush()
        return "OK", 200


class ApiNuageDbDomainDump(Resource):
    @staticmethod
    def get(domain_name):
        # set output format
        api.representations.update({'application/json': output_json_response_format})
        domain = nuage_db.get_domain(domain_name)
        if domain is None:
            return "unknown domain", 200
        else:
            return domain.dump_json_format(), 200


class ApiNuageDbDomainGet(Resource):
    @staticmethod
    def get(domain_name):
        # set output format
        api.representations.update({'application/json': output_json_response_format})
        domain = nuage_db.get_domain(domain_name)
        if domain is None:
            return "unknown domain", 200
        else:
            return domain.get_json_format(), 200


class ApiNuageDbDomainFetch(Resource):
    @staticmethod
    def get(domain_name):
        domain = nuage_db.get_domain(domain_name)
        if domain is None:
            return "unknown domain", 200
        else:
            domain.fetch()
            return "OK", 200


class ApiNuageDbPolicyGroupDump(Resource):
    @staticmethod
    def get(domain_name, policy_group_name):
        # set output format
        api.representations.update({'application/json': output_json_response_format})
        policy_group = nuage_db.get_policy_group(domain_name, policy_group_name)
        if policy_group is None:
            return "unknown policy_group", 200
        else:
            return policy_group.dump_json_format(), 200


class ApiNuageDbPolicyGroupGet(Resource):
    @staticmethod
    def get(domain_name, policy_group_name):
        # set output format
        api.representations.update({'application/json': output_json_response_format})
        policy_group = nuage_db.get_policy_group(domain_name, policy_group_name)
        if policy_group is None:
            return "unknown policy_group", 200
        else:
            return policy_group.get_json_format(), 200


class ApiNuageDbPolicyGroupFetch(Resource):
    @staticmethod
    def get(domain_name, policy_group_name):
        policy_group = nuage_db.get_policy_group(domain_name, policy_group_name)
        if policy_group is None:
            return "unknown policy_group", 200
        else:
            policy_group.fetch()
            return "OK", 200


class ApiNuageDbPolicyGroupTemplateIpAddresses(Resource):
    @staticmethod
    def get(domain_template_name, policy_group_template_name):
        policy_group_template = nuage_db.get_policy_group_template_ip_address_list(domain_template_name,
                                                                                   policy_group_template_name)
        if policy_group_template is None:
            return "unknown policy_group", 200
        else:
            return policy_group_template.get_ip_address_list(), 200


class ApiNuageDbIpPolicyGroupMappings(Resource):
    @staticmethod
    def get():
        return nuage_db.get_ip_policy_group_mapping(), 200


class ApiNuageDbIpPolicyGroupMapping(Resource):
    @staticmethod
    def get(ip_address):
        return nuage_db.get_ip_policy_group_mapping(ip_address_filter=ip_address), 200


class ApiPanDbSync(Resource):
    @staticmethod
    def get():

        # set output format
        api.representations.update({'application/json': output_json_response_format})

        pan_db.sync()

        return "OK", 200


class ApiPanDbDump(Resource):
    @staticmethod
    def get():

        # set output format
        api.representations.update({'application/json': output_json_response_format})

        return pan_db.dump_json_format(), 200


class ApiPanDbFetch(Resource):
    @staticmethod
    def get():
        pan_db.fetch()
        return "OK", 200


class ApiPanDbDeviceDump(Resource):
    @staticmethod
    def get(host):
        # set output format
        api.representations.update({'application/json': output_json_response_format})
        device = pan_db.get_host(host)
        if device is None:
            return "unknown host", 200
        else:
            return device.dump_json_format(), 200


class ApiPanDbDeviceGet(Resource):
    @staticmethod
    def get(host):
        # set output format
        api.representations.update({'application/json': output_json_response_format})
        device = pan_db.get_host(host)
        if device is None:
            return "unknown host", 200
        else:
            return device.get_json_format(), 200


class ApiPanDbDeviceFetch(Resource):
    @staticmethod
    def get(host):
        device = pan_db.get_host(host)
        if device is None:
            return "unknown host", 200
        else:
            device.fetch()
            return "OK", 200


class ApiPanDbVSysDump(Resource):
    @staticmethod
    def get(host, vsys_id):
        # set output format
        api.representations.update({'application/json': output_json_response_format})
        vsys = pan_db.get_vsys(host, vsys_id)
        if vsys is None:
            return "unknown vsys", 200
        else:
            return vsys.dump_json_format(), 200


class ApiPanDbVSysGet(Resource):
    @staticmethod
    def get(host, vsys_id):
        # set output format
        api.representations.update({'application/json': output_json_response_format})
        vsys = pan_db.get_vsys(host, vsys_id)
        if vsys is None:
            return "unknown vsys", 200
        else:
            return vsys.get_json_format(), 200


class ApiPanDbVSysFetch(Resource):
    @staticmethod
    def get(host, vsys_id):
        vsys = pan_db.get_vsys(host, vsys_id)
        if vsys is None:
            return "unknown host or vsys", 200
        else:
            vsys.fetch()
            return "OK", 200


class ApiPanFeed(Resource):
    @staticmethod
    def get(feed_list_name):
        # External Dynamic List in format :
        #   <enterprise_name>--<domain_tpl_name>--<pg_tpl_name>

        # set output format
        api.representations.update({'application/json': output_txt_response_format})

        # get domain tpl and pg tpl name
        enterprise_name, domain_tpl_name, pg_tpl_name = feed_list_name.split("--")
        pgt_db = nuage_db.get_policy_group_template(domain_template_name=domain_tpl_name,
                                                    policy_group_template_name=pg_tpl_name)
        if pgt_db is None:
            abort(404, message="policy group template name {} doesn't exist".format(domain_tpl_name, pg_tpl_name))
        else:
            # get feed list in the storage database format
            return storage_engine_pan.StorageEnginePan.get_feedlist_format(pgt_db.get_ip_address_list()), 200


class ApiF5DbSync(Resource):
    @staticmethod
    def get():

        # set output format
        api.representations.update({'application/json': output_json_response_format})

        f5_db.sync()

        return "OK", 200


class ApiF5DbDump(Resource):
    @staticmethod
    def get():

        # set output format
        api.representations.update({'application/json': output_json_response_format})

        return f5_db.dump_json_format(), 200


class ApiF5DbFetch(Resource):
    @staticmethod
    def get():

        # set output format
        api.representations.update({'application/json': output_json_response_format})

        f5_db.fetch()
        return "OK", 200


class ApiF5DbDeviceDump(Resource):
    @staticmethod
    def get(host):
        # set output format
        api.representations.update({'application/json': output_json_response_format})
        device = f5_db.get_host(host)
        if device is None:
            return "unknown host", 200
        else:
            return device.dump_json_format(), 200


class ApiF5DbDeviceGet(Resource):
    @staticmethod
    def get(host):
        # set output format
        api.representations.update({'application/json': output_json_response_format})
        device = f5_db.get_host(host)
        if device is None:
            return "unknown host", 200
        else:
            return device.get_json_format(), 200


class ApiF5DbDeviceFetch(Resource):
    @staticmethod
    def get(host):
        device = f5_db.get_host(host)
        if device is None:
            return "unknown host", 200
        else:
            device.fetch()
            return "OK", 200


class ApiF5DbPartitionDump(Resource):
    @staticmethod
    def get(host, partition_name):
        # set output format
        api.representations.update({'application/json': output_json_response_format})
        partition = f5_db.get_partition(host, partition_name)
        if partition is None:
            return "unknown partition", 200
        else:
            return partition.dump_json_format(), 200


class ApiF5DbPartitionGet(Resource):
    @staticmethod
    def get(host, partition_name):
        # set output format
        api.representations.update({'application/json': output_json_response_format})
        partition = pan_db.get_partition(host, partition_name)
        if partition_name is None:
            return "unknown partition", 200
        else:
            return partition.get_json_format(), 200


class ApiF5DbPartitionFetch(Resource):
    @staticmethod
    def get(host, partition_name):
        partition = f5_db.get_partition(host, partition_name)
        if partition is None:
            return "unknown host or partition", 200
        else:
            partition.fetch()
            return "OK", 200


class ApiF5Feed(Resource):
    @staticmethod
    def get(feed_list_name):
        # External Dynamic List in format :
        #   <enterprise_name>--<domain_tpl_name>--<pg_tpl_name>

        # set output format
        api.representations.update({'application/json': output_txt_response_format})

        # extract domain tpl and pg tpl name
        enterprise_name, domain_tpl_name, pg_tpl_name = feed_list_name.split("--")
        # load objects from db
        pgt_db = nuage_db.get_policy_group_template(domain_template_name=domain_tpl_name,
                                                    policy_group_template_name=pg_tpl_name)
        if pgt_db is None:
            abort(404, message="policy group template name {} doesn't exist".format(domain_tpl_name, pg_tpl_name))
        else:
            # get feed list in the storage database format
            return storage_engine_f5.StorageEngineF5.get_feedlist_format(pgt_db.get_ip_address_list()), 200


class ApiPanFeedSocSimulation(Resource):
    @staticmethod
    def get(feed_list_name):
        # set output format
        api.representations.update({'application/json': output_txt_response_format})

        # set simaulated feed list
        soc_feed_list = []
        soc_feed_list.append("1.1.1.1")
        soc_feed_list.append("2.2.2.2")
        soc_feed_list.append("3.3.3.3")
        return storage_engine_pan.StorageEnginePan.get_feedlist_format(soc_feed_list), 200


class ApiF5FeedSocSimulation(Resource):
    @staticmethod
    def get(feed_list_name):
        # set output format
        api.representations.update({'application/json': output_txt_response_format})

        # set simaulated feed list
        soc_feed_list = []
        soc_feed_list.append("1.1.1.1")
        soc_feed_list.append("2.2.2.2")
        soc_feed_list.append("3.3.3.3")
        return storage_engine_f5.StorageEngineF5.get_feedlist_format(soc_feed_list), 200


# -------------- API --------------
# listener
state_engine_listener = Flask(__name__)
api = Api(state_engine_listener)
# resource routing
api.add_resource(ApiHealthcheck, '/healthcheck')
api.add_resource(ApiConfig, '/config')
# Nuage storage engine
api.add_resource(ApiNuagePolicyGroupTemplateCreate, '/sensor/nuage/policygrouptemplate/CREATE')
api.add_resource(ApiNuagePolicyGroupTemplateUpdate, '/sensor/nuage/policygrouptemplate/UPDATE')
api.add_resource(ApiNuagePolicyGroupTemplateDelete, '/sensor/nuage/policygrouptemplate/DELETE')
api.add_resource(ApiNuagePolicyGroupCreate, '/sensor/nuage/policygroup/CREATE')
api.add_resource(ApiNuagePolicyGroupUpdate, '/sensor/nuage/policygroup/UPDATE')
api.add_resource(ApiNuagePolicyGroupUpdateDirectAttach, '/sensor/nuage/policygroup/UPDATE/direct_attach')
api.add_resource(ApiNuagePolicyGroupDelete, '/sensor/nuage/policygroup/DELETE')
api.add_resource(ApiNuageVminterfaceCreate, '/sensor/nuage/vminterface/CREATE')
api.add_resource(ApiNuageVminterfaceDelete, '/sensor/nuage/vminterface/DELETE')
api.add_resource(ApiNuageVportCreate, '/sensor/nuage/vport/CREATE')
api.add_resource(ApiNuageVportDelete, '/sensor/nuage/vport/DELETE')
api.add_resource(ApiNuageDomainTemplateCreate, '/sensor/nuage/domaintemplate/CREATE')
api.add_resource(ApiNuageDomainTemplateUpdate, '/sensor/nuage/domaintemplate/UPDATE')
api.add_resource(ApiNuageDomainTemplateDelete, '/sensor/nuage/domaintemplate/DELETE')
api.add_resource(ApiNuageDomainCreate, '/sensor/nuage/domain/CREATE')
api.add_resource(ApiNuageDomainUpdate, '/sensor/nuage/domain/UPDATE')
api.add_resource(ApiNuageDomainDelete, '/sensor/nuage/domain/DELETE')
api.add_resource(ApiNuageDbDump, '/database/nuage/dump')
api.add_resource(ApiNuageDbFetch, '/database/nuage/fetch')
api.add_resource(ApiNuageDbFlush, '/database/nuage/flush')
api.add_resource(ApiNuageDbDomainDump, '/database/nuage/domain/<domain_name>/dump')
api.add_resource(ApiNuageDbDomainGet, '/database/nuage/domain/<domain_name>/get')
api.add_resource(ApiNuageDbDomainFetch, '/database/nuage/domain/<domain_name>/fetch')
api.add_resource(ApiNuageDbPolicyGroupDump, '/database/nuage/domain/<domain_name>'
                                            '/pg/<policy_group_name>/dump')
api.add_resource(ApiNuageDbPolicyGroupGet, '/database/nuage/domain/<domain_name>'
                                           '/pg/<policy_group_name>/get')
api.add_resource(ApiNuageDbPolicyGroupFetch, '/database/nuage/domain/<domain_name>'
                                             '/pg/<policy_group_name>/fetch')
api.add_resource(ApiNuageDbPolicyGroupTemplateIpAddresses, '/database/nuage/domain_tpl/<domain_template_name>'
                                                           '/pg_tpl/<policy_group_template_name>')
api.add_resource(ApiNuageDbIpPolicyGroupMappings, '/database/nuage/ip_pg_mapping/all')
api.add_resource(ApiNuageDbIpPolicyGroupMapping, '/database/nuage/ip_pg_mapping/<ip_address>')
# PAN storage engine
api.add_resource(ApiPanDbSync, '/database/pan/sync')
api.add_resource(ApiPanDbDump, '/database/pan/dump')
api.add_resource(ApiPanDbFetch, '/database/pan/fetch')
api.add_resource(ApiPanDbDeviceDump, '/database/pan/device/<host>/dump')
api.add_resource(ApiPanDbDeviceGet, '/database/pan/device/<host>/get')
api.add_resource(ApiPanDbDeviceFetch, '/database/pan/device/<host>/fetch')
api.add_resource(ApiPanDbVSysDump, '/database/pan/device/<host>/vsys/<vsys_id>/dump')
api.add_resource(ApiPanDbVSysGet, '/database/pan/device/<host>/vsys/<vsys_id>/get')
api.add_resource(ApiPanDbVSysFetch, '/database/pan/device/<host>/vsys/<vsys_id>/fetch')
api.add_resource(ApiPanFeed, '/database/pan/edl/<feed_list_name>')
api.add_resource(ApiPanFeedSocSimulation, '/database/pan/soc_feed/<feed_list_name>')
# F5 storage engine
api.add_resource(ApiF5DbSync, '/database/f5/sync')
api.add_resource(ApiF5DbDump, '/database/f5/dump')
api.add_resource(ApiF5DbFetch, '/database/f5/fetch')
api.add_resource(ApiF5DbDeviceDump, '/database/f5/device/<host>/dump')
api.add_resource(ApiF5DbDeviceGet, '/database/f5/device/<host>/get')
api.add_resource(ApiF5DbDeviceFetch, '/database/f5/device/<host>/fetch')
api.add_resource(ApiF5DbPartitionDump, '/database/f5/device/<host>/partition/<partition_name>/dump')
api.add_resource(ApiF5DbPartitionGet, '/database/f5/device/<host>/partition/<partition_name>/get')
api.add_resource(ApiF5DbPartitionFetch, '/database/f5/device/<host>/partition/<partition_name>/fetch')
api.add_resource(ApiF5Feed, '/database/f5/edl/<feed_list_name>')
api.add_resource(ApiF5FeedSocSimulation, '/database/f5/soc_feed/<feed_list_name>')
# parser_policygroup
parser_policygroup = reqparse.RequestParser()
parser_policygroup.add_argument('ID')
parser_policygroup.add_argument('name')
parser_policygroup.add_argument('sourceEnterpriseID')
parser_policygroup.add_argument('parentType')
parser_policygroup.add_argument('parentID')
parser_policygroup.add_argument('policyGroupID')
parser_policygroup.add_argument('templateID')# parser_policygroup
parser_policygroup_direct_attach = reqparse.RequestParser()
parser_policygroup_direct_attach.add_argument('ID')
parser_policygroup_direct_attach.add_argument('name')
parser_policygroup_direct_attach.add_argument('sourceEnterpriseID')
parser_policygroup_direct_attach.add_argument('parentType')
parser_policygroup_direct_attach.add_argument('parentID')
parser_policygroup_direct_attach.add_argument('vportID')
# parser_vminterface
parser_vminterface = reqparse.RequestParser()
parser_vminterface.add_argument('IPAddress')
parser_vminterface.add_argument('VPortID')
parser_vminterface.add_argument('domainID')
# parser_generic / domain_template
parser_generic = reqparse.RequestParser()
parser_generic.add_argument('ID')
parser_generic.add_argument('name')
parser_generic.add_argument('parentID')
parser_generic.add_argument('sourceEnterpriseID')
# parser_domain
parser_domain = reqparse.RequestParser()
parser_domain.add_argument('ID')
parser_domain.add_argument('name')
parser_domain.add_argument('parentID')
parser_domain.add_argument('templateID')
parser_domain.add_argument('sourceEnterpriseID')
# parser_vport
parser_vport = reqparse.RequestParser()
parser_vport.add_argument('ID')
parser_vport.add_argument('name')
parser_vport.add_argument('domainID')
parser_vport.add_argument('type')

# Start program
if __name__ == "__main__":
    main()




