import uuid
import random
import requests
import time
import uuid

try:
    # Try and import Nuage VSPK from the development release
    from vspk import v5_0 as vsdk
except ImportError:
    # If this fails, import the Nuage VSPK from the pip release
    from vspk.vsdk import v5_0 as vsdk

from nuage import vsd


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


def nuage_create():
    # nuage_l3domain
    for dmz_i in range(start_domain, max_domain +1):
        # nuage_policy_group_template
        """
        if dmz_i == 1:
            for pgt_i in range(start_pgt, max_pgt + 1):
                pg_name = 'pge_' + str(pgt_i)
                pg_desc = 'PAN_test'
                # POLICY GROUP TEMPLATE
                nuage_pgt = vsd.PolicyGroupTemplate(nuage_session=nuage_session, logger=logger,
                                                    pg_name=pg_name,
                                                    pg_desc=pg_desc,
                                                    nuage_domain_template=nuage_domain_template)
                nuage_pgt.nuage_create()
        """
        # DOMAIN
        domain_name = 'domain_dmz_' + str(dmz_i)
        domain_desc = 'PAN_stress_test'
        nuage_l3domain = vsd.L3Domain(nuage_session=nuage_session, logger=logger,
                                      domain_name=domain_name,
                                      domain_desc=domain_desc,
                                      nuage_enterprise=nuage_enterprise,
                                      nuage_domain_template=nuage_domain_template)
        nuage_l3domain.create()
        logger.warning("|  +-- created: nuage_l3domain=%s" % nuage_l3domain.nuage_object.name)

        # ZONE
        x_filter = "name == \"" + zone + "\""
        nuage_zone = nuage_l3domain.nuage_object.zones.get_first(filter=x_filter)
        logger.warning("|  |  +-- loaded: nuage_zone=%s" % nuage_zone.name)

        # SUBNET
        subnet_name = 'Front_1_1_' + str(dmz_i) + '_24'
        subnet_desc = 'PAN_stress_test'
        subnet_address = '1.1.' + str(dmz_i) + '.0'
        subnet_mask = '255.255.255.0'
        subnet_gateway = '1.1.' + str(dmz_i) + '.1'

        nuage_subnet = vsd.Subnet(nuage_session=nuage_session, logger=logger,
                                  subnet_name=subnet_name,
                                  subnet_desc=subnet_desc,
                                  subnet_address=subnet_address,
                                  subnet_mask=subnet_mask,
                                  subnet_gateway=subnet_gateway,
                                  nuage_zone=nuage_zone)
        nuage_subnet.create()
        logger.warning("|  |  |  +-- created: nuage_subnet=%s" % nuage_subnet.nuage_object.name)

        # Get policy group list
        policy_group_list = []
        for pg_i in range(start_pgt, max_pgt + 1):
            pg_name = 'pge_' + str(pg_i)
            nuage_pg = vsd.PolicyGroup(nuage_session=nuage_session, logger=logger,
                                       pg_name=pg_name,
                                       nuage_domain=nuage_l3domain.nuage_object)
            nuage_pg.fetch()
            policy_group_list.append(nuage_pg.nuage_object)

        # VPORT & VM
        for vm_i in range(start_vm_per_domain, max_vm_per_domain + 1):
            # vPort
            vport_type = 'VM'
            vport_name = vport_type + '_1_1_' + str(dmz_i) + '_' + str(vm_i)
            vport_desc = 'PAN_stress_test'

            nuage_vport = vsd.VPort(nuage_session=nuage_session, logger=logger,
                                    vport_name=vport_name,
                                    vport_desc=vport_desc,
                                    vport_type=vport_type,
                                    nuage_subnet=nuage_subnet.nuage_object)
            nuage_vport.create()
            logger.warning("|  |  |  |  +-- created: nuage_vport=%s" % nuage_subnet.nuage_object.name)

            # VM_interface and VM
            vm_name = 'VM_domain_' + str(dmz_i) + '_id_' + str(vm_i)
            vm_uuid = str(uuid.uuid4())
            vm_interface_ip = '1.1.' + str(dmz_i) + '.' + str(vm_i + 100)
            vm_interface_ip_list = [vm_interface_ip]
            vm_interface_mac = "52:54:00:%02x:%02x:%02x" % (
                random.randint(0, 255),
                random.randint(0, 255),
                random.randint(0, 255),
            )
            vm_interface_mac_list = [vm_interface_mac]
            nuage_vport_list = [nuage_vport.nuage_object]

            nuage_vm = vsd.VM(nuage_session=nuage_session, logger=logger,
                              vm_name=vm_name)
            nuage_vm.create(vm_uuid=vm_uuid,
                            vm_interface_ip_list=vm_interface_ip_list,
                            vm_interface_mac_list=vm_interface_mac_list,
                            nuage_vport_list=nuage_vport_list,
                            domain_type='L3_DOMAIN')
            logger.warning("|  |  |  |  |  +-- created: nuage_vm=%s; ip=%s" %
                           (nuage_vm.nuage_object.name, vm_interface_ip))
            sleep(3)

            # Assign Policy Group
            nuage_vport.nuage_object.assign(policy_group_list, vsdk.NUPolicyGroup)
            logger.warning("|  |  |  |  |  +-- assigned: nuage_vport=%s; policy_groups" %
                           (nuage_vm.nuage_object.name,))
            sleep(2)


def nuage_delete():
    # Delete VM
    for dmz_i in range(start_domain, max_domain + 1):
        for vm_i in range(start_vm_per_domain, max_vm_per_domain +1):
            vm_name = 'VM_domain_' + str(dmz_i) + '_id_' + str(vm_i)
            vm_interface_ip = '1.1.' + str(dmz_i) + '.' + str(vm_i + 100)

            nuage_vm = vsd.VM(nuage_session=nuage_session, logger=logger,
                              vm_name=vm_name)
            logger.warning("|  |  |  |  |  +-- deleting: nuage_vm=%s; ip=%s" %
                           (vm_name, vm_interface_ip))
            nuage_vm.delete()

    # nuage_domain
    for dmz_i in range(start_domain, max_domain + 1):
        domain_name = 'domain_dmz_' + str(dmz_i)
        x_filter = "name == \"" + domain_name + "\""
        nuage_domain = nuage_enterprise.domains.get_first(filter=x_filter)
        nuage_domain.delete()
        logger.warning("|  +-- deleted: nuage_domain=%s" % domain_name)

    # nuage_policy_group_template
    """
    for pgt_i in range(start_pgt, max_pgt + 1):
        pg_name = 'pge_' + str(pgt_i)

        # Get domain_template
        x_filter = "name == \"" + domain_template + "\""
        nuage_domain_template = nuage_enterprise.domain_templates.get_first(filter=x_filter)

        # POLICY GROUP TEMPLATE
        for cur_pgt in nuage_domain_template.policy_group_templates.get():
            cur_pgt.delete()
    """


def add_domain(domain_id):
    # nuage_l3domain
    domain_name = 'domain_dmz_' + str(domain_id)
    domain_desc = 'PAN_stress_test'
    nuage_l3domain = vsd.L3Domain(nuage_session=nuage_session, logger=logger,
                                  domain_name=domain_name,
                                  domain_desc=domain_desc,
                                  nuage_enterprise=nuage_enterprise,
                                  nuage_domain_template=nuage_domain_template)
    nuage_l3domain.create()
    logger.warning("|  +-- created: nuage_l3domain=%s" % nuage_l3domain.nuage_object.name)

    # ZONE
    x_filter = "name == \"" + zone + "\""
    nuage_zone = nuage_l3domain.nuage_object.zones.get_first(filter=x_filter)
    logger.warning("|  |  +-- loaded: nuage_zone=%s" % nuage_zone.name)

    # SUBNET
    subnet_name = 'Front_1_1_' + str(domain_id) + '_24'
    subnet_desc = 'PAN_stress_test'
    subnet_address = '1.1.' + str(domain_id) + '.0'
    subnet_mask = '255.255.255.0'
    subnet_gateway = '1.1.' + str(domain_id) + '.1'

    nuage_subnet = vsd.Subnet(nuage_session=nuage_session, logger=logger,
                              subnet_name=subnet_name,
                              subnet_desc=subnet_desc,
                              subnet_address=subnet_address,
                              subnet_mask=subnet_mask,
                              subnet_gateway=subnet_gateway,
                              nuage_zone=nuage_zone)
    nuage_subnet.create()
    logger.warning("|  |  |  +-- created: nuage_subnet=%s" % nuage_subnet.nuage_object.name)


def add_vm(domain_id, vm_id):
    # Get domain
    # nuage_l3domain
    domain_name = 'domain_dmz_' + str(domain_id)
    nuage_l3domain = vsd.L3Domain(nuage_session=nuage_session, logger=logger,
                                  domain_name=domain_name,
                                  nuage_enterprise=nuage_enterprise,
                                  nuage_domain_template=nuage_domain_template)
    nuage_l3domain.browse_and_get()
    logger.warning("|  +-- loaded: nuage_l3domain=%s" % nuage_l3domain.nuage_object.name)

    # ZONE
    x_filter = "name == \"" + zone + "\""
    nuage_zone = nuage_l3domain.nuage_object.zones.get_first(filter=x_filter)
    logger.warning("|  |  +-- loaded: nuage_zone=%s" % nuage_zone.name)

    # SUBNET
    subnet_name = 'Front_1_1_' + str(domain_id) + '_24'
    nuage_subnet = vsd.Subnet(nuage_session=nuage_session, logger=logger,
                              enterprise=enterprise,
                              domain=domain_name,
                              zone=zone,
                              subnet_name=subnet_name,
                              nuage_zone=nuage_zone)
    nuage_subnet.browse_and_get()
    logger.warning("|  |  +-- loaded: nuage_subnet=%s" % nuage_subnet.nuage_object.name)

    # Get policy group list
    policy_group_list = []
    for pg_i in range(1, max_pgt + 1):
        pg_name = 'pge_' + str(pg_i)
        nuage_pg = vsd.PolicyGroup(nuage_session=nuage_session, logger=logger,
                                   pg_name=pg_name,
                                   nuage_domain=nuage_l3domain.nuage_object)
        nuage_pg.fetch()
        policy_group_list.append(nuage_pg.nuage_object)

    # VPORT & VM
    # vPort
    vport_type = 'VM'
    vport_name = vport_type + '_1_1_' + str(domain_id) + '_' + str(vm_id)
    vport_desc = 'PAN_stress_test'

    nuage_vport = vsd.VPort(nuage_session=nuage_session, logger=logger,
                            vport_name=vport_name,
                            vport_desc=vport_desc,
                            vport_type=vport_type,
                            nuage_subnet=nuage_subnet.nuage_object)
    nuage_vport.create()
    logger.warning("|  |  |  |  +-- created: nuage_vport=%s" % nuage_subnet.nuage_object.name)

    # VM_interface and VM
    vm_name = 'VM_domain_' + str(domain_id) + '_id_' + str(vm_id)
    vm_uuid = str(uuid.uuid4())
    vm_interface_ip = '1.1.' + str(domain_id) + '.' + str(vm_id + 100)
    vm_interface_ip_list = [vm_interface_ip]
    vm_interface_mac = "52:54:00:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
    )
    vm_interface_mac_list = [vm_interface_mac]
    nuage_vport_list = [nuage_vport.nuage_object]

    nuage_vm = vsd.VM(nuage_session=nuage_session, logger=logger,
                      vm_name=vm_name)
    nuage_vm.create(vm_uuid=vm_uuid,
                    vm_interface_ip_list=vm_interface_ip_list,
                    vm_interface_mac_list=vm_interface_mac_list,
                    nuage_vport_list=nuage_vport_list,
                    domain_type='L3_DOMAIN')
    logger.warning("|  |  |  |  |  +-- created: nuage_vm=%s; ip=%s" %
                   (nuage_vm.nuage_object.name, vm_interface_ip))


def test_manage_nuage():
    # Parameters
    enterprise = 'PAN'
    zone = 'Front'
    domain_template = 'L3_SRV-1T'
    # vsd_host = '127.2.24.2'  # non-PROD
    vsd_host = '127.3.24.1'    # PROD
    # vsd_username = 'cms_nuage-pgsync_vsd_non-prod'  # non-PROD
    vsd_username = 'cms_scripts_vsd_prod'  # PROD
    vsd_password = 'Sncfaes2018!'
    vsd_organization = 'csp'
    start_pgt = 1
    max_pgt = 10
    start_domain = 1
    max_domain = 25  # 25
    start_vm_per_domain = 1
    max_vm_per_domain = 20  # 20

    # nuage_session
    nuage_vsd = vsd.NuageVsdHost(host=vsd_host,
                                 username=vsd_username,
                                 password=vsd_password,
                                 organization=vsd_organization,
                                 logger=logger)
    nuage_vsd.login()
    nuage_session = nuage_vsd.session
    logger.warning("Connected to nuage")

    # nuage_enterprise
    x_filter = "name == \"" + enterprise + "\""
    nuage_enterprise = nuage_session.user.enterprises.get_first(filter=x_filter)
    logger.warning("loaded: nuage_enterprise=%s" % nuage_enterprise.name)

    # nuage_domain_template
    x_filter = "name == \"" + domain_template + "\""
    nuage_domain_template = nuage_enterprise.domain_templates.get_first(filter=x_filter)
    logger.warning("|  +-- loaded: nuage_domain_template=%s" % nuage_domain_template.name)

    # CREATE
    # create()

    # DELETE
    nuage_delete()

    # Test 1
    # Delete $max_vm_per_domain (20) attached to domain #25
    # Delete domain #25
    """
    start_domain = 25
    max_domain = 25
    nuage_delete()
    """

    # Test 2 - DOMAIN
    # Add domain #25 + Network
    # add_domain(domain_id=25)

    # Test 3 - VM
    # Add VM
    # add_vm(domain_id=25, vm_id=25)

    # Test 3 - assign tag to VM
    # done on GUI

    # Test 4 - Create a domain with 1 pg per VM; max 10 VM
    """
    start_pgt = 1
    max_pgt = 1
    start_domain = 25
    max_domain = 25
    start_vm_per_domain = 1
    max_vm_per_domain = 20
    nuage_create()
    """

    # Test 5 - Create a domain with 10 pg per VM; max 10 VM
    """
    start_pgt = 1
    max_pgt = 10
    start_domain = 25
    max_domain = 25
    start_vm_per_domain = 1
    max_vm_per_domain = 10
    nuage_create()
    """


def event_stream_simulator(sStateEngineAddr, sStateEnginePort, event):
    """

    :param logger:
    :param sStateEngineAddr:
    :param sStateEnginePort:
    :param event: expected format
        event['eventReceivedTime']
        event['type']
        event['entityType']
        event['entities'][0]['ID']
        ... see more on code
    :return:
    """
    engine_host = 'http://' + sStateEngineAddr + ':' + str(sStateEnginePort)
    engine = None
    # All code behind is coming from event stream function: did_receive_push()

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


def test_se_api_domain_template_create(sStateEngineAddr, sStateEnginePort, enterprise_uuid, object_name, object_uuid=None):
    action_type = 'CREATE'
    if object_uuid is None:
        object_uuid = str(uuid.uuid4())

    event = {}
    event['eventReceivedTime'] = time.localtime()
    event['type'] = action_type
    event['entityType'] = 'domaintemplate'
    event['sourceEnterpriseID'] = enterprise_uuid
    event['entities'] = {}
    event['entities'][0] = {'ID': object_uuid,
                            'name': object_name,
                            }
    event_stream_simulator(sStateEngineAddr, sStateEnginePort, event)
    logger.info("domain_template: name=%s; action=%s" % (object_name, action_type))

    return object_uuid


def test_se_api_policygroup_template_create(sStateEngineAddr, sStateEnginePort,
                                            enterprise_uuid, domain_template_uuid, object_name, object_uuid=None):
    action_type = 'CREATE'
    if object_uuid is None:
        object_uuid = str(uuid.uuid4())

    event = {}
    event['eventReceivedTime'] = time.localtime()
    event['type'] = action_type
    event['entityType'] = 'policygrouptemplate'
    event['sourceEnterpriseID'] = enterprise_uuid
    event['entities'] = {}
    event['entities'][0] = {'ID': object_uuid,
                            'name': object_name,
                            'parentID': domain_template_uuid,
                            'parentType': 'N/A',
                            }
    event_stream_simulator(sStateEngineAddr, sStateEnginePort, event)
    logger.info("policygroup_template: name=%s; action=%s" % (object_name, action_type))

    return object_uuid


def test_se_api_policygroup_create(sStateEngineAddr, sStateEnginePort,
                                   enterprise_uuid, object_name, domain_uuid, domain_type, pgt_uuid='null'):
    action_type = 'CREATE'
    object_uuid = str(uuid.uuid4())
    policy_group_short_id = 123456789

    event = {}
    event['eventReceivedTime'] = time.localtime()
    event['type'] = action_type
    event['entityType'] = 'policygroup'
    event['sourceEnterpriseID'] = enterprise_uuid
    event['entities'] = {}
    event['entities'][0] = {'ID': object_uuid,
                            'name': object_name,
                            'parentID': domain_uuid,
                            'parentType': domain_type,
                            'policyGroupID': policy_group_short_id,
                            'templateID': pgt_uuid
                            }
    event_stream_simulator(sStateEngineAddr, sStateEnginePort, event)
    logger.info("policygroup: name=%s; action=%s" % (object_name, action_type))

    return object_uuid


def test_se_api_policygroup_update_direct_attach(sStateEngineAddr, sStateEnginePort,
                                                 enterprise_uuid, object_uuid, object_name, domain_uuid, vport_uuid):
    action_type = 'UPDATE_direct_attach'

    event = {}
    event['eventReceivedTime'] = time.localtime()
    event['type'] = action_type
    event['entityType'] = 'policygroup'
    event['sourceEnterpriseID'] = enterprise_uuid
    event['entities'] = {}
    event['entities'][0] = {'ID': object_uuid,
                            'name': object_name,
                            'parentID': domain_uuid,
                            'vportID': vport_uuid,
                            }

    # Generate request
    data = {'ID': event['entities'][0]['ID'],
            'name': event['entities'][0]['name'],
            'parentID': event['entities'][0]['parentID'],
            'vportID': event['entities'][0]['vportID'],
            'sourceEnterpriseID': event['sourceEnterpriseID']
            }
    engine_host = 'http://' + sStateEngineAddr + ':' + str(sStateEnginePort)
    engine_url = engine_host + "/sensor/nuage/policygroup/UPDATE/direct_attach"
    engine = requests.put(engine_url, data=data)
    logger.info("policygroup: name=%s; action=%s" % (object_name, action_type))

    return object_uuid


def test_se_api_domain_create(sStateEngineAddr, sStateEnginePort, enterprise_uuid, object_name, domain_template_uuid):
    action_type = 'CREATE'
    object_uuid = str(uuid.uuid4())

    event = {}
    event['eventReceivedTime'] = time.localtime()
    event['type'] = action_type
    event['entityType'] = 'domain'
    event['sourceEnterpriseID'] = enterprise_uuid
    event['entities'] = {}
    event['entities'][0] = {'ID': object_uuid,
                            'name': object_name,
                            'templateID': domain_template_uuid,
                            }
    event_stream_simulator(sStateEngineAddr, sStateEnginePort, event)
    logger.info("domain: name=%s; action=%s" % (object_name, action_type))

    return object_uuid


def test_se_api_vport_create(sStateEngineAddr, sStateEnginePort, enterprise_uuid, object_name, vport_type, domain_uuid):
    action_type = 'CREATE'
    object_uuid = str(uuid.uuid4())

    event = {}
    event['eventReceivedTime'] = time.localtime()
    event['type'] = action_type
    event['entityType'] = 'vport'
    event['sourceEnterpriseID'] = enterprise_uuid
    event['entities'] = {}
    event['entities'][0] = {'ID': object_uuid,
                            'name': object_name,
                            'type': vport_type,
                            'domainID': domain_uuid
                            }
    event_stream_simulator(sStateEngineAddr, sStateEnginePort, event)
    logger.info("vport: name=%s; action=%s" % (object_name, action_type))

    return object_uuid


def test_se_api_vm_interface_create(sStateEngineAddr, sStateEnginePort,
                                    ip_address, vport_uuid, domain_uuid):
    action_type = 'CREATE'

    event = {}
    event['eventReceivedTime'] = time.localtime()
    event['type'] = action_type
    event['entityType'] = 'vminterface'
    event['entities'] = {}
    event['entities'][0] = {'IPAddress': ip_address,
                            'VPortID': vport_uuid,
                            'domainID': domain_uuid,
                            }
    event_stream_simulator(sStateEngineAddr, sStateEnginePort, event)
    logger.info("vm_interface: ip=%s; action=%s" % (ip_address, action_type))


def test_se_uc_create(enterprise_uuid, start_pgt, max_pgt, start_domain, max_domain, start_vm_per_domain, max_vm_per_domain):
    """
    se: State Engine
    uc: use case
    :return:
    """
    # Parameters
    sStateEngineAddr = '127.0.0.1'
    sStateEnginePort = 5001
    domain_template_name = 'L3_SRV-1T'
    domain_type = 'domain'

    # create domain_template
    domain_template_uuid = test_se_api_domain_template_create(sStateEngineAddr=sStateEngineAddr,
                                                              sStateEnginePort=sStateEnginePort,
                                                              enterprise_uuid=enterprise_uuid,
                                                              object_name=domain_template_name)


    # create policygroup_template
    policy_group_template_list = []
    for pgt_i in range(start_pgt, max_pgt + 1):
        object_name = 'pge_' + str(pgt_i)
        policygroup_template_uuid = test_se_api_policygroup_template_create(sStateEngineAddr=sStateEngineAddr,
                                                                            sStateEnginePort=sStateEnginePort,
                                                                            enterprise_uuid=enterprise_uuid,
                                                                            object_name=object_name,
                                                                            domain_template_uuid=domain_template_uuid)
        policy_group_template_list.append(policygroup_template_uuid)

    # create domains
    for dmz_i in range(start_domain, max_domain + 1):
        # create domain
        domain_name = 'domain_dmz_' + str(dmz_i)
        domain_uuid = test_se_api_domain_create(sStateEngineAddr=sStateEngineAddr,
                                                sStateEnginePort=sStateEnginePort,
                                                enterprise_uuid=enterprise_uuid,
                                                object_name=domain_name,
                                                domain_template_uuid=domain_template_uuid)
        # create policy groups
        policy_group_list = []
        for pgt_uuid in policy_group_template_list:
            object_name = 'pge_' + str(policy_group_template_list.index(pgt_uuid) + 1)
            policygroup_uuid = test_se_api_policygroup_create(sStateEngineAddr=sStateEngineAddr,
                                                              sStateEnginePort=sStateEnginePort,
                                                              enterprise_uuid=enterprise_uuid,
                                                              object_name=object_name,
                                                              domain_uuid=domain_uuid,
                                                              domain_type=domain_type,
                                                              pgt_uuid=pgt_uuid)
            policy_group_list.append(policygroup_uuid)

        for vm_i in range(start_vm_per_domain, max_vm_per_domain +1):
            # create vport
            vport_type = 'VM'
            vport_name = vport_type + '_1_1_' + str(dmz_i) + '_' + str(vm_i)
            vport_uuid = test_se_api_vport_create(sStateEngineAddr=sStateEngineAddr,
                                                  sStateEnginePort=sStateEnginePort,
                                                  enterprise_uuid=enterprise_uuid,
                                                  object_name=vport_name,
                                                  vport_type=vport_type,
                                                  domain_uuid=domain_uuid)
            # assign policy group to vport
            for pg_uuid in policy_group_list:
                object_name = 'pge_' + str(policy_group_list.index(pg_uuid) + 1)
                test_se_api_policygroup_update_direct_attach(sStateEngineAddr=sStateEngineAddr,
                                                             sStateEnginePort=sStateEnginePort,
                                                             enterprise_uuid=enterprise_uuid,
                                                             object_name=object_name,
                                                             object_uuid=pg_uuid,
                                                             vport_uuid=vport_uuid,
                                                             domain_uuid=domain_uuid)

            # create vminterface
            ip_address = '1.1.' + str(dmz_i) + '.' + str(vm_i + 100)
            test_se_api_vm_interface_create(sStateEngineAddr=sStateEngineAddr,
                                            sStateEnginePort=sStateEnginePort,
                                            ip_address=ip_address,
                                            vport_uuid=vport_uuid,
                                            domain_uuid=domain_uuid)


if __name__ == "__main__":
    # Parameters
    debug = True
    verbose = True
    log_file = 'logs/tests.log'

    # Logging settings
    global logger
    logger = setup_logging(debug, verbose, log_file)

    # Use Case Create directly on State Engine
    enterprise_uuid = '537fbde6-35ef-4ba2-8d11-877b7f500bc8'
    start_pgt = 1
    max_pgt = 5
    start_domain = 1
    max_domain = 30  # 25
    start_vm_per_domain = 1
    max_vm_per_domain = 20  # 20
    test_se_uc_create(enterprise_uuid=enterprise_uuid,
                      start_pgt=start_pgt,
                      max_pgt=max_pgt,
                      start_domain=start_domain,
                      max_domain=max_domain,
                      start_vm_per_domain=start_vm_per_domain,
                      max_vm_per_domain=max_vm_per_domain)







