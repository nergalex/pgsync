# -*- coding: utf-8 -*-
"""
--- Object ---
Class to connect to F5 BIG-IP and register/unregister ip_address/policy_group mapping record

--- Documentation ---
Pre-requisite :
    - F5 BIG-IPs belong to same organisation declared in Nuage.
        The organisation is specified in its device_tag (panorama/managed-devices)
    - F5 BIG-IPs that need to synchronize their ip_address/policy_group mapping
        with Nuage have a device_tag "nuage_sync" in BIG-IQ

--- Author ---
DA COSTA Alexis <alexis.dacosta@gmail.com>
"""

from f5.bigip import ManagementRoot as BigIp
from f5.iworkflow import ManagementRoot as Iworkflow
from storage_engine import storage_engine


class F5BigIpGeneric (storage_engine.DatabaseFormat):
    def __init__(self, host, username, password, logger, iworkflow_host=None):
        """
        A f5 BigIp appliance can be a "Virtual Edition", "Hardware Appliance", a "vCMP host" or a "vCMP guest"
        A f5 BigIp generic object can be used if you don't know his type

        :param host: management ip address or FQDN of the f5 BigIp device
        :param username: API user to access to the f5 BigIp device
        :param password: password for API user
        :param iworkflow_host: iWorkflow proxy. None by default
        :param logger: logger object
        """
        super(F5BigIpGeneric, self).__init__(logger)
        # Table
        self.type = 'generic_host'
        # Primary key
        self.id = host
        # Relationship with other tables
        self.children['partition'] = {}
        self.partitions = self.children['partition'].values()
        # specific attribute of the class
        self.host = host
        self.username = username
        self.password = password
        self.iworkflow_host = iworkflow_host
        self.serial = None
        self.model = None
        self.os = None
        self.module = []
        self.discovered_type = None
        self.session = None

    def login(self):
        if self.iworkflow_host is None:
            # Direct login to a big_ip device
            self.session = BigIp(hostname=self.host,
                                 username=self.username,
                                 password=self.password)
        else:
            # login to a big_ip device through a iWorkflow device
            # TODO : test
            self.session = Iworkflow(hostname=self.host,
                                     username=self.username,
                                     password=self.password,
                                     proxy_to=self.iworkflow_host)

    def logout(self):
        self.session = None

    def fetch_attribute(self):
        """
        Set attribute (serial, name, modules) from current config
        :return:
        """
        self.login()
        mgmt = self.session
        sys = mgmt.tm.sys
        hardware = sys.hardware.load()

        # Get type in database format
        appliance_type = \
            hardware.entries['https://localhost/mgmt/tm/sys/hardware/platform']['nestedStats']['entries'][
                'https://localhost/mgmt/tm/sys/hardware/platform/0']['nestedStats']['entries'][
                'marketingName']['description']
        if appliance_type == "BIG-IP vCMP Guest":
            self.discovered_type = "vcmp_guest"
        elif "BIG-IP VPR" in appliance_type:
            self.discovered_type = "vcmp_host"
        elif "Virtual Edition" in appliance_type:
            self.discovered_type = "bigip_VE"
        else:
            self.discovered_type = "bigip_hw"

        # serial
        self.serial = hardware.entries['https://localhost/mgmt/tm/sys/hardware/system-info']['nestedStats']['entries'][
            'https://localhost/mgmt/tm/sys/hardware/system-info/0']['nestedStats']['entries']['bigipChassisSerialNum'][
            'description']

        # name
        self.id = sys.global_settings.load().hostname

        # Modules
        for module in sys.provision.get_collection():
            if module['level'] != "none":
                self.module.append(module['name'])

    def fetch_partitions(self):
        """
        retrieve partition from current config
        :return:
        """

        # Connect to remote host
        self.login()

        mgmt = self.session
        auth = mgmt.tm.auth
        cur_partitions = auth.partitions.get_collection()

        # add missing running partition
        cur_partition_name_list = []
        for cur_partition in cur_partitions:
            cur_partition_name_list.append(cur_partition.name)
            if cur_partition.name not in self.children['partition']:
                # Create a new partition as a child
                partition = F5BigIpPartition(cur_partition.name, self.logger)
                self.create_child(partition)
                partition.fetch_attribute()

        # delete not running partition
        for cache_partition in list(self.partitions):
            if cache_partition.id not in cur_partition_name_list:
                cache_partition.delete()

    def fetch(self):
        self.login()
        for partition in self.partitions:
            partition.fetch(durable_connection=True)
        self.logout()

    def _get_record_specific_part(self, data):
        # specific attribute of the class
        data['serial'] = self.serial
        data['model'] = self.model
        data['os'] = self.os
        data['host'] = self.host
        data['module'] = self.module
        return data

    def get_address_lists(self, durable_connection=False):
        """
        :return: firewall address lists for each partition. If AFM module is not provisioned, return None
        """
        # Sanity check
        if 'afm' not in self.module:
            return None

        # re-use current connexion
        if self.session is None:
            self.login()

        # Fetch address_lists from remote device
        data = {}
        mgmt = self.session
        afm = mgmt.tm.security.firewall

        for afm_address_list in afm.address_lists.get_collection():
            if afm_address_list.partition not in data:
                data[afm_address_list.partition] = {}
            data[afm_address_list.partition][afm_address_list.name] = []
            for record in afm_address_list.addresses:
                # get ip_address without "%<route_domain_number>"
                if '%' in record['name']:
                    # ip address list in other route domain than RD 0
                    ip_address, route_domain = record['name'].split("%")
                else:
                    # ip address list in 'RD 0'
                    ip_address = record['name']

                # skip non-routable ip
                if ip_address == '192.0.2.0':
                    continue

                data[afm_address_list.partition][afm_address_list.name].append(ip_address)

        # Disconnect to remote device
        if durable_connection is False:
            self.session = None

        return data

    def sync(self):
        if 'afm' in self.module:
            self.login()
            for partition in self.partitions:
                partition.sync()
            self.logout()
        else:
            self.logger.info("F5BigIpGeneric::sync: afm module not provisioned, skip: name=%s; type=%s; serial=%s" %
                             (self.id, self.discovered_type, self.serial))


class F5BigIpVe (F5BigIpGeneric):
    """ Description
    A f5 BigIp Virtual Edition
    """

    def __init__(self, host, username, password, logger, iworkflow_host=None):
        super(F5BigIpVe, self).__init__(host, username, password, logger, iworkflow_host)
        self.type = "bigip_VE"


class F5BigIpHW (F5BigIpGeneric):
    """ Description
    A f5 BigIp Hardware Appliance
    """

    def __init__(self, host, username, password, logger, iworkflow_host=None):
        super(F5BigIpHW, self).__init__(host, username, password, logger, iworkflow_host)
        self.type = "bigip_hw"


class F5BigIpVcmpHost (F5BigIpGeneric):
    """ Description
    A f5 BigIp appliance with vCMP enable
    """

    def __init__(self, host, username, password, logger, iworkflow_host=None):
        super(F5BigIpVcmpHost, self).__init__(host, username, password, logger, iworkflow_host)
        self.type = "vcmp_host"
        self.children['vcmp_guest'] = {}
        self.vcmp_guests = self.children['vcmp_guest'].values()

    def fetch_attribute(self, durable_connection=False):
        # re-use current connexion
        if self.session is None:
            self.login()

        # retrieve host information
        mgmt = self.session
        sys = mgmt.tm.sys
        hardware = sys.hardware.load()
        # model
        self.model = \
            hardware.entries['https://localhost/mgmt/tm/sys/hardware/platform']['nestedStats']['entries'][
                'https://localhost/mgmt/tm/sys/hardware/platform/0']['nestedStats']['entries'][
                'marketingName']['description']
        # serial
        self.serial = hardware.entries['https://localhost/mgmt/tm/sys/hardware/system-info']['nestedStats']['entries'][
            'https://localhost/mgmt/tm/sys/hardware/system-info/0']['nestedStats']['entries']['bigipChassisSerialNum'][
            'description']
        # OS version
        self.os = mgmt.tmos_version
        # Name
        self.id = sys.global_settings.load().hostname

        # Disconnect to remote device
        if durable_connection is False:
            self.session = None

    def fetch_attribute_from_vcmp_guest(self):
        # lookup for a guest to retrieve host information through it
        vcmp_guest = list(self.vcmp_guests)[0]

        # retrieve vcmp_host information
        vcmp_guest.login()
        mgmt = vcmp_guest.session
        sys = mgmt.tm.sys
        hardware = sys.hardware.load()
        self.model = \
            hardware.entries['https://localhost/mgmt/tm/sys/hardware/hardware-version']['nestedStats']['entries'][
                'https://localhost/mgmt/tm/sys/hardware/hardware-version/host_platform']['nestedStats']['entries'][
                'https://localhost/mgmt/tm/sys/hardware/hardwareVersion/host_platform/versions']['nestedStats']['entries'][
                'https://localhost/mgmt/tm/sys/hardware/hardwareVersion/host_platform/versions/1']['nestedStats'][
                'entries']['version']['description']
        self.serial = hardware.entries['https://localhost/mgmt/tm/sys/hardware/system-info']['nestedStats']['entries'][
            'https://localhost/mgmt/tm/sys/hardware/system-info/0']['nestedStats']['entries']['bigipChassisSerialNum'][
            'description']
        self.id = self.serial
        self.os = hardware.entries['https://localhost/mgmt/tm/sys/hardware/hardware-version']['nestedStats']['entries'][
            'https://localhost/mgmt/tm/sys/hardware/hardware-version/host_platform']['nestedStats']['entries'][
            'https://localhost/mgmt/tm/sys/hardware/hardwareVersion/host_platform/versions']['nestedStats']['entries'][
            'https://localhost/mgmt/tm/sys/hardware/hardwareVersion/host_platform/versions/2']['nestedStats'][
            'entries']['version']['description']


class F5BigIpVcmpGuest (F5BigIpGeneric):
    """ Description
    A f5 BigIp virtualized (guest) and hosted on F5 hypervisor = a f5 BigIp appliance with vCMP enable
    """

    def __init__(self, host, username, password, logger, iworkflow_host=None):
        super(F5BigIpVcmpGuest, self).__init__(host, username, password, logger, iworkflow_host)
        self.type = "vcmp_guest"
        self.model = "none(vcmp_guest)"
        self.serial = "none(vcmp_guest)"

    def fetch_attribute(self):
        # retrieve software information
        self.login()
        mgmt = self.session
        sys = mgmt.tm.sys
        # OS
        self.os = mgmt.tmos_version
        # hostname
        self.id = sys.global_settings.load().hostname
        # Modules
        for module in sys.provision.get_collection():
            if module['level'] != "none":
                self.module.append(module['name'])


class F5BigIpPartition (storage_engine.DatabaseFormat):
    """ Description
    A f5 BigIp partition
    """

    def __init__(self, name, logger):
        super(F5BigIpPartition, self).__init__(logger)
        # Table
        self.type = "partition"
        # Primary key
        self.id = name
        # Relationship with other tables
        self.children['policy_group'] = {}
        self.afm_address_lists = self.children['policy_group'].values()
        # specific attribute of the class
        self.route_domain = None

    def fetch_attribute(self):
        self.parent.login()
        mgmt = self.parent.session

        # Route Domain
        auth = mgmt.tm.auth
        for partition in auth.partitions.get_collection():
            if partition.name == self.id:
                self.route_domain = partition.defaultRouteDomain

    def fetch(self, durable_connection=False):
        # Get object from database
        device = self.parent
        db = None
        if self.parent.parent_type == 'db':
            db = self.parent.parent
        elif self.parent.parent_type == 'vcmp_host':
            db = self.parent.parent.parent
        else:
            raise RuntimeError("db object not found, error in database scheme")

        # Clear policy-groups
        self.clear()

        # Get current configuration
        cur_address_lists = device.get_address_lists(durable_connection)

        # Get current address_list for each partition
        for partition_name, cur_address_list in cur_address_lists.items():
            if partition_name == self.id:
                for cur_address_list_name, cur_addresses in cur_address_list.items():
                    # skip policy group that do not belong to nuage_enterprise
                    if cur_address_list_name.startswith(db.nuage_enterprise):
                        # Check for existing policy_group
                        if cur_address_list_name not in self.children['policy_group']:
                            # unknown policy_group
                            # create a policy_group from current address list
                            policy_group = F5NuagePolicyGroup(name=cur_address_list_name,
                                                              nuage_enterprise=db.nuage_enterprise,
                                                              logger=self.logger)
                            policy_group.address_list = cur_addresses
                            self.create_child(policy_group)

    def _get_record_specific_part(self, data):
        # specific attribute of the class
        data['route_domain'] = self.route_domain
        return data

    def sync(self):
        """
        Compare policy group name in Nuage Vs current config
        CREATE new pg in all partition 'Common',
        UPDATE ip address list in partition 'Common',
        DELETE in other partitions
        :return:
        """
        # Delete policy group in all partition other than 'Common'
        if self.id == 'Common':
            self._sync_common_partition()
        else:
            self._sync_user_partition()

    def _sync_user_partition(self):
        """
        Delete all afm_address_lists in current configuration and then in database
        :return:
        """
        for afm_address_list in list(self.afm_address_lists):
            afm_address_list.delete_and_save(durable_connection=True)

    def _sync_common_partition(self):
        # Get objects from database
        if self.parent_type == 'vcmp_guest':
            # vCMP
            db = self.parent.parent.parent
        else:
            # firewall managed by PANORAMA
            db = self.parent.parent

        # Use a container for transaction
        transaction = {}

        # ADD or UPDATE policy group in current config
        for nuage_pg in db.nuage_db.get_policy_group():
            nuage_pg_tag = nuage_pg.get_tag()
            # UPDATE policy group in current config
            if nuage_pg_tag in self.children['policy_group']:
                # Existing policy_group in current_config
                afm_address_list = self.children['policy_group'][nuage_pg_tag]

                # Update attributes
                if afm_address_list.domain != nuage_pg.get_domain():
                    afm_address_list.domain = nuage_pg.get_domain()
                if afm_address_list.policy_group != nuage_pg.id:
                    afm_address_list.policy_group = nuage_pg.id

                # Compare ip address list
                if nuage_pg.get_ip_address_list() != afm_address_list.address_list:
                    # Update ip address list
                    # make a copy in transaction container
                    transaction['address_list'] = afm_address_list.address_list
                    afm_address_list.address_list = list(nuage_pg.get_ip_address_list())
                    try:
                        afm_address_list.save(durable_connection=True)
                    except Exception as e:
                        # rollback
                        afm_address_list.address_list = transaction['address_list']
                        self.logger.warning("F5BigIpPartition::_sync_common:"
                                            "unknown error, rollback: pg=%s; partition=%s; host=%s" %
                                        (afm_address_list.id, self.id, self.parent.id))
                    else:
                        # transaction success
                        # log
                        self.logger.info("F5BigIpPartition::_sync_common:"
                                         "updated policy group: pg=%s; partition=%s; host=%s" %
                                         (afm_address_list.id, self.id, self.parent.id))
                        ip_address_to_add = set(list(nuage_pg.get_ip_address_list())) - \
                                            set(list(afm_address_list.address_list))
                        if len(ip_address_to_add) != 0:
                            self.logger.info("F5BigIpPartition::_sync_common: adding ip address in list %s: %s" %
                                             (afm_address_list.id, ip_address_to_add))
                        ip_address_to_delete = set(list(afm_address_list.address_list)) - \
                                               set(list(nuage_pg.get_ip_address_list()))
                        if len(ip_address_to_delete) != 0:
                            self.logger.info("F5BigIpPartition::_sync_common: deleting ip address in list %s: %s" %
                                             (afm_address_list.id, ip_address_to_delete))
            else:
                # Unknown policy group that is present in Nuage and not in current_configuration
                # ADD policy group in current config
                afm_address_list = F5NuagePolicyGroup(name=nuage_pg_tag,
                                                      logger=self.logger,
                                                      nuage_enterprise=db.nuage_enterprise,
                                                      domain=nuage_pg.get_domain(),
                                                      policy_group=nuage_pg.name)
                self.create_child(afm_address_list)
                # Update current configuration
                afm_address_list.address_list = list(nuage_pg.get_ip_address_list())
                try:
                    afm_address_list.save(durable_connection=True)
                except Exception as e:
                    # rollback
                    afm_address_list.delete()
                    self.logger.warning("F5BigIpPartition::_sync_common:"
                                        "unknown error, rollback: pg=%s; partition=%s; host=%s" %
                                        (afm_address_list.id, self.id, self.parent.id))
                else:
                    self.logger.info("F5BigIpPartition::_sync_common: "
                                     "added policy group: pg=%s; partition=%s; host=%s" %
                                     (afm_address_list.id, self.id, self.parent.id))

        # DELETE unknown policy group in Nuage
        for afm_address_list in list(self.afm_address_lists):
            if afm_address_list.id not in db.nuage_db.get_policy_group_tag_list():
                afm_address_list.delete_and_save(durable_connection=True)


class F5NuagePolicyGroup (storage_engine.DatabaseFormat):
    """ Description
    A policy_group <> ip_address mapping
    """

    def __init__(self, name, logger, nuage_enterprise, domain=None, policy_group=None):
        super(F5NuagePolicyGroup, self).__init__(logger)
        # Table
        self.type = "policy_group"
        # Primary key: nuage_tag = nuage_enterprise + '-' + domain + '-' + policy_group
        self.id = name
        # Relationship with other tables
        # specific attribute of the class
        self.nuage_enterprise = nuage_enterprise
        self.domain = domain
        self.policy_group = policy_group
        self.address_list = []
        self.description = "nuage_sync-do_not_edit_or_delete_this_object"

    def _get_record_specific_part(self, data):
        # specific attribute of the class
        data['nuage_enterprise'] = self.nuage_enterprise
        data['nuage_domain'] = self.domain
        data['nuage_policy_group'] = self.policy_group
        data['address_list'] = self.address_list
        data['description'] = self.description
        return data

    def save(self, durable_connection=False):
        # re-use current connection
        if self.parent.parent.session is None:
            self.parent.parent.login()

        # append non routable ip address in case of empty feed list
        ip_address_list = self.address_list
        if len(ip_address_list) == 0:
            ip_address_list.append("192.0.2.0")

        # CREATE or UPDATE if not exists
        mgmt = self.parent.parent.session
        afm = mgmt.tm.security.firewall

        # Test presence of afm_address_list in current configuration
        already_exist = False
        for afm_address_list in afm.address_lists.get_collection():
            if afm_address_list.name == self.id and afm_address_list.partition == self.parent.id:
                # Already exist, update afm_address_list
                already_exist = True
                afm_address_list = afm.address_lists.address_list.load(partition=self.parent.id,
                                                                       name=self.id)
                afm_address_list.addresses = ip_address_list
                afm_address_list.description = self.description
                afm_address_list.update()
                self.logger.info("Updated AFM address list: partition=%s; name=%s" % (self.parent.id, self.id))

        if not already_exist:
            # Unknown, create afm_address_list
            afm.address_lists.address_list.create(partition=self.parent.id,
                                                  name=self.id,
                                                  addresses=ip_address_list,
                                                  description=self.description)
            self.logger.info("Created AFM address list: partition=%s; name=%s" % (self.parent.id, self.id))

        # Disconnect to remote device
        if durable_connection is False:
            self.parent.parent.session = None

    def delete_and_save(self, durable_connection=False):
        """
        Try to delete from current configuration and then delete from database
        :param durable_connection:
        :return:
        """
        # Use a container for transaction
        transaction = {}

        # re-use current connexion
        if self.parent.parent.session is None:
            self.parent.parent.login()

        mgmt = self.parent.parent.session
        afm = mgmt.tm.security.firewall

        # Test presence before deletion
        for afm_address_list in afm.address_lists.get_collection():
            if afm_address_list.name == self.id and afm_address_list.partition == self.parent.id:
                # Still exist, delete it
                afm_address_list = afm.address_lists.address_list.load(partition=self.parent.id,
                                                                       name=self.id)
                try:
                    afm_address_list.delete()
                except Exception as e:
                    if e.response.status_code == 400 and "is referenced by one or more firewall" in e.response.text:
                        # address list still in use
                        self.logger.warning(
                            "AFM address list cannot be deleted because it's still in use: "
                            "partition=%s; name=%s; error=%s" %
                            (self.parent.id, self.id, e.response.text))
                        # flush address list
                        # make a copy in transaction container
                        transaction['address_list'] = self.address_list
                        transaction['description'] = self.description
                        afm_address_list.description = "policy group deleted in Nuage, please detach this address list"
                        afm_address_list.address_list = []
                        try:
                            afm_address_list.update()
                        except Exception as e:
                            # rollback
                            self.description = transaction['description']
                            self.address_list = transaction['address_list']
                            self.logger.warning("F5NuagePolicyGroup::delete_and_save:"
                                                "unknown error, rollback: pg=%s; partition=%s; host=%s" %
                                                (self.id, self.parent.id, self.parent.parent.id))
                else:
                    self.delete()
                    self.logger.info("F5NuagePolicyGroup::delete_and_save: deleted: pg=%s; partition=%s; host=%s" %
                                     (self.id, self.parent.id, self.parent.parent.id))
                finally:
                    # Disconnect to remote device
                    if durable_connection is False:
                        self.parent.parent.session = None

                self.logger.info("Deleted AFM address list: partition=%s; name=%s" % (self.parent.id, self.id))

        # Disconnect to remote device
        if durable_connection is False:
            self.parent.parent.session = None


class F5Database(storage_engine.DatabaseFormat):
    """ Description
    database synchronized with current configuration on devices
    """

    def __init__(self, nuage_db, logger):
        super(F5Database, self).__init__(logger)
        # Table
        self.type = "db"
        # Primary key
        self.id = nuage_db.nuage_enterprise
        # Relationship with other tables
        self.children['generic_host'] = {}
        self.generic_hosts = self.children['generic_host'].values()
        self.children['bigip_VE'] = {}
        self.bigip_ves = self.children['bigip_VE'].values()
        self.children['bigip_hw'] = {}
        self.bigip_hws = self.children['bigip_hw'].values()
        self.children['vcmp_host'] = {}
        self.vcmp_hosts = self.children['vcmp_host'].values()
        # specific attribute of the class
        self.nuage_enterprise = nuage_db.nuage_enterprise
        self.nuage_db = nuage_db

    def get_device(self, name, db_type, serial):
        """
                Lookup for an existing device

        :param name: hostname of the device. Mandatory for vcmp_guest type
        :param db_type: bigip type in database format : bigip_VE, bigip_hw, vcmp_host, vcmp_guest
        :param serial: serial number. Mandatory for a bigip_VE, bigip_hw or vcmp_host
        :return: Device object, None if not found
        """
        if db_type == "vcmp_guest":
            for vcmp_host in self.vcmp_hosts:
                if vcmp_host.serial == serial:
                    if name in vcmp_host.children['vcmp_guest'].keys():
                        return self.children[db_type][name]
                    else:
                        return None
                else:
                    return None
        else:
            if name is None:
                # lookup by serial
                for device in self.children[db_type].values():
                    if device.serial == serial:
                        return device
                return None
            else:
                # lookup by name
                if name in self.children[db_type].keys():
                    return self.children[db_type][name]
                else:
                    return None

    def import_from_iworkflow(self, iworkflow_host):
        """
        TODO
        Import big-ip devices from iworkflow

        :param iworkflow_host: iworkflow ip address or FQDN
        :return: nothing
        """
        pass

    def import_device(self, host, username, password):
        # Discover host type
        device = F5BigIpGeneric(host=host,
                                username=username,
                                password=password,
                                logger=self.logger)
        device.fetch_attribute()

        # Check for duplicate entry
        if self.get_device(name=device.id,
                           db_type=device.discovered_type,
                           serial=device.serial) is not None:
            self.logger.warning("F5Database::import_device: duplicate entry, skip: ip=%s; name=%s; type=%s; serial=%s"
                                % (host, device.id, device.discovered_type, device.serial))
            return False

        # Create a bigip object,
        # fetch attribute from current configuration
        # and create association in the database with create_child method
        if device.discovered_type == 'vcmp_host':
            # Check for an existing vcmp_host with same serial
            vcmp_host = self.get_device(name=None,
                                        db_type='vcmp_host',
                                        serial=device.serial)
            if vcmp_host is None:
                # no conflict with existing "unknown" vcmp_host
                device = F5BigIpVcmpHost(host=host,
                                         username=username,
                                         password=password,
                                         logger=self.logger)
                device.fetch_attribute()
                self.create_child(device)
            else:
                # Update existing "unknown" vcmp_host
                device = vcmp_host
                device.host = host
                device.username = username
                device.password = password

        elif device.discovered_type == 'vcmp_guest':
            device = F5BigIpVcmpGuest(host=host,
                                      username=username,
                                      password=password,
                                      logger=self.logger)
            device.fetch_attribute()

            # Check for an existing vcmp_host that can be its parent
            vcmp_host = self.get_device(name=None,
                                        db_type='vcmp_host',
                                        serial=device.serial)
            if vcmp_host is None:
                # No vcmp_host yet, create it
                vcmp_host = F5BigIpVcmpHost(host='unknown',
                                            username='unknown',
                                            password='unknown',
                                            logger=self.logger)
                vcmp_host.create_child(device)
                vcmp_host.fetch_attribute_from_vcmp_guest()
                self.create_child(vcmp_host)
                self.logger.info(
                    "F5Database::import_device: added device type=%s; name=%s; serial=%s"
                    % (vcmp_host.type, vcmp_host.id, vcmp_host.serial))
            else:
                # Existing vcmp_host
                vcmp_host.create_child(device)

        elif device.discovered_type == 'bigip_VE':
            device = F5BigIpVe(host=host,
                               username=username,
                               password=password,
                               logger=self.logger)
            self.create_child(device)

        elif device.discovered_type == 'bigip_hw':
            device = F5BigIpHW(host=host,
                               username=username,
                               password=password,
                               logger=self.logger)
            self.create_child(device)

        else:
            # unknown device type
            self.logger.warning(
                "F5Database::import_device : unknown device type, skip: type=%s; name=%s; serial=%s"
                % (device.type, device.id, device.serial))
            return False

        device.fetch_partitions()

        self.logger.info(
            "F5Database::import_device: added device type=%s; name=%s; serial=%s"
            % (device.type, device.id, device.serial))
        return True

    def import_devices(self, host_list, username_list=None, username_default=None, password_list=None, password_default=None):
        """
        import bigip devices from a list. If a default username/password is not given in parameter,
        username and password are retrieved from a list
        database is updated with information get from f5 bigip API

        :param host_list: FQDN or ip address of bigip devices
        :param username_list: API users to access to the f5 BigIp device, one per bigip device
        :param username_default: default API user for all bigip devices
        :param password_list: password for API user, one per bigip device
        :param password_default: password for API user for all bigip devices
        :return: nothing
        """
        i = 0
        for host in host_list:
            # Get credential
            if username_default is None:
                username = username_list[i]
                password = password_list[i]
                i += 1
            else:
                username = username_default
                password = password_default

            self.import_device(host, username, password)

    def _get_record_specific_part(self, data):
        # specific attribute of the class
        data['nuage_enterprise'] = self.nuage_enterprise
        return data

    def fetch(self):
        """
        Retrieve policy-groups from current configuration
        :return:
        """
        # BIG-IP VE
        for device in self.bigip_ves:
            device.fetch()
        # BIG-IP HW
        for device in self.bigip_hws:
            device.fetch()
        # BIG-IP vCMP guest
        for vcmp_host in self.vcmp_hosts:
            for device in vcmp_host.vcmp_guests:
                device.fetch()

    def sync(self):
        """
        Retrieve policy-groups from current configuration
        :return:
        """
        # BIG-IP VE
        for device in self.bigip_ves:
            device.sync()
        # BIG-IP HW
        for device in self.bigip_hws:
            device.sync()
        # BIG-IP vCMP guest
        for vcmp_host in self.vcmp_hosts:
            for device in vcmp_host.vcmp_guests:
                device.sync()

    def get_host(self, host):
        # lookup for a bigip device by name or by ip address. Except for vcmp_guest, lookup by serial is also possible.

        # vcmp_host, bigip_VE, bigip_hw
        for device_type in ['vcmp_host', 'bigip_VE', 'bigip_hw']:
            for device in self.children[device_type].values():
                if device.id.startswith(host) or device.host == host or device.serial == host:
                    return device

        # BIG-IP vCMP guest
        for vcmp_host in self.vcmp_hosts:
            for device in vcmp_host.vcmp_guests:
                if device.id.startswith(host) or device.host == host:
                    return device

        return None

    def get_partition(self, host, partition_name):
        # lookup for a bigip device by name or by ip address. Except for vcmp_guest, lookup by serial is also possible.

        # vcmp_host, bigip_VE, bigip_hw
        for device_type in ['vcmp_host', 'bigip_VE', 'bigip_hw']:
            for device in self.children[device_type].values():
                if device.id.startswith(host) or device.host == host or device.serial == host:
                    for partition in device.partitions:
                        if partition.id == partition_name:
                            return partition

        # BIG-IP vCMP guest
        for vcmp_host in self.vcmp_hosts:
            for device in vcmp_host.vcmp_guests:
                if device.id.startswith(host) or device.host == host:
                    for partition in device.partitions:
                        if partition.id == partition_name:
                            return partition

        return None


class StorageEngineF5:
    """ Description
    Provide static methods
    """
    @staticmethod
    def get_feedlist_format(ip_address_list):
        # append non routable ip address in case of empty feed list
        feed_list = list(ip_address_list)
        feed_list.append("192.0.2.0,32,,\n")
        return ",32,,\n".join(feed_list)
