# -*- coding: utf-8 -*-
"""
--- Object ---
Class to connect to PANORAMA and register/unregister ip_address/policy_group mapping record

--- Documentation ---
Pre-requisite :
    - PAN fw belong to same organisation declared in Nuage.
        The organisation is specified in its device_tag (panorama/managed-devices)
    - PAN fw that need to synchronize their ip_address/policy_group mapping with Nuage
        have a device_tag "nuage_sync" in PANORAMA

--- Author ---
DA COSTA Alexis <alexis.dacosta@gmail.com>
"""

import pan.xapi
from storage_engine import storage_engine


class PanGenericDevice (storage_engine.DatabaseFormat):
    """Defines a Pan Session"""

    def __init__(self, host, username, password, logger, port='443', serial=None):
        super(PanGenericDevice, self).__init__(logger)
        # Table
        self.type = 'generic_host'
        # Primary key
        self.id = host
        # Relationship with other tables
        # specific attribute of the class
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.serial = serial
        self.xapi = None

    def login(self):
        # ISSUE :
        #   Symptoms : for an access to registered ip,
        #               a "missing vsys" error is raised when a request is done through PANORAMA
        #   Workaround : login directly to pan fw
        #   Fix Information : Bug fixed in 8.03 panorama release
        self.xapi = pan.xapi.PanXapi(hostname=self.host,
                                     api_username=self.username,
                                     api_password=self.password,
                                     timeout=60)

    def logout(self):
        self.xapi = None

    def _get_record_specific_part(self, data):
        # specific attribute of the class
        data['host'] = self.host
        data['port'] = self.port
        data['username'] = self.username
        data['serial'] = self.serial

        return data


class PanPanoramaDevice (PanGenericDevice):
    """Defines a Panorama Session"""

    def __init__(self, host, username, password, logger, port='443', serial=None):
        super(PanPanoramaDevice, self).__init__(host=host,
                                                port=port,
                                                username=username,
                                                password=password,
                                                logger=logger,
                                                serial=serial)
        # Table
        self.type = 'panorama_device'
        # Primary key
        self.id = host
        # Relationship with other tables
        # specific attribute of the class

    def _get_record_specific_part(self, data):
        # specific attribute of the class

        return data

    def login(self):
        try:
            self.xapi = pan.xapi.PanXapi(hostname=self.host,
                                         api_username=self.username,
                                         api_password=self.password,
                                         timeout=30)
            self.xapi.op(cmd="show system info", cmd_xml=True)
        except Exception:
            self.logger.warning('Could not connect to Panorama host %s with user %s and specified password' %
                                (self.host, self.username))
            raise RuntimeError("Could not connect to PANORAMA")

    def login_vault(self, serial):
        # log into PAN fw via PANORAMA.
        # Serial number used for Panorama to device redirection.
        # When an API request is made on Panorama and the serial number is specified,
        # Panorama will redirect the request to the managed device with the serial number.
        # here panorama_host_list is not a list but a host
        try:
            xapi = pan.xapi.PanXapi(hostname=self.host,
                                    api_username=self.username,
                                    api_password=self.password,
                                    serial=serial,
                                    timeout=60)
            self.xapi.op(cmd="show system info", cmd_xml=True)
        except Exception:
            self.logger.warning('Could not connect to Panorama host %s with user %s and specified password' %
                                (self.host, self.username))
            raise RuntimeError("Could not connect to PANORAMA")

        return xapi


class PanPanoramaPool (storage_engine.DatabaseFormat):
    """Logical object that can be in Standalone mode or in Cluster mode"""

    def __init__(self, name, logger):
        super(PanPanoramaPool, self).__init__(logger)
        # Table
        self.type = 'panorama'
        # Primary key
        self.id = name
        # Relationship with other tables
        self.children['fw_appliance'] = {}
        self.fw_appliances = self.children['fw_appliance'].values()
        self.children['panorama_device'] = {}
        self.panorama_devices = self.children['panorama_device'].values()
        # specific attribute of the class
        self.xapi = None

    def login(self):
        # Reset old panorama_device session
        self.xapi = None
        # Try each panorama_device to connect to
        for panorama_device in self.panorama_devices:
            try:
                panorama_device.login()
            except Exception as e:
                if e.args[0] == "Could not connect to PANORAMA":
                    # Try next panorama_device
                    continue
                else:
                    self.logger.error('Unexpected error: %s' % e.args[0])
                    raise
            else:
                self.logger.info('Connected to PANORAMA: %s' % panorama_device.id)
                self.xapi = panorama_device.xapi
                break

        # Raise an alert if no PANORAMA device could be reached
        if self.xapi is None:
            self.logger.warning('Could not connect to any PANORAMA device')
            raise RuntimeError("Could not connect to PANORAMA")

    def login_vault(self, serial):
        xapi = None
        # Try each panorama_device to connect to
        for panorama_device in self.panorama_devices:
            try:
                xapi = panorama_device.login_vault(serial)
            except Exception as e:
                if e.args[0] == "Could not connect to PANORAMA":
                    # Try next panorama_device
                    continue
                else:
                    self.logger.error('Unexpected error: %s' % e.args[0])
                    raise
            else:
                self.logger.info('Connected to PANORAMA: %s' % panorama_device.id)
                break

        # Raise an alert if no PANORAMA device coud be reached
        if xapi is None:
            self.logger.warning('Could not connect to any PANORAMA device')
            raise RuntimeError("Could not connect to PANORAMA")

        return xapi

    def logout(self):
        self.xapi = None

    def _get_record_specific_part(self, data):
        # specific attribute of the class

        return data

    def _get_current_perimeter(self):
        """
        cur_device_dict is a dict :
            key = serial of pan_fw ; value = list of vsys ID in perimeter
        :return:
        """

        # cur_device_dict: current pan_fw and associated vsys list in <nuage_enterprise> perimeter
        cur_device_dict = {}

        # Connect to PANORAMA
        if self.xapi is None:
            self.login()

        # Get pan_fw and vsys in the perimeter
        self.logger.info("PanPanoramaPool::_get_current_device: get device and vsys in %s perimeter" %
                         self.parent.nuage_enterprise)

        # Get pan_fw with at least one vsys with a tag <nuage_enterprise> and a tag 'nuage_sync'
        xpath = "/config/mgt-config/devices/entry[vsys/entry/tags/member = '%s' and vsys/entry/tags/member = '%s']" % \
                (self.parent.nuage_enterprise, 'nuage_sync')
        self.xapi.get(xpath=xpath)
        devices = self.xapi.element_root.findall('./result/entry')

        for cur_device in devices:
            # get Serial of pan_fw
            serial = cur_device.get('name', None)
            if serial is None:
                # line without 'name' tag is not a serial, skip
                continue
            else:
                # managed device in current config
                cur_device_dict[serial] = []

            # get virtual_systems of pan_fw
            for cur_vsys in cur_device[0]:
                vsys = cur_vsys.get('name', None)
                # line without 'name' tag is not a vsys, skip
                if vsys is None:
                    continue

                # If mandatory 'nuage_sync' tag is present, add vsys
                for tag_member in cur_vsys[0]:
                    if tag_member.text == 'nuage_sync':
                        # vsys to sync found
                        cur_device_dict[serial].append(vsys)
                        self.logger.info("%s: %s >> %s: %s >> %s: %s" %
                                         (cur_device.tag, cur_device.get('name', None),
                                          cur_vsys.tag, cur_vsys.get('name', None),
                                          tag_member.tag, tag_member.text))
        return cur_device_dict

    def fetch(self, durable_connection=False):
        """
        Discover managed devices and associated vsys
        :return:
        """
        self.logger.info("PanPanoramaPool::fetch: started")

        # Connect to PANORAMA
        if self.xapi is None:
            self.login()

        # Get current pan_fw and associated vsys list in <nuage_enterprise> perimeter
        cur_device_dict = self._get_current_perimeter()

        # Get current config for all devices
        self.xapi.op(cmd="show devices connected", cmd_xml=True)
        devices_config = self.xapi.element_root.findall('./result/devices/entry')

        # -------------------------- ADD unknown pan_fw in database --------------------------
        # Compare pan_fw from current_config and database
        added_device_list = set(list(cur_device_dict.keys())) - set(list(self.children['fw_appliance'].keys()))

        # Add unknown pan_fw to database
        for cur_device in devices_config:
            cur_device_serial = cur_device.get('name', None)

            # Add unknown pan_fw
            if cur_device_serial in added_device_list:
                # create a new PanFwAppliance
                cur_hostname = None
                cur_ip_address = None
                cur_model = None
                cur_os = None
                for cur_attribute in cur_device:
                    # host
                    if cur_attribute.tag == 'hostname':
                        cur_hostname = cur_attribute.text
                    # ip_address
                    if cur_attribute.tag == 'ip-address':
                        cur_ip_address = cur_attribute.text
                    # model
                    if cur_attribute.tag == 'model':
                        cur_model = cur_attribute.text
                    # os version
                    if cur_attribute.tag == 'sw-version':
                        cur_os = cur_attribute.text
                # Create a new fw_appliance
                db_device = PanFwAppliance(host=cur_hostname,
                                           serial=cur_device_serial,
                                           ip_address=cur_ip_address,
                                           model=cur_model,
                                           os=cur_os,
                                           username=self.get_username(),
                                           password=self.get_password(),
                                           logger=self.logger
                                           )
                self.create_child(db_device)

            # -------------------------- ADD unknown vsys in database --------------------------
            # Check if pan_fw have mandatory tags to be in the perimeter
            if cur_device_serial in cur_device_dict.keys():
                # load pan_fw from database
                db_device = self.children['fw_appliance'][cur_device_serial]

                # Add unknown vSys to database
                for cur_attribute in cur_device:
                    if cur_attribute.tag == 'vsys':
                        for cur_vsys in cur_attribute:
                            cur_vsys_id = cur_vsys.get('name', None)

                            # Check if vsys have mandatory tags and not in database
                            if cur_vsys_id in cur_device_dict[cur_device_serial] and \
                                    cur_vsys_id not in db_device.children['virtual_system'].keys():
                                # name
                                cur_vsys_name = 'unknown'
                                for cur_vsys_attribute in cur_vsys:
                                    if cur_vsys_attribute.tag == 'display-name':
                                        cur_vsys_name = cur_vsys_attribute.text
                                # Create a new vsys
                                db_vsys = PanFwVsys(vsys_id=cur_vsys_id,
                                                    name=cur_vsys_name,
                                                    logger=self.logger)
                                db_device.create_child(db_vsys)
                            else:
                                # current vsys vSys not in <nuage_enterprise> perimeter or already known
                                continue
            else:
                # current device does not have a vSys in <nuage_enterprise> perimeter
                continue

        # -------------------------- DELETE pan_fw out of perimeter in database --------------------------
        # Compare pan_fw from current_config and database
        deleted_device_list = set(list(self.children['fw_appliance'].keys())) - set(list(cur_device_dict.keys()))

        # Delete out of scope pan_fw from database
        for serial in deleted_device_list:
            device = self.children['fw_appliance'][serial]
            for vsys in device.virtual_systems:
                for cur_serial, cur_vsys_list in cur_device_dict.items():
                    if device.serial == cur_serial and vsys.id not in cur_vsys_list:
                        # Tag vSys to be deleted
                        vsys.status = "DELETING"
            # Sync vSys to erase ip_policygroup_mapping from vSys in DELETING state
            device.sync()
            # Delete device
            device.delete()

        # -------------------------- DELETE vsys out of perimeter in database --------------------------
        for device in list(self.fw_appliances):
            for vsys in list(device.virtual_systems):
                for cur_serial, cur_vsys_list in cur_device_dict.items():
                    if device.serial == cur_serial and vsys.id not in cur_vsys_list:
                        # Tag vSys to be deleted
                        vsys.status = "DELETING"
                        # Sync vSys to erase ip_policygroup_mapping from vSys in DELETING state
                        device.sync()
                        # Delete vSys
                        vsys.delete()

        self.logger.info("PanPanoramaPool::fetch: done")

        # Disconnect from PANORAMA
        if durable_connection is False:
            self.xapi = None

    def sync(self):
        for fw_appliance in self.fw_appliances:
            fw_appliance.sync()

    def get_username(self):
        return next(iter(self.panorama_devices)).username

    def get_password(self):
        return next(iter(self.panorama_devices)).password


class PanFwAppliance (PanGenericDevice):
    def __init__(self, host, ip_address, serial, logger, port=None, username=None, password=None, model=None,
                 os=None):
        super(PanFwAppliance, self).__init__(host=ip_address,
                                             port=port,
                                             username=username,
                                             password=password,
                                             logger=logger,
                                             serial=serial)
        # Table
        self.type = 'fw_appliance'
        # Primary key
        self.id = serial
        # Relationship with other tables
        self.children['virtual_system'] = {}
        self.virtual_systems = self.children['virtual_system'].values()
        # specific attribute of the class
        self.name = host
        self.ip_address = ip_address
        self.model = model
        self.os = os
        self.status = 'unknown'

    def _get_record_specific_part(self, data):
        # specific attribute of the class
        data['name'] = self.name
        data['ip_address'] = self.ip_address
        data['model'] = self.model
        data['os'] = self.os
        data['status'] = self.status

        return data

    def login_vault(self):
        """
        Login via PANORAMA, using its parent relationship
        :return:
        """
        self.xapi = self.parent.login_vault(self.serial)

    def fetch(self, durable_connection=False):
        if self.parent_type == 'panorama':
            # Connect to PANORAMA
            panorama = self.parent
            if panorama.xapi is None:
                panorama.login()

            # Get status
            panorama.xapi.op(cmd="show devices connected", cmd_xml=True)
            devices_config = panorama.xapi.element_root.findall('./result/devices/entry')

            for cur_device in devices_config:
                if cur_device.get('name', None) == self.serial:
                    self.status = 'active'  # active is the default value
                    for cur_attribute in cur_device:
                        # ha
                        if cur_attribute.tag == 'ha':
                            for cur_ha in cur_attribute:
                                if cur_ha.tag == 'state':
                                    self.status = cur_ha.text
                        # host
                        if cur_attribute.tag == 'hostname':
                            self.name = cur_attribute.text
                        # model
                        if cur_attribute.tag == 'model':
                            self.model = cur_attribute.text
                        # os version
                        if cur_attribute.tag == 'sw-version':
                            self.os = cur_attribute.text
        else:
            # TODO fetch directly from an unmanaged fw
            raise RuntimeError("Standalone device not supported. Operation aborted")

        # Disconnect to remote panorama
        if durable_connection is False:
            panorama.xapi = None

    def sync(self):
        self.login_vault()
        for vsys in self.virtual_systems:
            vsys.sync(durable_connection=True)
        self.logout()


class PanFwVsys (storage_engine.DatabaseFormat):

    def __init__(self, vsys_id, name, logger):
        """
            Logical vSys object. Login, serial and other stuff are accessed via its Parent "PanFwAppliance"
            Status : RUNNING or DELETING. DELETING is an intermediate state for deleting all policy group registered
        :param vsys_id:
        :param name:
        :param logger:
        """
        super(PanFwVsys, self).__init__(logger)
        # Table
        self.type = 'virtual_system'
        # Primary key
        self.id = vsys_id
        # Relationship with other tables
        self.children['registered_ip'] = {}
        self.registered_ips = self.children['registered_ip'].values()
        # specific attribute of the class
        self.name = name
        self.status = "RUNNING"

    def _get_record_specific_part(self, data):
        # specific attribute of the class
        data['name'] = self.name

        return data

    def fetch(self, durable_connection=False):
        """
        Load registered_ips and associated tags from current config
        PAN response is limited to 500 registered IPs max per bloc (<start-point>)

        :param durable_connection: if set, do not close session established on remote host (pan_fw)
        :return:
        """
        self.clear()

        # Get objects from database
        host = self.parent
        if host.parent_type != 'panorama':
            # unmanaged firewall
            db = host.parent
        else:
            # firewall managed by PANORAMA
            db = host.parent.parent

        # Connect directly to remote pan_fw
        self.logger.info("PanFwVsys::fetch started for sn=%s; vsys=%s" % (host.serial, self.id))
        if host.xapi is None:
            host.login()

        # Check regitered_ip with tag which starts with nuage_enterprise
        all_registered_ips_received = False
        start_point = 1
        counter_registered_ip_all = 0
        max_registered_ips_per_response = 500
        while not all_registered_ips_received:
            # Request
            pan_cmd = "show object registered-ip start-point \"" + str(start_point) + "\""
            host.xapi.op(cmd=pan_cmd,
                         vsys=self.id,
                         cmd_xml=True)
            root = host.xapi.element_root.findall('./result/entry')
            counter_registered_ip_in_response = 0
            # Response
            for IpPgs in root:
                counter_registered_ip_in_response += 1
                cur_registered_ip = IpPgs.get('ip', None)
                for Pgs in IpPgs:
                    for Pg in Pgs:
                        if Pg.text.startswith(db.nuage_enterprise):
                            cur_tag = Pg.text
                            self.logger.info("Current config sn=%s; vsys=%s; ip=%s ; pg=%s" %
                                             (host.serial, self.id, cur_registered_ip, cur_tag))

                            # Load registered_ip in database
                            if cur_registered_ip not in self.children['registered_ip'].keys():
                                # Unknown ip_address
                                registered_ip = PanNuageIpAddress(ip_address=cur_registered_ip,
                                                                  logger=self.logger)
                                self.create_child(registered_ip)
                            else:
                                registered_ip = self.children['registered_ip'][cur_registered_ip]

                            # Attach tag
                            if cur_tag not in registered_ip.children['tag'].keys():
                                    # Unknown tag
                                    tag = PanNuagePolicyGroup(name=cur_tag,
                                                              logger=self.logger,
                                                              nuage_enterprise=db.nuage_enterprise
                                                              )
                                    registered_ip.create_child(tag)

            # All registered ips was downloaded, exit loop
            if counter_registered_ip_in_response < max_registered_ips_per_response:
                all_registered_ips_received = True
                counter_registered_ip_all = start_point + counter_registered_ip_in_response - 1

            # Next registered ips
            else:
                start_point += 500

        # Disconnect to remote pan_fw
        if durable_connection is False:
            self.parent.xapi = None

        self.logger.info("PanFwVsys::fetch ended for sn=%s; vsys=%s; counter=%s" %
                         (host.serial, self.id, counter_registered_ip_all))

    def sync(self, durable_connection=False):
        self._sync_register(durable_connection)
        self._sync_unregister(durable_connection)

    def _sync_register(self, durable_connection=False):
        """
        Send a bulk message to update current configuration
        :param durable_connection:
        :return:
        """
        self.logger.info("PanFwVsys::_sync_register started for sn=%s; vsys=%s" % (self.parent.serial, self.id))

        # Get objects from database
        if self.parent.parent_type != 'panorama':
            # unmanaged firewall
            db = self.parent.parent
        else:
            # firewall managed by PANORAMA
            db = self.parent.parent.parent

        # Use a container for transaction
        transaction = {}

        # Parse IpPgMappingTable
        cmd_xml_list = None
        updated_registered_ip_table = False
        for ip_address, nuage_pg_dict in db.nuage_db.get_ip_policy_group_mapping().items():
            # sync registered_ip
            registered_ip = None
            if ip_address in self.children['registered_ip'].keys():
                # registered_ip mapping already exists
                registered_ip = self.children['registered_ip'][ip_address]
                # unknown registered_ip
                transaction[registered_ip.id] = {}
                transaction[registered_ip.id]['action'] = 'none'
                transaction[ip_address]['tag'] = {}
            else:
                # unknown registered_ip
                transaction[ip_address] = {}
                transaction[ip_address]['action'] = 'create'
                transaction[ip_address]['tag'] = {}

            # sync tag
            updated_registered_ip = False
            for nuage_pg_tag, nuage_pg_details in nuage_pg_dict.items():
                if registered_ip is not None and \
                        nuage_pg_tag in registered_ip.children['tag'].keys():
                    # registered_ip <> tag mapping already exists
                    # update attributes
                    tag = registered_ip.children['tag'][nuage_pg_tag]
                    tag.nuage_enterprise = nuage_pg_details['nuage_enterprise']
                    tag.sanity_check_domain = nuage_pg_details['domain']
                    tag.policy_group = nuage_pg_details['policy_group']
                else:
                    # unknown tag => create
                    transaction[ip_address]['tag'][nuage_pg_tag] = {}
                    transaction[ip_address]['tag'][nuage_pg_tag]['action'] = 'create'
                    transaction[ip_address]['tag'][nuage_pg_tag]['nuage_enterprise'] = nuage_pg_details['nuage_enterprise']
                    transaction[ip_address]['tag'][nuage_pg_tag]['domain'] = nuage_pg_details['domain']
                    transaction[ip_address]['tag'][nuage_pg_tag]['policy_group'] = nuage_pg_details['policy_group']
                    # prepare message to update current config
                    if not updated_registered_ip_table:
                        # First registered_ip to update
                        cmd_xml_list = ["<uid-message>",
                                        "<version>1.0</version>",
                                        "<type>update</type>",
                                        "<payload>",
                                        "<register>"]
                        updated_registered_ip_table = True
                    if not updated_registered_ip:
                        # First policy_group to update for this registered_ip
                        cmd_xml_list += ['<entry ip="%s">' % ip_address]
                        cmd_xml_list += ['<tag>']
                        updated_registered_ip = True
                    cmd_xml_list += ['<member>%s</member>' % nuage_pg_tag]
            if updated_registered_ip:
                cmd_xml_list += ['</tag>']
                cmd_xml_list += ['</entry>']
        if updated_registered_ip_table:
            cmd_xml_list += ["</register>",
                             "</payload>",
                             "</uid-message>"]

        if cmd_xml_list is not None:
            # Update current configuration
            cmd = ''.join(cmd_xml_list)
            try:
                self.logger.debug("PanFwVsys::_sync_register is sending to sn=%s; vsys=%s; cmd=%s" %
                                 (self.parent.serial, self.id, cmd))
                self._update_cmd(cmd)
                self.logger.debug("PanFwVsys::_sync_register is sending to sn=%s; vsys=%s; cmd=%s" %
                                 (self.parent.serial, self.id, cmd))
            except Exception as e:
                if "Unknown error" in e.args[0]:
                    raise
                else:
                    self.logger.warning(
                        "PanFwVsys::_sync_register transaction aborted for sn=%s; vsys=%s" %
                        (self.parent.serial, self.id))
            else:
                self.commit(transaction)

        # Disconnect to remote pan_fw
        if durable_connection is False:
            self.parent.xapi = None

        self.logger.info("PanFwVsys::_sync_register ended for sn=%s; vsys=%s" % (self.parent.serial, self.id))

    def _sync_unregister(self, durable_connection=False):
        """
        Send a bulk message to update current configuration
        :param durable_connection:
        :return:
        """
        self.logger.info("PanFwVsys::_sync_unregister started for sn=%s; vsys=%s" % (self.parent.serial, self.id))

        # Get objects from database
        if self.parent.parent_type != 'panorama':
            # unmanaged firewall
            db = self.parent.parent
        else:
            # firewall managed by PANORAMA
            db = self.parent.parent.parent

        # Use a container for transaction
        transaction = {}

        # Parse IpPgMappingTable
        cmd_xml_list = None
        updated_registered_ip_table = False
        ips_policy_groups_mapping = db.nuage_db.get_ip_policy_group_mapping()

        for registered_ip in self.registered_ips:
            # sync registered_ip
            if registered_ip.id in ips_policy_groups_mapping.keys():
                # registered_ip in current config and Nuage
                transaction[registered_ip.id] = {}
                transaction[registered_ip.id]['action'] = 'none'
                transaction[registered_ip.id]['tag'] = {}
            else:
                # unknown registered_ip
                transaction[registered_ip.id] = {}
                transaction[registered_ip.id]['action'] = 'delete'
                transaction[registered_ip.id]['tag'] = {}

            # sync tag
            updated_registered_ip = False
            for tag in registered_ip.tags:
                delete_tag = False
                if tag.id.startswith(db.nuage_enterprise):
                    if self.status == "DELETING":
                        # vSys in DELETING state => delete
                        delete_tag = True

                    elif registered_ip.id not in ips_policy_groups_mapping.keys():
                        # unknown IP in Nuage => delete
                        delete_tag = True

                    elif tag.id not in ips_policy_groups_mapping[registered_ip.id].keys():
                        # known IP in Nuage but unknown tag in Nuage => delete
                        delete_tag = True

                if delete_tag:
                    transaction[registered_ip.id]['tag'][tag.id] = {}
                    transaction[registered_ip.id]['tag'][tag.id]['action'] = 'delete'
                    # prepare message to update current config
                    if not updated_registered_ip_table:
                        # First registered_ip to update
                        cmd_xml_list = ["<uid-message>",
                                        "<version>1.0</version>",
                                        "<type>update</type>",
                                        "<payload>",
                                        "<unregister>"]
                        updated_registered_ip_table = True
                    if not updated_registered_ip:
                        # First policy_group to update for this registered_ip
                        cmd_xml_list += ['<entry ip="%s">' % registered_ip.id]
                        cmd_xml_list += ['<tag>']
                        updated_registered_ip = True
                    cmd_xml_list += ['<member>%s</member>' % tag.id]
            if updated_registered_ip:
                cmd_xml_list += ['</tag>']
                cmd_xml_list += ['</entry>']
        if updated_registered_ip_table:
            cmd_xml_list += ["</unregister>",
                             "</payload>",
                             "</uid-message>"]

        if cmd_xml_list is not None:
            # Update current configuration
            cmd = ''.join(cmd_xml_list)
            try:
                self.logger.debug("PanFwVsys::_sync_unregister is sending to sn=%s; vsys=%s; cmd=%s" %
                                  (self.parent.serial, self.id, cmd))
                self._update_cmd(cmd)
                self.logger.debug("PanFwVsys::_sync_unregister sent to sn=%s; vsys=%s; cmd=%s" %
                                  (self.parent.serial, self.id, cmd))
            except Exception as e:
                if "Host unreachable" not in e.args[0]:
                    raise
                else:
                    self.logger.warning(
                        "PanFwVsys::_sync_unregister transaction aborted for sn=%s; vsys=%s" %
                        (self.parent.serial, self.id))
            else:
                self.commit(transaction)

        # Disconnect to remote pan_fw
        if durable_connection is False:
            self.parent.xapi = None

        self.logger.info("PanFwVsys::_sync_unregister ended for sn=%s; vsys=%s" % (self.parent.serial, self.id))

    def commit(self, transaction):
        """
        Update database
        :param transaction:
        :return:
        """
        self.logger.info("PanFwVsys::commit started for sn=%s; vsys=%s" % (self.parent.serial, self.id))

        # Update registered_ip
        for ip_address, registered_ip_dict in transaction.items():
            if registered_ip_dict['action'] == 'create':
                registered_ip = PanNuageIpAddress(ip_address=ip_address,
                                                  logger=self.logger
                                                  )
                self.create_child(registered_ip)
            elif registered_ip_dict['action'] == 'delete':
                self.children['registered_ip'][ip_address].delete()
                continue
            else:
                registered_ip = self.children['registered_ip'][ip_address]

            # Update tag
            for tag_name, tag_dict in registered_ip_dict['tag'].items():
                if tag_dict['action'] == 'create':
                    tag = PanNuagePolicyGroup(name=tag_name,
                                              nuage_enterprise=tag_dict['nuage_enterprise'],
                                              domain=tag_dict['domain'],
                                              policy_group=tag_dict['policy_group'],
                                              logger=self.logger
                                              )
                    registered_ip.create_child(tag)
                elif tag_dict['action'] == 'delete':
                    registered_ip.children['tag'][tag_name].delete()
                    continue

        self.logger.info("PanFwVsys::commit done for sn=%s; vsys=%s" % (self.parent.serial, self.id))

    def _update_cmd(self, cmd):
        # Connect to host
        host = self.parent
        if host.xapi is None:
            host.login()

        self.logger.debug("clsPan::_update_vsys_cmd for sn=%s; vsys=%s ; update_message=%s" %
                          (host.serial, self.id, cmd))
        try:
            host.xapi.user_id(cmd=cmd, vsys=self.id)
        except Exception as e:
            if "ignore" in e.args[0]:
                # tag already exist
                self.logger.warning(
                    "Useless action, skip: serial=%s; vsys=%s; message=%s" %
                    (host.serial, self.id, e.args[0]))
            elif "timed out" in e.args[0]:
                self.logger.warning(
                    "Time Out: serial=%s; vsys=%s; message=%s" %
                    (host.serial, self.id, e.args[0]))
                raise RuntimeError("Host unreachable")
            elif "Connection refused" in e.args[0]:
                self.logger.warning(
                    "Connection refused: serial=%s; vsys=%s; message=%s" %
                    (host.serial, self.id, e.args[0]))
                raise RuntimeError("Host unreachable")
            elif "Forbidden" in e.args[0]:
                self.logger.warning(
                    "Too much connection on PAN fw: serial=%s; vsys=%s; message=%s" %
                    (host.serial, self.id, e.args[0]))
                raise RuntimeError("Host busy")
            elif "Failed to set session target vsys" in e.args[0]:
                self.logger.warning(
                    "Too much connection on PAN fw: serial=%s; vsys=%s; message=%s" %
                    (host.serial, self.id, e.args[0]))
                raise RuntimeError("Host busy")
            else:
                self.logger.error(
                    "Error during command execution: cmd=%s; serial=%s; vsys=%s; error=%s" %
                    (cmd, host.serial, self.id, e.args[0]))
                raise RuntimeError("Unknown error")

        self.logger.info("clsPan::_update_vsys_cmd sent [sn=%s; vsys=%s; ha_status=%s]" %
                         (host.serial, self.id, host.status))


class PanNuageIpAddress (storage_engine.DatabaseFormat):
    """
    ip_address object. Unique for each vsys
    """

    def __init__(self, ip_address, logger):
        super(PanNuageIpAddress, self).__init__(logger)
        # Table
        self.type = "registered_ip"
        # Primary key
        self.id = ip_address
        # Relationship with other tables
        self.children['tag'] = {}
        self.tags = self.children['tag'].values()
        # specific attribute of the class

    def _get_record_specific_part(self, data):
        # specific attribute of the class

        return data


class PanNuagePolicyGroup (storage_engine.DatabaseFormat):
    """ Description
    policy_group object
    """

    def __init__(self, name, logger, nuage_enterprise, domain=None, policy_group=None):
        super(PanNuagePolicyGroup, self).__init__(logger)
        # Table
        self.type = "tag"
        # Primary key: nuage_tag = nuage_enterprise + '-' + domain + '-' + policy_group
        self.id = name
        # Relationship with other tables
        # specific attribute of the class
        self.nuage_enterprise = nuage_enterprise
        self.domain = domain
        self.policy_group = policy_group

    def _get_record_specific_part(self, data):
        # specific attribute of the class
        data['nuage_enterprise'] = self.nuage_enterprise
        data['nuage_domain'] = self.domain
        data['nuage_policy_group'] = self.policy_group
        return data


class PanDatabase(storage_engine.DatabaseFormat):
    """ Description
    database synchronized with current configuration on devices
    """

    def __init__(self, nuage_db, logger):
        super(PanDatabase, self).__init__(logger)
        # Table
        self.type = "db"
        # Primary key
        self.id = nuage_db.nuage_enterprise
        # Relationship with other tables
        self.children['generic_host'] = {}
        self.generic_hosts = self.children['generic_host'].values()
        self.children['panorama'] = {}
        self.panoramas = self.children['panorama'].values()
        # specific attribute of the class
        self.nuage_enterprise = nuage_db.nuage_enterprise
        self.nuage_db = nuage_db

    def _get_record_specific_part(self, data):
        # specific attribute of the class
        data['nuage_enterprise'] = self.nuage_enterprise

        return data

    def get_host(self, host):
        """
        lookup for a PAN device by name, ip_address or serial number.
        :param host:
        :return:
        """
        for panorama in self.panoramas:
            # lookup in PANORAMA devices
            for device in panorama.panorama_devices:
                if device.id == host or device.host == host or device.serial == host:
                    return device

            # lookup in devices managed by PANORAMA
            for device in panorama.fw_appliances:
                if device.id == host or device.name == host or device.host == host or device.serial == host:
                    return device

        # host not found
        return None

    def get_vsys(self, host, vsys_id):
        """
        lookup for a PAN device by name, ip_address or serial number.
        :param host:
        :return:
        """
        for panorama in self.panoramas:
            # lookup in devices managed by PANORAMA
            for device in panorama.fw_appliances:
                if device.id == host or device.name == host or device.host == host or device.serial == host:
                    for vsys in device.virtual_systems:
                        if vsys.id == vsys_id or vsys.name == vsys_id:
                            return vsys

        # vsys not found
        return None

    def fetch(self):
        """
        fetch devices (pan_fw) and associated vsys which are marked with mandatory tags in PANORAMA
        fetch registered_ips which have at least 1 associated tag named <nuage_enterprise>-XXX
        fetch associated tags named <nuage_enterprise>-XXX
        :return:
        """
        # fetch devices and vsys
        for panorama in self.panoramas:
            panorama.login()
            panorama.fetch(durable_connection=True)
            # fetch registered_ips
            for device in panorama.fw_appliances:
                device.login()
                device.fetch(durable_connection=True)
                for vsys in device.virtual_systems:
                    vsys.fetch(durable_connection=True)
                device.logout()
            panorama.logout()

    def sync(self):
        for panorama in self.panoramas:
            panorama.sync()

    def import_panorama_pool(self, name, host_list, username, password):
        """
        import one panorama in standalone mode or 2 panoramas in a cluster mode

        :param name: pool name
        :param host_list: FQDN or ip address of panorama devices
        :param username: API user for all panorama devices
        :param password: password for API user for all panorama devices
        :return: nothing
        """
        # Check if host already exist
        for host in host_list:
            for panorama in self.panoramas:
                if host in panorama.children['panorama_device'].keys():
                    self.logger.error(
                        "PanDatabase::import_panorama_pool: Duplicated host in database, operation aborted host=%s"
                        % host)
                    raise RuntimeError("Duplicated PANORAMA device in database. Operation aborted")

        # Create a pool
        panorama_pool = PanPanoramaPool(name=name,
                                        logger=self.logger
                                        )
        self.create_child(panorama_pool)

        # Add pool members
        for host in host_list:
            # check if host already exist
            panorama_pool_member = PanPanoramaDevice(host=host,
                                                     username=username,
                                                     password=password,
                                                     logger=self.logger
                                                     )
            panorama_pool.create_child(panorama_pool_member)


class StorageEnginePan:
    """ Description
    Provide static methods
    """
    @staticmethod
    def get_feedlist_format(ip_address_list):
        # append non routable ip address in case of empty feed list
        feed_list = list(ip_address_list)
        feed_list.append("192.0.2.0/32\n")
        return "/32\n".join(feed_list)
"""
*** DEBUG bloc
import logging
pan_logger = logging.getLogger()
pan_logger.setLevel(pan.xapi.DEBUG3)
handler = logging.StreamHandler()
pan_logger.addHandler(handler)
*** DEBUG bloc
"""

# Start program
"""
if __name__ == "__main__":
    import pprint
    import logging
    log_level = logging.INFO
    logging.basicConfig(filename="logs/storage_engine_pan.log",
                        format='%(asctime)s %(levelname)s %(message)s',
                        level=log_level
                        )
    test_logger = logging.getLogger(__name__)

    import_host_list = ["10.5.27.110"]
    pan_db = PanDatabase(nuage_enterprise="AES",
                         nuage_ip_pg_mapping=None,
                         logger=test_logger
                         )
    pan_db.import_panorama_pool(name="non-PROD",
                                host_list=import_host_list,
                                username="admin",
                                password="bt123!"
                                )
    pprint.pprint(pan_db.dump_json_format())
"""

