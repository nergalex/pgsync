try:
    # Try and import Nuage VSPK from the development release
    from vspk import v5_0 as vsdk
except ImportError:
    # If this fails, import the Nuage VSPK from the pip release
    from vspk.vsdk import v5_0 as vsdk


class NuageVsdHost (object):
    def __init__(self, host, username, password, organization, logger, port=8443):
        self.host = host
        self.username = username
        self.password = password
        self.organization = organization
        self.port = port
        self.session = None
        self.logger = logger

    def login(self):
        self.logger.info('Connecting to Nuage server %s:%s with username %s' % (self.host, self.port,
                                                                                self.username))
        self.session = vsdk.NUVSDSession(username=self.username,
                                         password=self.password,
                                         enterprise=self.organization,
                                         api_url="https://%s:%s" % (self.host, self.port))

        # Connecting to Nuage
        try:
            self.session.start()
        except Exception as e:
            self.logger.error('Could not connect to Nuage host %s with user %s, enterprise %s and specified password' %
                              (self.host, self.username, self.password))
            raise

    def logout(self):
        self.session = None


class GenericNuageObject(object):
    def __init__(self, nuage_session, logger):
        self.nc = nuage_session.user  # nc = nuage_connection
        self.logger = logger
        self.nuage_object = None
        self.cms_name = 'CMS-scripts'

    def create(self):
        # to be defined by the child class
        pass

    def _create_log(self):
        self.logger.info('object is created : id=%s; name=%s' % (
                    self.nuage_object.id, self.nuage_object.name))

    def delete(self):
        if self.nuage_object is None:
            self.fetch()

        if self.nuage_object is None:
            self.logger.error('Object cannot be deleted. Cause: unknown object in Nuage')
        else:
            object_id = self.nuage_object.id
            object_name = self.nuage_object.name
            self.nuage_object.delete()
            self.logger.info('object is deleted: id=%s; name=%s' % (
                object_id, object_name))

    def fetch(self):
        if self.nuage_object is None:
            self.browse_and_get()
        else:
            self.nuage_object.fetch()

    def browse_and_get(self):
        # to be defined by the child class
        pass


class L3Domain(GenericNuageObject):
    def __init__(self, nuage_session, logger, domain_name, domain_desc=None,
                 domain_template=None, enterprise=None,
                 nuage_enterprise=None, nuage_domain_template=None):
        super(L3Domain, self).__init__(nuage_session, logger)
        self.domain_template = domain_template
        self.domain_desc = domain_desc
        self.enterprise = enterprise
        self.domain_name = domain_name
        self.nuage_enterprise = nuage_enterprise
        self.nuage_domain_template = nuage_domain_template

    def create(self):
        if self.nuage_domain_template is None:
            self._get_domain_template()

        self.nuage_object = vsdk.NUDomain(name=self.domain_name,
                                          template_id=self.nuage_domain_template.id,
                                          pat_enabled='DISABLED',
                                          ecmp_count=1,
                                          dhcp_behavior='CONSUME',
                                          fip_underlay=False,
                                          dpi='DISABLED',
                                          permitted_action='ALL',
                                          description=self.domain_desc,
                                          encryption='DISABLED',
                                          underlay_enabled='DISABLED',
                                          entity_scope='ENTERPRISE',
                                          stretched=False,
                                          multicast='DISABLED',
                                          tunnel_type='VXLAN',
                                          external_id=self.cms_name)
        self.nuage_enterprise.create_child(self.nuage_object)

        self._create_log()

    def _get_domain_template(self):
        x_filter = "name == \"" + self.enterprise + "\""
        self.nuage_enterprise = self.nc.enterprises.get_first(filter=x_filter)

        x_filter = "name == \"" + self.domain_template + "\""
        self.nuage_domain_template = self.nuage_enterprise.domain_templates.get_first(filter=x_filter)

    def browse_and_get(self):
        if self.nuage_domain_template is None:
            self._get_domain_template()

        x_filter = "name == \"" + self.domain_name + "\""
        self.nuage_object = self.nuage_enterprise.domains.get_first(filter=x_filter)


class Subnet(GenericNuageObject):
    def __init__(self, nuage_session, logger, subnet_name, subnet_desc=None, subnet_address=None, subnet_mask=None, subnet_gateway=None,
                 domain=None, enterprise=None, zone=None,
                 nuage_zone=None):
        super(Subnet, self).__init__(nuage_session, logger)
        self.subnet_name = subnet_name
        self.subnet_desc = subnet_desc
        self.subnet_address = subnet_address
        self.subnet_mask = subnet_mask
        self.subnet_gateway = subnet_gateway
        self.enterprise = enterprise
        self.domain = domain
        self.zone = zone
        self.nuage_zone = nuage_zone

    def create(self):
        if self.nuage_zone is None:
            self._get_nuage_zone()

        self.nuage_object = vsdk.NUSubnet(name=self.subnet_name,
                                          dpi='DISABLED',
                                          ip_type='IPV4',
                                          description=self.subnet_desc,
                                          address=self.subnet_address,
                                          netmask=self.subnet_mask,
                                          gateway=self.subnet_gateway,
                                          encryption='INHERITED',
                                          entity_scope='ENTERPRISE',
                                          multicast='DISABLED',
                                          proxy_arp=False,
                                          external_id=self.cms_name)
        self.nuage_zone.create_child(self.nuage_object)

        self._create_log()

    def _get_nuage_zone(self):
        x_filter = "name == \"" + self.enterprise + "\""
        self.nuage_enterprise = self.nc.enterprises.get_first(filter=x_filter)

        x_filter = "name == \"" + self.domain + "\""
        nuage_domain = self.nuage_enterprise.domains.get_first(filter=x_filter)

        x_filter = "name == \"" + self.zone + "\""
        self.nuage_zone = nuage_domain.zones.get_first(filter=x_filter)

    def browse_and_get(self):
        self._get_nuage_zone()

        x_filter = "name == \"" + self.subnet_name + "\""
        self.nuage_object = self.nuage_zone.subnets.get_first(filter=x_filter)


class VPort(GenericNuageObject):
    def __init__(self, nuage_session, logger,
                 vport_name, vport_desc, vport_type,
                 enterprise=None, domain=None, zone=None, subnet_name=None,
                 nuage_subnet=None):
        super(VPort, self).__init__(nuage_session, logger)
        self.enterprise = enterprise
        self.domain = domain
        self.zone = zone
        self.subnet_name = subnet_name
        self.vport_name = vport_name
        self.vport_desc = vport_desc
        self.vport_type = vport_type
        self.nuage_subnet = nuage_subnet

    def create(self):
        if self.vport_type == 'VM':
            self._create_vport_vm()
        self._create_log()

    def _get_subnet(self):
        x_filter = "name == \"" + self.enterprise + "\""
        nuage_enterprise = self.nc.enterprises.get_first(filter=x_filter)

        x_filter = "name == \"" + self.domain + "\""
        nuage_domain = nuage_enterprise.domains.get_first(filter=x_filter)

        x_filter = "name == \"" + self.zone + "\""
        nuage_zone = nuage_domain.zones.get_first(filter=x_filter)

        x_filter = "name == \"" + self.subnet_name + "\""
        self.nuage_subnet = nuage_zone.subnets.get_first(filter=x_filter)

    def _create_vport_vm(self):
        if self.nuage_subnet is None:
            self._get_subnet()

        self.nuage_object = vsdk.NUVPort(name=self.vport_name,
                                         description=self.vport_desc,
                                         type=self.vport_type,
                                         address_spoofing='INHERITED',
                                         entity_scope='ENTERPRISE',
                                         external_id=self.cms_name)
        self.nuage_subnet.create_child(self.nuage_object)

    def browse_and_get(self):
        self._get_subnet()

        x_filter = "name == \"" + self.vport_name + "\""
        self.nuage_object = self.nuage_subnet.vports.get_first(filter=x_filter)


class VM(GenericNuageObject):
    def __init__(self, nuage_session, logger, vm_name):
        """

        :param nuage_session:
        :param logger:
        :param vm_name:
        :param vm_uuid:
        :param vm_interface_ip_list:
        :param vm_interface_mac_list:
        :param enterprise:
        :param domain_list: Assumed that same domain type for all interfaces of the VM
        :param zone_list:
        :param subnet_name_list:
        :param vport_name_list:
        :param nuage_vport:
        """
        super(VM, self).__init__(nuage_session, logger)
        self.vm_name = vm_name
        self.vm_interface_list = []
        self.enterprise = None
        self.domain_list = None
        self.zone_list = None
        self.subnet_name_list = None
        self.vport_name_list = None
        self.vm_uuid = None
        self.vm_interface_ip_list = None
        self.vm_interface_mac_list = None
        self.nuage_vport_list = None
        self.domain_type = None

    def _get_vport_list(self):
        self.nuage_vport_list = []

        x_filter = "name == \"" + self.enterprise + "\""
        nuage_enterprise = self.nc.enterprises.get_first(filter=x_filter)

        # Define domain_type.
        x_filter = "name == \"" + self.domain_list[0] + "\""
        domain = nuage_enterprise.domains.get_first(filter=x_filter)
        if domain:
            # L3 DOMAIN
            self.domain_type = "L3_DOMAIN"

            # Sanity checks
            if len(self.zone_list) > 0 and len(self.zone_list) != len(self.vm_interface_mac_list):
                self.logger.error('!!!>error: incorrect arguments. '
                                  'Each interface must be in a different subnet, zone, domain.<!!!')
                raise RuntimeError("length of domain and interface arrays must be identical")
            if len(self.subnet_name_list) > 0 and len(self.subnet_name_list) != len(self.vm_interface_mac_list):
                self.logger.error('!!!>error: incorrect arguments. '
                                  'Each interface must be in a different subnet, zone, domain.<!!!')
                raise RuntimeError("length of domain and interface arrays must be identical")
            if len(self.vm_interface_ip_list) > 0 and len(self.vm_interface_ip_list) != len(self.vm_interface_mac_list):
                self.logger.error('!!!>error: incorrect arguments. '
                                  'Each interface must be in a different subnet, zone, domain.<!!!')
                raise RuntimeError("length of domain and interface arrays must be identical")
        else:
            # L2 DOMAIN
            self.domain_type = "L2_DOMAIN"

        # Handling each mac/subnet combination and creating the necessary VM Interfaces
        for mac in self.vm_interface_mac_list:
            index = self.vm_interface_mac_list.index(mac)
            domain_name = self.domain_list[index]
            zone_name = self.zone_list[index]
            subnet_name = self.subnet_name_list[index]
            vport_name = self.vport_name_list[index]

            # lookup Domain
            x_filter = "name == \"" + domain_name + "\""
            if self.domain_type == "L3_DOMAIN":
                domain = nuage_enterprise.domains.get_first(filter=x_filter)
            else:
                domain = nuage_enterprise.l2_domains.get_first(filter=x_filter)

            if self.domain_type == "L3_DOMAIN":
                # lookup Zone
                x_filter = "name == \"" + zone_name + "\""
                zone = domain.zones.get_first(filter=x_filter)

                # lookup Subnet
                x_filter = "name == \"" + subnet_name + "\""
                subnet = zone.subnets.get_first(filter=x_filter)

                # lookup vport
                x_filter = "name == \"" + vport_name + "\""
                vport = subnet.vports.get_first(filter=x_filter)

            else:
                # L2_DOMAIN
                # lookup vport
                x_filter = "name == \"" + vport_name + "\""
                vport = domain.vports.get_first(filter=x_filter)

            self.nuage_vport_list.append(vport)

    def _create_vm_interfaces(self):
        for mac in self.vm_interface_mac_list:
            index = self.vm_interface_mac_list.index(mac)
            nuage_vport = self.nuage_vport_list[index]
            ip_address = self.vm_interface_ip_list[index]

            if self.domain_type == "L3_DOMAIN":
                vm_interface = vsdk.NUVMInterface(name='eth%s' % (index + 1),
                                                  vport_id=nuage_vport.id,
                                                  mac=mac,
                                                  external_id=self.cms_name,
                                                  ip_address=ip_address
                                                  )
            else:
                # L2_DOMAIN
                vm_interface = vsdk.NUVMInterface(name='eth%s' % (index + 1),
                                                  vport_id=nuage_vport.id,
                                                  mac=mac,
                                                  external_id=self.cms_name
                                                  )

            self.vm_interface_list.append(vm_interface)

    def _create_vm(self):
        self.nuage_object = vsdk.NUVM(name=self.vm_name,
                                      uuid=self.vm_uuid,
                                      interfaces=self.vm_interface_list,
                                      external_id=self.cms_name)
        try:
            self.logger.debug('Trying to save VM %s.' % self.vm_name)
            self.nc.create_child(self.nuage_object)
            self.logger.info('VM %s is created by user %s.' % (self.nuage_object.name, self.nuage_object.user_name))
        except Exception as e:
            self.logger.error('VM %s can not be created because of error %s' % (self.vm_name, str(e)))

    def create(self, vm_uuid, vm_interface_ip_list, vm_interface_mac_list,
        enterprise=None, domain_list=None, zone_list=None, subnet_name_list=None, vport_name_list=None,
        domain_type=None, nuage_vport_list=None):
        # Sanity checks
        if domain_list is not None and len(domain_list) > 0 and len(domain_list) != len(vm_interface_mac_list):
            self.logger.error('!!!>error: incorrect arguments. '
                              'Each interface must be in a different subnet, zone, domain.<!!!')
            raise RuntimeError("length of domain and interface arrays must be identical")

        if vport_name_list is not None and len(vport_name_list) > 0 and len(vport_name_list) != len(vm_interface_mac_list):
            self.logger.error('!!!>error: incorrect arguments. '
                              'Each interface must be in a different subnet, zone, domain.<!!!')
            raise RuntimeError("length of vport and interface arrays must be identical")

        self.enterprise = enterprise
        self.domain_list = domain_list
        self.zone_list = zone_list
        self.subnet_name_list = subnet_name_list
        self.vport_name_list = vport_name_list
        self.vm_uuid = vm_uuid
        self.vm_interface_ip_list = vm_interface_ip_list
        self.vm_interface_mac_list = vm_interface_mac_list
        self.nuage_vport_list = nuage_vport_list
        self.domain_type = domain_type

        if self.nuage_vport_list is None:
            self._get_vport_list()

        self._create_vm_interfaces()
        self._create_vm()
        self._create_log()

    def fetch(self):
        x_filter = "name == \"" + self.vm_name + "\""
        self.nuage_object = self.nc.vms.get_first(filter=x_filter)


class PolicyGroupTemplate(GenericNuageObject):
    def __init__(self, nuage_session, logger, pg_name, pg_desc,
                 domain=None, enterprise=None,
                 nuage_domain_template=None):
        super(PolicyGroupTemplate, self).__init__(nuage_session, logger)
        self.pg_name = pg_name
        self.pg_desc = pg_desc
        self.domain = domain
        self.enterprise = enterprise
        self.nuage_domain_template = nuage_domain_template

    def create(self):
        if self.nuage_domain_template is None:
            self._get_nuage_domain_template()

        self.nuage_object = vsdk.NUPolicyGroupTemplate(name=self.pg_name,
                                                       description=self.pg_desc,
                                                       external_id=self.cms_name)
        self.nuage_domain_template.create_child(self.nuage_object)

        self._create_log()

    def _get_nuage_domain_template(self):
        x_filter = "name == \"" + self.enterprise + "\""
        nuage_enterprise = self.nc.enterprises.get_first(filter=x_filter)

        x_filter = "name == \"" + self.domain + "\""
        self.nuage_domain_template = nuage_enterprise.domain_templates.get_first(filter=x_filter)

        if not self.nuage_domain_template:
            # L2_DOMAIN
            self.nuage_domain_template = nuage_enterprise.l2_domain_templates.get_first(filter=myFilter)

        if self.nuage_domain_template:
            raise RuntimeError("Unknown domain template")

    def browse_and_get(self):
        self._get_nuage_domain_template()

        x_filter = "name == \"" + self.pg_name + "\""
        self.nuage_object = self.nuage_domain_template.policy_group_templates.get_first(filter=x_filter)


class PolicyGroup(GenericNuageObject):
    def __init__(self, nuage_session, logger, pg_name, nuage_domain):
        super(PolicyGroup, self).__init__(nuage_session, logger)
        self.pg_name = pg_name
        self.nuage_domain = nuage_domain

    def browse_and_get(self):
        # domain = None, enterprise = None
        # self._get_nuage_domain()

        x_filter = "name == \"" + self.pg_name + "\""
        self.nuage_object = self.nuage_domain.policy_groups.get_first(filter=x_filter)

    def assign_vport(self, nuage_vport):
        nuage_vport.assign([self.nuage_object] + nuage_vport.policy_groups.get(), vsdk.NUPolicyGroup)


class GenericRequest:
    @staticmethod
    def get_domain_type(nuage_connection, enterprise, domain):
        x_filter = "name == \"" + enterprise + "\""
        nuage_enterprise = nuage_connection.enterprises.get_first(filter=x_filter)

        # Define domain_type.
        x_filter = "name == \"" + domain + "\""
        nuage_domain = nuage_enterprise.domains.get_first(filter=x_filter)
        if nuage_domain:
            # L3 DOMAIN
            return "L3_DOMAIN"
        else:
            # L2 DOMAIN
            return "L2_DOMAIN"







