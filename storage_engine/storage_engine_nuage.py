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

try:
    # Try and import Nuage VSPK from the development release
    from vspk import v5_0 as vsdk
except ImportError:
    # If this fails, import the Nuage VSPK from the pip release
    from vspk.vsdk import v5_0 as vsdk
from storage_engine import storage_engine


class NuageVsdHost (storage_engine.DatabaseFormat):
    def __init__(self, host, username, password, organization, logger, port=8443):
        super(NuageVsdHost, self).__init__(logger)
        # Table
        self.type = 'vsd_host'
        # Primary key
        self.id = host
        # Relationship with other tables
        # specific attribute of the class
        self.host = host
        self.username = username
        self.password = password
        self.organization = organization
        self.port = port
        self.session = None

    def _get_record_specific_part(self, data):
        # specific attribute of the class
        data['host'] = self.host
        data['username'] = self.username
        data['organization'] = self.organization
        data['port'] = self.port
        return data

    def db(self):
        return self.parent.db()

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


class NuageVsdCluster (storage_engine.DatabaseFormat):
    def __init__(self, name, logger):
        super(NuageVsdCluster, self).__init__(logger)
        # Table
        self.type = 'vsd_cluster'
        # Primary key
        self.id = name
        # Relationship with other tables
        self.children['vsd_host'] = {}
        self.vsd_hosts = self.children['vsd_host'].values()
        # specific attribute of the class
        self.session = None

    def _get_record_specific_part(self, data):
        # specific attribute of the class
        return data

    def db(self):
        return self.parent.db()

    def login(self):
        self.session = None

        # Connection to Nuage
        for vsd_host in self.vsd_hosts:
            try:
                vsd_host.login()
            except Exception as e:
                self.logger.warning('NuageVsdCluster::login: failed. cause=%s' % e)
                # Try next VSD
                continue
            else:
                # Connected to VSD
                self.session = vsd_host.session
                break
        if self.session is None:
            raise RuntimeError("Could not connect to Nuage")

    def logout(self):
        self.session = None
        for vsd_host in self.vsd_hosts:
            vsd_host.logout()


class NuageDomainTemplate (storage_engine.DatabaseFormat):
    def __init__(self, vsd_id, domain_type, logger):
        """

        :param vsd_id:
        :param domain_type: "domaintemplate" or 'l2domaintemplate"
        :param logger:
        """
        super(NuageDomainTemplate, self).__init__(logger)
        # Table
        self.type = 'domain_template'
        # Primary key
        self.id = vsd_id
        # Relationship with other tables
        self.children['policy_group_template'] = {}
        self.policy_group_templates = self.children['policy_group_template'].values()
        self.associated_objects['domain'] = {}
        self.domains = self.associated_objects['domain'].values()
        # specific attribute of the class
        self.name = None
        self.domain_type = domain_type

    def _get_record_specific_part(self, data):
        # specific attribute of the class
        data['name'] = self.name
        data['domain_type'] = self.domain_type
        return data

    def fetch(self):
        """
        Fetch attribute from Nuage
        Discover children and then propagate fetch() on them
        Do not propagate fetch() on already known children in database
        :return:
        """
        # Get object from database
        db = self.get_db()
        # Connect to Nuage
        db.login()
        # Load Nuage object
        if self.domain_type == "domaintemplate":
            nuage_domain_template = vsdk.NUDomainTemplate(id=self.id)
        elif self.domain_type == "l2domaintemplate":
            nuage_domain_template = vsdk.NUL2DomainTemplate(id=self.id)
        else:
            self.logger.error('%s::%s: unknown domain_type: %s' %
                              (__class__.__name__, __name__, self.domain_type))
            raise RuntimeError("unknown domain_type %s" % self.domain_type)
        if nuage_domain_template is None:
            # Error handling : object doesn't exist anymore in current configuration
            self.logger.error("%s::%s: unexpected object deletion."
                              "Cause: object id=%s doesn't exist anymore in Nuage" %
                              (__class__.__name__, __name__, self.id))
            self.delete()

            return
        else:
            nuage_domain_template.fetch()
        # Fetch attribute
        self.name = nuage_domain_template.name

        # Discover NuagePolicyGroupTemplate
        for nuage_policy_group_template in nuage_domain_template.policy_group_templates.get():
            if nuage_policy_group_template.id in self.children['policy_group_template'].keys():
                # known policy_group_template in db
                pass
            else:
                # unknown policy_group_template in db
                # fetch recursively
                db_policy_group_template = NuagePolicyGroupTemplate(vsd_id=nuage_policy_group_template.id,
                                                                    logger=self.logger)
                self.create_child(db_policy_group_template)
                db_policy_group_template.fetch()


class NuagePolicyGroupTemplate (storage_engine.DatabaseFormat):
    def __init__(self, vsd_id, logger):
        super(NuagePolicyGroupTemplate, self).__init__(logger)
        # Table
        self.type = 'policy_group_template'
        # Primary key
        self.id = vsd_id
        # Relationship with other tables
        self.associated_objects['policy_group'] = {}
        self.policy_groups = self.associated_objects['policy_group'].values()
        # specific attribute of the class
        self.name = None
        self.policy_group_id = None
        self.template_id = None

    def _get_record_specific_part(self, data):
        # specific attribute of the class
        data['name'] = self.name
        data['policy_group_id'] = self.policy_group_id
        data['template_id'] = self.template_id
        data['ip_address_list'] = self.get_ip_address_list()
        return data

    def get_ip_address_list(self):
        """

        :return: ip_addresses of ip_address_list from all associated Policy Groups
        """
        data = []
        for cur_policy_group in self.policy_groups:
            data += cur_policy_group.get_ip_address_list()
        return data

    def fetch(self):
        """
        Fetch attribute from Nuage
        :return:
        """
        # Get object from database
        db = self.get_db()
        # Connect to Nuage
        db.login()
        # Load Nuage object
        nuage_pg_template = vsdk.NUPolicyGroupTemplate(id=self.id)
        if nuage_pg_template is None:
            # Error handling : object doesn't exist anymore in current configuration
            self.logger.error("%s::%s: unexpected object deletion."
                              "Cause: object id=%s doesn't exist anymore in Nuage" %
                              (__class__.__name__, __name__, self.id))
            self.delete()
            return
        else:
            nuage_pg_template.fetch()
        # Fetch attribute
        self.name = nuage_pg_template.name


class NuageDomain (storage_engine.DatabaseFormat):
    def __init__(self, vsd_id, domain_type, logger):
        super(NuageDomain, self).__init__(logger)
        # Table
        self.type = 'domain'
        # Primary key
        self.id = vsd_id
        # Relationship with other tables
        self.children['policy_group'] = {}
        self.policy_groups = self.children['policy_group'].values()
        self.children['vport'] = {}
        self.vports = self.children['vport'].values()
        self.associated_objects['domain_template'] = {}
        self.domain_templates = self.associated_objects['domain_template'].values()
        # specific attribute of the class
        self.name = None
        self.domain_type = domain_type

    def _get_record_specific_part(self, data):
        # specific attribute of the class
        data['name'] = self.name
        data['domain_type'] = self.domain_type
        return data

    def fetch(self):
        """
        Fetch attribute from Nuage
        Discover children and then propagate fetch() on them
        Do not propagate fetch() on already known children in database
        :return:
        """
        # Get object from database
        db = self.get_db()
        # Connect to Nuage
        db.login()
        # Load Nuage object
        if self.domain_type == "domain":
            nuage_domain = vsdk.NUDomain(id=self.id)
        elif self.domain_type == "l2domain":
            nuage_domain = vsdk.NUL2Domain(id=self.id)
        else:
            self.logger.error('NuageDomain::fetch: unknown domain_type: %s' %
                              self.domain_type)
            raise RuntimeError("unknown domain_type %s" % self.domain_type)
        if nuage_domain is None:
            # Error handling : object doesn't exist anymore
            self.logger.error("%s::%s: unexpected object deletion."
                              "Cause: object id=%s doesn't exist anymore in Nuage" %
                              (__class__.__name__, __name__, self.id))
            self.delete()
            return
        else:
            nuage_domain.fetch()

        # Fetch attribute
        self.name = nuage_domain.name

        # Discover domain_template
        if nuage_domain.template_id in db.children['domain_template'].keys():
            # domain_template in db
            if nuage_domain.template_id in self.associated_objects['domain_template'].keys():
                # domain_template already attached to policy group template
                pass
            else:
                # a domain can be attached to only one domain template
                for domain_template in self.domain_templates:
                    self.detach(domain_template)
                self.assign(db.children['domain_template'][nuage_domain.template_id])
        else:
            # unknown domain_template in db
            # launch a discovery on all database
            self.logger.info("%s::%s: unknown domain_template to assign: dom_id=%s; dom_id_tpl=%s" %
                             (__class__.__name__, __name__, self.id, nuage_domain.template_id))
            # fetch
            db.fetch()

        # Discover vPort
        for nuage_vport in nuage_domain.vports.get():
            if nuage_vport.id in self.children['vport'].keys():
                # known vport in db
                pass
            else:
                # unknown vport in db
                # if len(nuage_vport.policy_groups.get()) == 0:
                #     # no policy group attached
                #     self.logger.info("%s::%s: do not attach vport because no policy group is attached: "
                #                      "vport_id=%s; vport_name=%s; domain_id=%s; domain_name=%s" %
                #                      (__class__.__name__, __name__,
                #                       nuage_vport.id, nuage_vport.name,self.id, self.name))
                #     pass
                db_vport = NuageVPort(vsd_id=nuage_vport.id,
                                      vport_type=nuage_vport.type,
                                      logger=self.logger)
                # attach vPort to parent domain
                self.create_child(db_vport)
                # fetch recursively
                db_vport.fetch()

        # Discover NuagePolicyGroup
        for nuage_policy_group in nuage_domain.policy_groups.get():
            # policy_group filter
            if (db.nuage_pg_filter is not None and db.nuage_pg_filter in nuage_policy_group.name) or \
                    db.nuage_pg_filter is None:
                if nuage_policy_group.id in self.children['policy_group'].keys():
                    # known policy_group in db
                    pass
                else:
                    # unknown policy_group in db
                    # fetch recursively
                    db_policy_group = NuagePolicyGroup(vsd_id=nuage_policy_group.id,
                                                       logger=self.logger)
                    self.create_child(db_policy_group)
                    db_policy_group.fetch()


class NuagePolicyGroup (storage_engine.DatabaseFormat):
    def __init__(self, vsd_id, logger):
        super(NuagePolicyGroup, self).__init__(logger)
        # Table
        self.type = 'policy_group'
        # Primary key
        self.id = vsd_id
        # Relationship with other tables
        self.associated_objects['policy_group_template'] = {}
        self.policy_group_templates = self.associated_objects['policy_group_template'].values()
        self.associated_objects['vport'] = {}
        self.vports = self.associated_objects['vport'].values()
        # specific attribute of the class
        self.id = vsd_id
        self.name = None
        self.policy_group_id = None

    def _get_record_specific_part(self, data):
        # specific attribute of the class
        data['name'] = self.name
        data['tag'] = self.get_tag()
        data['policy_group_id'] = self.policy_group_id
        data['ip_address_list'] = self.get_ip_address_list()
        return data

    def fetch(self):
        """
        Attach to existing Policy Group Template
        Attach to existing vPort
        :return:
        """
        # Get object from database
        db = self.get_db()
        # Connect to Nuage
        db.login()
        # Load Nuage object
        nuage_pg = vsdk.NUPolicyGroup(id=self.id)
        if nuage_pg is None:
            # Error handling : object doesn't exist anymore
            self.logger.error("%s::%s: unexpected object deletion."
                              "Cause: object id=%s doesn't exist anymore in Nuage" %
                              (__class__.__name__, __name__, self.id))
            self.delete()
            return
        else:
            nuage_pg.fetch()
        # Fetch attribute
        self.name = nuage_pg.name
        self.policy_group_id = str(nuage_pg.policy_group_id)

        # Discover policy_group_template
        if nuage_pg.template_id is not None:
            for domain_template in db.domain_templates:
                if nuage_pg.template_id in domain_template.children['policy_group_template'].keys() and \
                        nuage_pg.template_id not in self.associated_objects['policy_group_template'].keys():
                    # known policy_group_template
                    # Create a relation with policy_group_template
                    self.assign(domain_template.children['policy_group_template'][nuage_pg.template_id])
                    break
            if len(self.associated_objects['policy_group_template']) == 0:
                # Policy Template not found
                # Fetch domain_template
                self.logger.info("NuagePolicyGroup::fetch: unknown policy_group_template to assign: "
                                 "pg_id=%s; pg_id_tpl=%s" %
                                 (self.id, nuage_pg.template_id))
                db.fetch()

        # Discover vport
        for nuage_vport in nuage_pg.vports.get():
            if nuage_vport.id in self.associated_objects['vport'].keys():
                # already attached vport
                pass
            elif nuage_vport.id in self.parent.children['vport'].keys():
                # existing vport in db, attached to domain
                db_vport = self.parent.children['vport'][nuage_vport.id]
                # attach vPort to policy group
                self.assign(db_vport)
            else:
                # unknown vport in db
                # do a preventive fetch on domain
                self.logger.error("%s::%s: unexpected absent object: vport_id=%s; pg_id=%s" %
                                  (__class__.__name__, __name__, nuage_vport.id, self.id))
                self.parent.fetch()

    def get_ip_address_list(self):
        """

        :return: ip_addresses of all vPort associated to this Policy Group
        """
        data = []
        for cur_vport in self.vports:
            data += cur_vport.ip_address_list

        return data

    def get_tag(self):
        """

        :return: policy group name in 'tag' format
        """
        # Get object from database
        db = self.get_db()

        return '-'.join([db.nuage_enterprise, self.parent.name, self.name])

    def get_domain(self):
        return self.parent.name


class NuageVPort(storage_engine.DatabaseFormat):
    def __init__(self, vsd_id, vport_type, logger):
        """

        :param vsd_id:
        :param vport_type: Type of vport. Possible values are VM, HOST, CONTAINER.
        :param logger:
        """
        super(NuageVPort, self).__init__(logger)
        # Table
        self.type = "vport"
        # Primary key
        self.id = vsd_id
        # Relationship with other tables
        self.associated_objects['policy_group'] = {}
        self.policy_groups = self.associated_objects['policy_group'].values()
        # specific attribute of the class
        self.id = vsd_id
        self.vport_type = vport_type
        self.ip_address_list = []
        self.name = None

    def _get_record_specific_part(self, data):
        # specific attribute of the class
        data['name'] = self.name
        data['vport_type'] = self.vport_type
        data['ip_addresses'] = self.ip_address_list
        return data

    def fetch(self):
        # Get object from database
        db = self.get_db()
        # Connect to Nuage
        db.login()
        # Load Nuage object
        nuage_vport = vsdk.NUVPort(id=self.id)
        if nuage_vport is None:
            # Error handling : object doesn't exist anymore
            self.logger.error("%s::%s: unexpected object deletion."
                              "Cause: object id=%s doesn't exist anymore in Nuage" %
                              (__class__.__name__, __name__, self.id))
            self.delete()
            return
        else:
            nuage_vport.fetch()
        # Fetch attribute
        self.name = nuage_vport.name

        # Clear ip_addresses in database
        self.ip_address_list = []

        # Discover ip_addresses from connected interfaces
        if nuage_vport.type == 'VM':
            for cur_interface in nuage_vport.vm_interfaces.get():
                if cur_interface.ip_address is not None:
                    self.ip_address_list.append(cur_interface.ip_address)
        elif nuage_vport.type == 'HOST':
            for cur_interface in nuage_vport.host_interfaces.get():
                if cur_interface.ip_address is not None:
                    self.ip_address_list.append(cur_interface.ip_address)
        elif nuage_vport.type == 'CONTAINER':
            for cur_interface in nuage_vport.container_interfaces.get():
                if cur_interface.ip_address is not None:
                    self.ip_address_list.append(cur_interface.ip_address)

        # Discover virtual ip_addresses
        for cur_vip in nuage_vport.virtual_ips.get():
            self.ip_address_list.append(cur_vip.virtual_ip)


class NuageDatabase(storage_engine.DatabaseFormat):
    """ Description
    database synchronized with current configuration on Nuage
    """
    def __init__(self, nuage_enterprise, logger, nuage_domain_filter=None, nuage_pg_filter=None):
        super(NuageDatabase, self).__init__(logger)
        # Table
        self.type = "db"
        # Primary key
        self.id = None
        # Relationship with other tables
        self.children['vsd_cluster'] = {}
        self.vsd_clusters = self.children['vsd_cluster'].values()
        self.children['domain_template'] = {}
        self.domain_templates = self.children['domain_template'].values()
        self.children['domain'] = {}
        self.domains = self.children['domain'].values()
        self.children['tmp'] = {}
        # specific attribute of the class
        self.nuage_enterprise = nuage_enterprise
        self.nuage_domain_filter = nuage_domain_filter
        self.nuage_pg_filter = nuage_pg_filter

    def _get_record_specific_part(self, data):
        # specific attribute of the class
        data['nuage_enterprise'] = self.nuage_enterprise
        data['id'] = self.id
        data['nuage_domain_filter'] = self.nuage_domain_filter
        data['nuage_pg_filter'] = self.nuage_pg_filter

        return data

    def fetch(self):
        """
        Fetch attribute from Nuage
        Discover domain templates
        Propagate fetch() on domain templates
        :return:
        """
        self.logger.info("NuageDatabase::fetch: started")
        # Connect to Nuage
        self.login()
        nuage_session = self.get_nuage_session()
        if nuage_session is None:
            self.logger.error("NuageDatabase::fetch: aborted. Cause: no active Nuage session")
            raise RuntimeError("No active session")
        nc = nuage_session.user

        # Load enterprise from current configuration
        nuage_filter = "name == \"" + self.nuage_enterprise + "\""
        nuage_enterprise = nc.enterprises.get_first(filter=nuage_filter)
        if nuage_enterprise is None:
            # Error handling : object doesn't exist anymore in current configuration
            for domain_template in self.domain_templates:
                domain_template.delete()
            for domain in self.domains:
                domain.delete()
                self.logger.error("%s::%s: empty database."
                                  "Cause: enterprise %s doesn't exist in Nuage" %
                                  (__class__.__name__, __name__, self.nuage_enterprise))
            return

        # Fetch attributes
        self.id = nuage_enterprise.id

        # Discover domain template
        for domain_template in nuage_enterprise.domain_templates.get():
            if domain_template.id in self.children['domain_template'].keys():
                # known policy_group_template in db
                # fetch recursively
                self.children['domain_template'][domain_template.id].fetch()
            else:
                # unknown policy_group_template in db
                # fetch recursively
                db_domain_template = NuageDomainTemplate(vsd_id=domain_template.id,
                                                         domain_type="domaintemplate",
                                                         logger=self.logger
                                                         )
                self.create_child(db_domain_template)
                db_domain_template.fetch()

        # Discover domain
        for nuage_domain in nuage_enterprise.domains.get():
            # domain filter
            if (self.nuage_domain_filter is not None and self.nuage_domain_filter in nuage_domain.name) or \
                    self.nuage_domain_filter is None:
                if nuage_domain.id in self.children['domain'].keys():
                    # known domain in db
                    pass
                else:
                    # unknown domain in db
                    # fetch recursively
                    db_domain = NuageDomain(vsd_id=nuage_domain.id,
                                            domain_type='domain',
                                            logger=self.logger)
                    self.create_child(db_domain)
                    db_domain.fetch()

        # Disconnect from Nuage
        self.logout()
        self.logger.info("NuageDatabase::fetch: ended")

    def flush(self):
        """
        Delete all records get from Nuage
        :return:
        """
        for domain_template in list(self.domain_templates):
            domain_template.delete()
        for domain in list(self.domains):
            domain.delete()

    def get_db(self):
        return self

    def get_nuage_session(self):
        for vsd_cluster in self.vsd_clusters:
            if vsd_cluster.session is not None:
                return vsd_cluster.session
        return None

    def get_domain(self, domain_name=None, vsd_id=None):
        """
        two ways to lookup for a policy_group:
            Method 1. Specify vsd_id
            Method 2. Specify domain_name
        :param domain_name:
        :param vsd_id:
        :return:
        """
        if vsd_id is not None:
            # Method 1
            if vsd_id in self.children['domain'].keys():
                return self.children['domain'][vsd_id]
        else:
            # Method 2
            for domain in self.domains:
                if domain.name == domain_name:
                    return domain
        return None

    def get_domain_template(self, domain_name=None, vsd_id=None):
        """
        two ways to lookup for a policy_group:
            Method 1. Specify vsd_id
            Method 2. Specify domain_name
        :param domain_name:
        :param vsd_id:
        :return:
        """
        if vsd_id is not None:
            # Method 1
            if vsd_id in self.children['domain_template'].keys():
                return self.children['domain_template'][vsd_id]
        else:
            # Method 2
            for domain_template in self.domain_templates:
                if domain_template.name == domain_name:
                    return domain_template
        return None

    def get_policy_group_tag_list(self):
        data = []
        for domain in self.domains:
            for policy_group in domain.policy_groups:
                data.append(policy_group.get_tag())
        return data

    def get_policy_group(self, domain_name=None, policy_group_name=None, vsd_id=None):
        """
        If no parameter set, return all policy groups
        two ways to lookup for a policy_group:
            Method 1. Specify vsd_id
            Method 2. Specify domain_name AND policy_group_name
        :param domain_name:
        :param policy_group_name:
        :param vsd_id:
        :return:
        """
        if domain_name is None and policy_group_name is None and vsd_id is None:
            # return all policy_groups
            data = []
            for domain in self.domains:
                data += domain.policy_groups
            return data

        if vsd_id is not None:
            # Method 1
            for domain in self.domains:
                if vsd_id in domain.children['policy_group'].keys():
                    return domain.children['policy_group'][vsd_id]
        else:
            # Method 2
            for domain in self.domains:
                if domain.name == domain_name:
                    for policy_group in domain.policy_groups:
                        if policy_group.name == policy_group_name:
                            return policy_group
        return None

    def get_policy_group_template(self, domain_template_name=None, policy_group_template_name=None, vsd_id=None):
        """
        two ways to lookup for a policy_group_template:
            Method 1. Specify vsd_id
            Method 2. Specify domain_template_name AND policy_group_template_name
        :param domain_template_name:
        :param policy_group_template_name:
        :return: object
        """
        if vsd_id is not None:
            # Method 1
            for domain_template in self.domain_templates:
                if vsd_id in domain_template.children['policy_group_template'].keys():
                    return domain_template.children['policy_group_template'][vsd_id]
        else:
            # Method 2
            for domain_template in self.domain_templates:
                if domain_template.name == domain_template_name:
                    for policy_group_template in domain_template.policy_group_templates:
                        if policy_group_template.name == policy_group_template_name:
                            return policy_group_template
        return None

    def get_policy_group_template_ip_address_list(self, domain_template_name, policy_group_template_name):
        """

        :param domain_template_name:
        :param policy_group_template_name:
        :return: aggregated list from policy_group_template with the same name
        """
        data = []
        domain_template_found = False
        for domain_template in self.domain_templates:
            if domain_template.name == domain_template_name:
                for policy_group_template in domain_template.policy_group_templates:
                    if policy_group_template.name == policy_group_template_name:
                        domain_template_found = True
                        data += policy_group_template.get_ip_address_list()
        if domain_template_found:
            return data
        else:
            return None

    def get_vport(self, vsd_id):
        for domain in self.domains:
            if vsd_id in domain.children['vport'].keys():
                return domain.children['vport'][vsd_id]
        return None

    def get_ip_policy_group_mapping(self, ip_address_filter=None):
        """

        :param ip_address_filter: specify ip_address filter. By default, return all ip_address in database
        :return:
        """
        # Build ip_policy_group_mapping table
        data = {}
        for domain in self.domains:
            for policy_group in domain.policy_groups:
                for vport in policy_group.vports:
                    for ip_address in vport.ip_address_list:
                        if ip_address not in data.keys():
                            # unknown ip_address
                            data[ip_address] = {}
                        # ip_address already exist
                        data[ip_address][policy_group.get_tag()] = {}
                        data[ip_address][policy_group.get_tag()]['nuage_enterprise'] = self.nuage_enterprise
                        data[ip_address][policy_group.get_tag()]['domain'] = domain.name
                        data[ip_address][policy_group.get_tag()]['policy_group'] = policy_group.name

        # ip_address filter
        if ip_address_filter is None:
            return data
        else:
            if ip_address_filter in data.keys():
                return data[ip_address_filter]
            else:
                # unknown ip_address
                return None

    def login(self):
        # Reuse existing connection to VSD
        if next(iter(self.vsd_clusters)).session is None:
            next(iter(self.vsd_clusters)).login()

    def logout(self):
        if next(iter(self.vsd_clusters)).session is None:
            next(iter(self.vsd_clusters)).logout()

    def import_vsd_pool(self, name, host_list, username, password, organization):
        """
        import one VSD in standalone mode, 3 VSD in a cluster mode or 6 in geo cluster mode

        :param name: pool name
        :param host_list: FQDN or ip address of VSD devices
        :param username: API user for all VSD devices
        :param password: password for API user for all VSD devices
        :param organization: organization that belongs nuage_enterprise
        :return: nothing
        """
        # Check if host already exist
        for host in host_list:
            for vsd in self.vsd_clusters:
                if host in vsd.children['vsd_host'].keys():
                    self.logger.error(
                        "NuageDatabase::import_vsd_pool: Duplicated host in database, operation aborted host=%s"
                        % host)
                    raise RuntimeError("Duplicated VSD device in database. Operation aborted")

        # Create a pool
        vsd_pool = NuageVsdCluster(name=name,
                                   logger=self.logger
                                   )
        self.create_child(vsd_pool)

        # Add pool members
        for host in host_list:
            # check if host already exist
            vsd_pool_member = NuageVsdHost(host=host,
                                           username=username,
                                           password=password,
                                           organization=organization,
                                           logger=self.logger
                                           )
            vsd_pool.create_child(vsd_pool_member)


class NuageGenericDomain(NuageDomain):
    def __init__(self, vsd_id, logger):
        super(NuageGenericDomain, self).__init__(vsd_id=vsd_id, domain_type='domain', logger=logger)
        # Table
        self.type = 'tmp'

    def fetch(self):
        """
        Do not fetch policy-group_templates
        :return:
        """
        # Get object from database
        db = self.get_db()
        # Connect to Nuage
        db.login()
        # Load Nuage object
        nuage_pg = vsdk.NUDomain(id=self.id)
        # Fetch attribute
        if nuage_pg is not None:
            self.name = nuage_pg.name
        # Disconnect from Nuage
        db.logout()
