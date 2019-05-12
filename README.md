# nuage-pgsync

nuage-pgsync is a Python program for [Nuage VSP Platform](http://www.nuagenetworks.net/products/virtualized-services-platform/).

nuage-pgsync synchronizes "policy group" objects from Nuage with third-party provider. Supported third-party technology :
* [Palo Alto Networks Next Generation Firewall](https://www.paloaltonetworks.com/).
An ip address / policy groups mapping table is synchronized with a pool of Palo Alto Networks (PAN) firewalls (FW).
Then policy groups can be used in PAN FW security policies through Dynamic Address Group (DAG) objects.
A DAG does not need to commit policy changes to update its associated ip addresses, it's Dynamic ;o)

## High Level Design
### The components
* sensor:
    * Nuage VSD. "push center" gathers events from VSD and pushes them to its subscribers.
    A sensor accumulates much knowledge from Nuage as possible. "push center" is included in nuage-vspk module.
* event stream:
    * event_stream.py captures notification sent by Nuage, extracts the useful metric key and sends them to the "state engine" through its REST API.
    event_stream has no concept of state.
* aggregator : none
* state engine :
    * state_engine.py tracks changes within the event stream.
    It contains rules that define the behavior of the system, it can decide to change the state (UP/DOWN aka CREATED/DELETED) of monitored objects (policy group, associated ip_address).
    Monitored objects are provided by nuage_engine class.
    Some events require additional GET request to remote VSD system in order to collect up-to-date information for monitored objects.
    The state engine have a north REST API for third party connection.
* storage engine : is responsible for long term storage of ip_address/policy_group mapping table and high availability of this data.
It is capable of post-mortem program retrieval. Supported technologies are :
    * PAN : The storage system is a pool of PAN Virtual System (vSys) that is managed by a central management system "PANORAMA".
    Pool members (PAN vsys), their availability or their state in the high availability (ha) cluster is typically managed by PANORAMA.
    The storage system (PAN FW, PANORAMA) have an XML/API and are accessed through pan-python module.
    State engine uses storage_engine_pan.py to manipulate the PAN storage engine : clsStorageEnginePan class
* visualizer
    * PAN FW & DAG : "Dynamic Address Group" (DAG) object are built on top of the ip_address/policy_group mapping table. Then DAG are used in the Security Policy.
* notifier : none
* scheduler : none

### View of flows between components
                                                            [North API]
                                                                |
                                                                |
        [VSD system][sensor] --PUSH--> [event stream] --> [state engine] --> [storage engine] --> [vizualiser]
        |                                                 |
        +-------------------<--PULL--<--------------------+
   
### Concept of perimeter
#### Enterprise concept in Nuage
A nuage VSP platform can virtualize the network for multiple enterprises.
Each enterprise have their own network and security design :
* domain : a domain is a Routing Domain (PAN, F5 terminology), a Distributed Virtual Router and Switch, vpn-instance (HP Comware) or VRF (Cisco).
There is two types of Domain :
    * L2 : the domain is a unique broadcast domain, alias a VLAN. There is 2 types of L2_DOMAIN :
        * managed : ip address are known because they are distributed with DHCP. A managed_L2_DOMAIN contains a pool of vPort
        * unmanaged : ip address are unknown. This object is useless for this program.
    * L3 : the domain is a pool of "Zone"
        * zone : a zone is a pool of "Subnet". This object is useless for this program.
        * subnet : a subnet contains a pool of vPort (Virtual Port).
        Each domain is unique, so a domain can have different or same ip subnet inside.
        In case of same subnet use, public cloud for example, NAT will be used at perimeter for having a unique ip outside the domain.
* vPort : a Virtual Port is associated to :
    * one logical interface of a device. A device can be a Virtual Machine, a Container or a Hardware.
    * multiple policy group.
* Policy Group : a policy group is like a Security Tag.
A policy group is unique per domain, so different domain can have the same policy group name.
The associated ip address of a policy group are unique per Domain, so different policy group can have the same ip addresses.
* Security Policy : each domain have their own security policy for micro-segmentation or perimeter security.

#### Our enterprise approach
Each enterprise has multiple security devices (PAN NG FW, F5 BIG-IP for example) managed by a centralized management device (PANORAMA, BIG-IQ for example).
A nuage-pgs instance is dedicated for one enterprise ("nuage_enterprise" argument) and can have multiple storage devices.
A storage device is a centralized management device.

A company can be divided in multiple entities or branch, and the centralized management device can manage multiples branch FW with a strict Role Based Access Control. 
In this way, a branch is an enterprise and a centralized management device can manage multiple enterprises.

#### Sync method
The referential is the ip address / policy group mapping table defined in Nuage.
The synchronization :
* is done only on devices which belong to the enterprise (nuage_enterprise argument value set as a tag)
* is done only on devices which have been tagged to be synchronized ("nuage_sync" tag value)
* is differential : the current device config is compared to the Nuage referential,
an action of creation/deletion is done only for added/removed ip address and/or policy group mapping
* preserves additive tags : a device has its own "ip address / tag mapping table" and all tags are not policy groups to synchronize.
All tags that are out of scope of the nuage-pgsync are preserved.
* all devices inside an enterprise share the same "ip address / policy group mapping table"

#### Multi-domain with same subnet
If an enterprise have multiple domain with same ip subnet, in public cloud for example, this use case is supported.

### Rule
#### Published policy group name
Policy groups published on third-party providers, aka tag, have a unique name :
    
    <nuage_enterprise>-<domain_name>-<policygroup_name>
    - nuage_enterprise : string, enterprise name in Nuage
    - domain_name : string, domain name in Nuage
    - policygroup_name : string, policy group name in Nuage

Nuage rules :
* Different domain can have a policy group with the same name,
* An enterprise cannot have different domain with the same name.

##### Tag name in PAN NG FW
A synchronized device is synchronizing with Nuage its "ip address / tag mapping table".
Only tags that begins with "nuage_enterprise" value is synchronized.

#### Providers
##### Palo Alto Networks
###### Tag devices on Panorama
A synchronized device have the tags defined : 
* nuage_enterprise value : the enterprise name defined in Nuage
* "nuage_sync"

### Module design and specifics
#### event_stream
event_stream.py starts a standalone program that subscribes to VSD "push_center".
Each notification received by Nuage is processed by the did_receive_push() function.
Only event that have an impact on policy group are processed.
The output is a request done to the state engine API.

Push center send a notification each 30s. This notification is used as a state engine health check.

Code based on nuagenetworks examples :
- [Nuage-VSPK-Part-2-Advanced-concepts-examples](http://nuagenetworks.github.io/2016/03/04/Scripting-with-Nuage-VSPK-Part-2-Advanced-concepts-examples.html)
- [pushcenter example](https://github.com/nuagenetworks/vspk-examples/blob/master/python/show_pushcenter_notifications.py)

#### state_engine
Start the state engine program.
Steps of the startup :
1. fetch VSD policy groups, their associated ips and store them in a ip_address/policy_group mapping table.
2. start an instance of each storage_database passed in argument
3. start the nuage-pgsync API

#### storage_engine
Each third party provider have its own storage_engine.

Properties :
* image of the current ip_address/policy_group mapping table distributed through devices

Method :
* fetch_devices : get_json_format the list of devices to synchronized with Nuage.
If devices are added or deleted compared to the last fetch, a synchronization is launched for those devices.
* fetch_registered_ip : get_json_format the current ip_address/policy_group mapping table on a device
* sync : synchronize current ip_address/policy_group mapping table on devices with the one imported from Nuage

## Getting started
### Nuage VSD GUI or API
* Create an enterprise "my_enterprise"
* Create a L3 DOMAIN template with zones.
If the L3 DOMAIN instances have the same subnet ip address, so associate subnet(s) to zone
* Create multiple L3 DOMAIN from the template
* for each domain
    * Create subnet
    * Create hosts vPorts
    * Create vms with its vm-interface(s)
    * Attach each vm-interface to vPort
    * Create Policy Groups
    * Attach Policy Group to vPort 
* Create a user dedicated for nuage-pgsync
* Attach nuage-pgs user to CMS group
### PANORAMA
* go to panorama > managed devices 
    * add a tag "my_enterprise" to each NG FW that belong to the enterprise
    * add a tag "nuage_sync" to each NG FW to synchronize
### synchronized PAN NG FW
* login to PAN GUI
* switch to API mode by adding the "/api" path to the URL
* go to "operational command > show > object > registered ip > all" and submit
* a new tab opens and list the current ip address / tag mapping table
* if your device is not vsys-1, in the new opened tab, add "&vsys=vsys<my_vsys_number>" at the end of the URL

### VM nuage-pgsync
* install nuage-pgsync (see deployment guide)
* launch nuage-pgsync
* if a firewall is present on the VM, accept a new service to listen on TCP/5000. For example on centOS 7:
`firewall-cmd --zone=public --add-port=5000/tcp`

### synchronized PAN NG FW
* refresh the tab and see the current ip address / tag mapping table updated with the Nuage ip address / Policy Group mapping table
* switch to GUI mode
* go to Object > Address Group
* create a Dynamic Address Group based on the policy group name(s) synchronized
* go to Policy
* create a rule witch the newly created Dynamic Address Group
* commit changes

### Nuage VSD GUI or API
* attach or detach policy group to a vport
* detach/attach a vm interface to a vport
* rename a policy group

### synchronized PAN NG FW
* update the DAG : add the renamed policy group

## Deployment guide
* Install python version 3.6+
* Install required modules listed in requirements.txt, using "pip install"
* Ungzip nuage-pgsync
* launch nuage-pgs_start.sh --help
* edit parameter in `nuage-pgs_start.sh`
* launch `./nuage-pgs_start.sh start`





