[comment]: # "Auto-generated SOAR connector documentation"
# Cisco ISE

Publisher: Splunk  
Connector Version: 2\.0\.5  
Product Vendor: Cisco Systems  
Product Name: Cisco ISE  
Product Version Supported (regex): "/\(\[2\]\.\[67\]\)\|\(\[3\]\.\[01\]\)/"  
Minimum Product Version: 5\.0\.0  

This app implements investigative and containment actions on a Cisco ISE device

[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2014-2021 Splunk Inc."
[comment]: # ""
[comment]: # "  SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part"
[comment]: # "  without a valid written license from Splunk Inc. is PROHIBITED."
[comment]: # ""
[comment]: # " pragma: allowlist secret "
[comment]: # " pragma: allowlist secret "
[comment]: # " pragma: allowlist secret "
## Getting ERS credentials

1.  ### Enable Ers

    ERS uses on HTTPS port 9060 which is by default closed. Clients trying to access this port
    without enabling ERS first, will face a timeout from the server. Therefore, the first
    requirement is to enable ERS from the Cisco ISE admin UI. Go to **Administration \> Settings \>
    ERS Settings** and enable the Enable ERS for Read/Write radio button

2.  ### Creating ERS Admin

    Go to **Administration \> Settings \> ERS Settings** and then from the panel on the left select
    **Admin Users** under administrators. Now add an account by clicking **Add \> Create an admin
    user** . Then enter name and password and select **ERS Admin** in Admin Group and then press
    save.

## Note

1.  Quarantine device and Unquarantine device actions may not work properly sometimes. Apply policy
    and Clear policy with policy type QUARANTINE are recommended to use
2.  ERS credentials are required for actions list endpoints, get device info, update device info,
    get resources, delete resource, create resource, update resource, apply policy and create policy
3.  An ISE node can assume any or all of the following personas: Administration, Policy Service, and
    Monitoring. For detailed info: [Types of
    nodes](https://www.cisco.com/en/US/docs/security/ise/1.0/user_guide/ise10_dis_deploy.html#wp1123452)
    -   All actions can run on Administration node.
    -   Actions create resource, update resource, delete resource, list resource, get resources,
        list sessions, update device info, get device info, and list endpoints can run on Monitoring
        node
    -   Actions quarantine device, unquarantine device, apply policy, clear policy, and terminate
        session can run on Policy Service node
4.  For create resource action, user needs to provide valid json with required fields of that
    specified resource (For more details head over to [API
    Reference](https://developer.cisco.com/docs/identity-services-engine/v1/#!endpoint) ). Examples
    as below
    -   Endpoint

            {
                "ERSEndPoint": {
                    "name": "name",
                    "description": "MyEndpoint",
                    "mac": "11:22:33:44:55:66"
                }
            }
                

    -   Endpoint identity groups

            {
                "EndPointGroup": {
                    "name": "Cisco-Meraki-Device",
                    "description": "Identity Group for Profile: Cisco-Meraki-Device",
                    "systemDefined": "true"
                }
            }
                

    -   Guest users

            {
                "GuestUser": {
                    "name": "guestUser",
                    "guestInfo": {
                      "userName": "DS3ewdsa34wWE",
                      "password": "asdlkj324ew", 
                      "enabled": true
                    },
                    "guestAccessInfo": {
                        "validDays": 90
                    }
                }
            }
                

    -   User identity groups

            {
                "IdentityGroup": {
                    "name": "GuestType_Weekly (default)",
                    "parent": "NAC Group:NAC:IdentityGroups:User Identity Groups"
                }
            }
                

    -   Internal users

            {
                "InternalUser": {
                    "name": "name",
                    "enabled": true,
                    "password": "*******",
                    "changePassword": true,
                    "passwordIDStore": "Internal Users" 
                }
            }
                

    -   Network devices

            {
                  "NetworkDevice": {
                        "name": "ISE_EST_Local_Host",
                        "authenticationSettings": {
                            "enableKeyWrap": true,
                            "enableMultiSecret": true,
                            "keyEncryptionKey": 1234567890123456,
                            "keyInputFormat": "ASCII"
                        },
                        "coaPort": 0,
                        "snmpsettings": {
                            "pollingInterval": 3600,
                            "linkTrapQuery": true,
                            "macTrapQuery": true,
                            "originatingPolicyServicesNode": "Auto"
                        },
                        "trustsecsettings": {
                            "deviceAuthenticationSettings": {},
                            "sgaNotificationAndUpdates": {},
                            "deviceConfigurationDeployment": {},
                            "pushIdSupport": false
                        },
                        "tacacsSettings": {
                            "sharedSecret": "aaa" 
                        },
                        "profileName": "Cisco",
                        "NetworkDeviceIPList": [
                            {
                                "ipaddress": "127.0.0.1",
                                "mask": 32
                            }
                        ]
                  }
            }
                

    -   Network device groups

            {
                "NetworkDeviceGroup": {
                    "name": "Device Type#All Device Types"
                }
            }
                

    -   Security groups

            {
                "Sgt": {
                    "name": "Employees",
                    "value": 4
                }
            }
                

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Cisco ISE server. Below are the default
ports used by Splunk SOAR.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Cisco ISE asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**device** |  required  | string | Device IP/Hostname
**ha\_device** |  optional  | string | Device IP/Hostname for a High Availability node if available
**username** |  required  | string | Username
**password** |  required  | password | Password
**ers\_user** |  optional  | string | Username for ERS APIs
**ers\_password** |  optional  | password | Password for ERS APIs
**verify\_server\_cert** |  optional  | boolean | Verify server certificate

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity\. This action logs into the device using a REST API call to check the connection and credentials  
[list endpoints](#action-list-endpoints) - List the endpoints configured on the system  
[get device info](#action-get-device-info) - Get information about a specific endpoint  
[update device info](#action-update-device-info) - Update information or attributes for a specific endpoint  
[list sessions](#action-list-sessions) - List the sessions currently available on the Monitoring node  
[quarantine device](#action-quarantine-device) - Quarantine the device  
[unquarantine device](#action-unquarantine-device) - Unquarantine the device  
[terminate session](#action-terminate-session) - Terminate sessions  
[list resources](#action-list-resources) - Lists all the resources configured on the system of a particular resource  
[get resources](#action-get-resources) - Get the information about resource if resource\_id is provided\. Fetch the list of resources match with the key\-value filter  
[delete resource](#action-delete-resource) - Delete a resource  
[create resource](#action-create-resource) - Create a resource  
[update resource](#action-update-resource) - Update a resource  
[apply policy](#action-apply-policy) - Apply policy on selected Ip address or MAC address  
[clear policy](#action-clear-policy) - Clear policy on selected Ip address or MAC address  

## action: 'test connectivity'
Validate the asset configuration for connectivity\. This action logs into the device using a REST API call to check the connection and credentials

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list endpoints'
List the endpoints configured on the system

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**mac\_address** |  optional  | Mac Address to filter on \(6 bytes, colon separated\) | string |  `mac address` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.mac\_address | string |  `mac address` 
action\_result\.data\.\*\.SearchResult\.resources\.\*\.id | string |  `ise endpoint id`  `ise resource id` 
action\_result\.data\.\*\.SearchResult\.resources\.\*\.link\.href | string |  `url` 
action\_result\.data\.\*\.SearchResult\.resources\.\*\.link\.rel | string | 
action\_result\.data\.\*\.SearchResult\.resources\.\*\.link\.type | string | 
action\_result\.data\.\*\.SearchResult\.resources\.\*\.name | string | 
action\_result\.data\.\*\.SearchResult\.total | numeric | 
action\_result\.summary\.Endpoints found | string | 
action\_result\.summary\.endpoints\_found | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get device info'
Get information about a specific endpoint

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**endpoint\_id** |  required  | ISE Endpoint ID for device | string |  `ise endpoint id`  `ise resource id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.endpoint\_id | string |  `ise endpoint id`  `ise resource id` 
action\_result\.data\.\*\.ERSEndPoint\.customAttributes\.customAttributes\.ITSecurityBlock | string | 
action\_result\.data\.\*\.ERSEndPoint\.description | string | 
action\_result\.data\.\*\.ERSEndPoint\.groupId | string | 
action\_result\.data\.\*\.ERSEndPoint\.id | string |  `ise endpoint id`  `ise resource id` 
action\_result\.data\.\*\.ERSEndPoint\.identityStore | string | 
action\_result\.data\.\*\.ERSEndPoint\.identityStoreId | string | 
action\_result\.data\.\*\.ERSEndPoint\.link\.href | string |  `url` 
action\_result\.data\.\*\.ERSEndPoint\.link\.rel | string | 
action\_result\.data\.\*\.ERSEndPoint\.link\.type | string | 
action\_result\.data\.\*\.ERSEndPoint\.mac | string | 
action\_result\.data\.\*\.ERSEndPoint\.name | string | 
action\_result\.data\.\*\.ERSEndPoint\.portalUser | string | 
action\_result\.data\.\*\.ERSEndPoint\.profileId | string | 
action\_result\.data\.\*\.ERSEndPoint\.staticGroupAssignment | boolean | 
action\_result\.data\.\*\.ERSEndPoint\.staticProfileAssignment | boolean | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update device info'
Update information or attributes for a specific endpoint

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**endpoint\_id** |  required  | ISE Endpoint ID for device | string |  `ise endpoint id`  `ise resource id` 
**attribute** |  optional  | Attribute to update for the Endpoint | string | 
**attribute\_value** |  optional  | Value to put in the attribute for the Endpoint | string | 
**custom\_attribute** |  optional  | Custom attribute to update for the Endpoint | string | 
**custom\_attribute\_value** |  optional  | Value to put in the custom attribute for the Endpoint | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.attribute | string | 
action\_result\.parameter\.attribute\_value | string | 
action\_result\.parameter\.custom\_attribute | string | 
action\_result\.parameter\.custom\_attribute\_value | string | 
action\_result\.parameter\.endpoint\_id | string |  `ise endpoint id`  `ise resource id` 
action\_result\.data\.\*\.UpdatedFieldsList\.updatedField\.\*\.field | string | 
action\_result\.data\.\*\.UpdatedFieldsList\.updatedField\.\*\.newValue | string | 
action\_result\.data\.\*\.UpdatedFieldsList\.updatedField\.\*\.oldValue | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list sessions'
List the sessions currently available on the Monitoring node

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.acct\_session\_id | string | 
action\_result\.data\.\*\.audit\_session\_id | string |  `ise session id` 
action\_result\.data\.\*\.calling\_station\_id | string |  `mac address` 
action\_result\.data\.\*\.framed\_ip\_address | string |  `ip` 
action\_result\.data\.\*\.framed\_ipv6\_address | string | 
action\_result\.data\.\*\.is\_quarantined | string | 
action\_result\.data\.\*\.nas\_ip\_address | string |  `nas server` 
action\_result\.data\.\*\.server | string |  `ise server` 
action\_result\.data\.\*\.user\_name | string |  `user name` 
action\_result\.summary | string | 
action\_result\.summary\.sessions\_found | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'quarantine device'
Quarantine the device

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_macaddress** |  required  | MAC or IP address of device to quarantine | string |  `mac address`  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_macaddress | string |  `mac address`  `ip` 
action\_result\.data | string | 
action\_result\.data\.\*\.EPS\_RESULT\.errorCode | string | 
action\_result\.data\.\*\.EPS\_RESULT\.operationID | string | 
action\_result\.data\.\*\.EPS\_RESULT\.requestID | string | 
action\_result\.data\.\*\.EPS\_RESULT\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unquarantine device'
Unquarantine the device

Type: **correct**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip\_macaddress** |  required  | MAC or IP address of device to unquarantine | string |  `mac address`  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip\_macaddress | string |  `mac address`  `ip` 
action\_result\.data | string | 
action\_result\.data\.\*\.EPS\_RESULT\.errorCode | string | 
action\_result\.data\.\*\.EPS\_RESULT\.operationID | string | 
action\_result\.data\.\*\.EPS\_RESULT\.requestID | string | 
action\_result\.data\.\*\.EPS\_RESULT\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'terminate session'
Terminate sessions

Type: **contain**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**macaddress** |  required  | MAC address of device to terminate sessions of | string |  `mac address` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.macaddress | string |  `mac address` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list resources'
Lists all the resources configured on the system of a particular resource

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**resource** |  required  | Resource type of the resources to fetch | string | 
**max\_results** |  optional  | Total number of observables to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.max\_results | numeric | 
action\_result\.parameter\.resource | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.id | string |  `ise resource id` 
action\_result\.data\.\*\.link\.href | string |  `url` 
action\_result\.data\.\*\.link\.rel | string | 
action\_result\.data\.\*\.link\.type | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.summary\.resources\_returned | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get resources'
Get the information about resource if resource\_id is provided\. Fetch the list of resources match with the key\-value filter

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**resource** |  required  | Resource type of the resource to fetch | string | 
**resource\_id** |  optional  | Resource ID | string |  `ise resource id` 
**key** |  optional  | Key | string | 
**value** |  optional  | Value | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.key | string | 
action\_result\.parameter\.resource | string | 
action\_result\.parameter\.resource\_id | string |  `ise resource id` 
action\_result\.parameter\.value | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.groupId | string | 
action\_result\.data\.\*\.id | string |  `ise resource id` 
action\_result\.data\.\*\.identityStore | string | 
action\_result\.data\.\*\.identityStoreId | string | 
action\_result\.data\.\*\.link\.href | string |  `url` 
action\_result\.data\.\*\.link\.rel | string | 
action\_result\.data\.\*\.link\.type | string | 
action\_result\.data\.\*\.mac | string | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.portalUser | string | 
action\_result\.data\.\*\.profileId | string | 
action\_result\.data\.\*\.staticGroupAssignment | boolean | 
action\_result\.data\.\*\.staticProfileAssignment | boolean | 
action\_result\.summary\.resource\_id | string |  `ise resource id` 
action\_result\.summary\.resources\_returned | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete resource'
Delete a resource

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**resource** |  required  | Resource type of the resource to be deleted | string | 
**resource\_id** |  required  | Resource ID | string |  `ise resource id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.resource | string | 
action\_result\.parameter\.resource\_id | string |  `ise resource id` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'create resource'
Create a resource

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**resource** |  required  | Resource type of the resource to be created | string | 
**resource\_json** |  required  | JSON which contains all values needed to create a resource | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.resource | string | 
action\_result\.parameter\.resource\_json | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update resource'
Update a resource

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**resource** |  required  | Resource type of the resource to be created | string | 
**resource\_id** |  required  | ID of resource | string |  `ise resource id` 
**key** |  required  | Key of resource which needs to be updated | string | 
**value** |  required  | New value of key | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.key | string | 
action\_result\.parameter\.resource | string | 
action\_result\.parameter\.resource\_id | string |  `ise resource id` 
action\_result\.parameter\.value | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'apply policy'
Apply policy on selected Ip address or MAC address

Type: **investigate**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**policy\_name** |  required  | Policy Name | string | 
**ip\_mac\_address** |  required  | MAC or IP Address of the device | string |  `mac address`  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip\_mac\_address | string |  `mac address`  `ip` 
action\_result\.parameter\.policy\_name | string | 
action\_result\.message | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.status | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'clear policy'
Clear policy on selected Ip address or MAC address

Type: **investigate**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**policy\_name** |  required  | Policy Name | string | 
**ip\_mac\_address** |  required  | MAC or IP Address of the device | string |  `mac address`  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.ip\_mac\_address | string |  `mac address`  `ip` 
action\_result\.parameter\.policy\_name | string | 
action\_result\.message | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.status | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 