# File: ciscoise_consts.py
#
# Copyright (c) 2014-2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# Jsons
CISCOISE_JSON_SERVER = "server"
CISCOISE_JSON_MACADDR = "mac_address"
CISCOISE_JSON_TOTAL_SESSIONS = "sessions_found"

# REST endpoint Consts
ACTIVE_LIST_REST = "/admin/API/mnt/Session/ActiveList"
AUTH_LIST_REST_ENDPOINT = "/ise/mnt/Session/AuthList/null/null"
DISCONNECT_MAC_REST = "/ise/mnt/CoA/Disconnect"
REAUTH_MAC_REST = "/ise/mnt/CoA/Reauth"
IS_MAC_QUARANTINED_REST = "/ise/eps/isQuarantineByMAC"
QUARANTINE_MAC_REST = "/ise/eps/QuarantineByMAC_S"
QUARANTINE_IP_REST = "/ise/eps/QuarantineByIP_S"
UNQUARANTINE_MAC_REST = "/ise/eps/UnQuarantineByMAC_S"
UNQUARANTINE_IP_REST = "/ise/eps/UnQuarantineByIP_S"
MAC_SESSION_DETAILS_REST = "/ise/mnt/Session/MACAddress"
ERS_ENDPOINT_REST = ":9060/ers/config/endpoint"
ERS_RESOURCE_REST = ":9060/ers/config/{resource}"
ERS_ENDPOINT_ANC_APPLY = ":9060/ers/config/ancendpoint/apply"
ERS_ENDPOINT_ANC_CLEAR = ":9060/ers/config/ancendpoint/clear"

# Error/Success
CISCOISE_ERR_TEST_CONNECTIVITY_FAILED = "Test connectivity failed"
CISCOISE_ERR_TEST_CONNECTIVITY_FAILED_ERR_CODE = "Test connectivity failed with status code: '{code}'"
CISCOISE_SUCC_TEST_CONNECTIVITY_PASSED = "Test connectivity passed"
CISCOISE_ERR_REST_API = "REST Api error"
CISCOISE_ERR_REST_API_ERR_CODE = "REST Api error with status code: {code}, Message from server: {message}"
CISCOISE_ERR_UNABLE_TO_PARSE_REPLY = "Parsing error, Unable to convert xml reply to json"
CISCOISE_SUCC_SESSION_TERMINATED = "Session terminated"
CISCOISE_ERR_PARSE_REPLY = "Error parsing reply"
CISCOISE_ERR_TERMINATE_SESSION = "Session termination failed. Session possibly not found"
CISCOISE_ERR_LOGOFF_SYSTEM = "System Logoff failed"
CISCOISE_ERR_MAC_AND_IP_NOT_SPECIFIED = "Please specify a valid mac or ip address to execute action"
CISCOISE_ERR_ACTION_FAILED = "Action failed with error code: {error_code}"
CISCOISE_SUCC_SYSTEM_QUARANTINED = "System Quarantined"
CISCOISE_SUCC_SYSTEM_UNQUARANTINED = "System unquarantined"
CISCOISE_SUCC_LIST_ENDPOINTS = "{0} Endpoints found"
CISCOISE_SUCC_GET_ENDPOINT = "Endpoint found"
CISCOISE_SUCC_UPDATE_ENDPOINT = "Endpoint updated"
CISCOISE_ERR_INVALID_PARAM = "Please provide non-zero positive integer in {param}"
CISCOISE_MAP_IP_ABSENT_ERROR = "Please provide either mac address or ip address"
DEFAULT_MAX_RESULTS = 7

# Json reply schema
IS_MAC_QUARAN_RESP_SCHEMA = {"EPS_RESULT": {"type": "dict", "schema": {"status": {"type": "string"}, "userData": {"type": "string"}}}}
QUARANTINE_RESP_SCHEMA = {"EPS_RESULT": {"type": "dict", "schema": {"status": {"type": "string"}, "errorCode": {"type": "string"}}}}
MAC_SESSION_RESP_SCHEMA = {"sessionParameters": {"type": "dict", "schema": {"acs_server": {"type": "string"}}}}
DISCONNECT_MAC_SESS_RESP_SCHEMA = {"remoteCoA": {"type": "dict", "schema": {"results": {"type": "string"}}}}
ERS_UPDATE_ENDPOINT_SCHEMA = {"updatedField": {"type": "dict", "schema": {"newValue": {"type": "string"}, "oldValue": {"type": "string"}}}}

MAP_RESOURCE = {
    "Endpoints": ["endpoint", "ERSEndPoint"],
    "Endpoint identity groups": ["endpointgroup", "EndPointGroup"],
    "Guest users": ["guestuser", "GuestUser"],
    "User identity groups": ["identitygroup", "IdentityGroup"],
    "Internal users": ["internaluser", "InternalUser"],
    "Network devices": ["networkdevice", "NetworkDevice"],
    "Network device groups": ["networkdevicegroup", "NetworkDeviceGroup"],
    "Security groups": ["sgt", "Sgt"]
}
