# --
# File: ciscoise_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Jsons
CISCOISE_JSON_TYPE = "type"
CISCOISE_JSON_SERVER = "server"
CISCOISE_JSON_MACADDR = "mac_address"
CISCOISE_JSON_TOTAL_SESSIONS = "sessions_found"
CISCOISE_JSON_ENDPOINT_IP = "endpoint_ip"
CISCOISE_JSON_NAS_IP = "nas_ip"

# REST endpoint Consts
ACTIVE_COUNT_REST_ENDPOINT = "/admin/API/mnt/Session/ActiveCount"
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

# Json reply schema
IS_MAC_QUARAN_RESP_SCHEMA = {"EPS_RESULT": {"type": "dict", "schema": {"status": {"type": "string"}, "userData": {"type": "string"}}}}
QUARANTINE_RESP_SCHEMA = {"EPS_RESULT": {"type": "dict", "schema": {"status": {"type": "string"}, "errorCode": {"type": "string"}}}}
MAC_SESSION_RESP_SCHEMA = {"sessionParameters": {"type": "dict", "schema": {"acs_server": {"type": "string"}}}}
DISCONNECT_MAC_SESS_RESP_SCHEMA = {"remoteCoA": {"type": "dict", "schema": {"results": {"type": "string"}}}}
