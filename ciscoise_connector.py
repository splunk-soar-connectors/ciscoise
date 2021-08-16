# --
# File: ciscoise_connector.py
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

# Phantom imports
import phantom.app as phantom

from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# THIS Connector imports
from ciscoise_consts import *
from cerberus import Validator

import xmltodict
import requests
from requests.auth import HTTPBasicAuth


class CiscoISEConnector(BaseConnector):

    # actions supported by this script
    ACTION_ID_LIST_SESSIONS = "list_sessions"
    ACTION_ID_TERMINATE_SESSION = "terminate_session"
    ACTION_ID_LOGOFF_SYSTEM = "logoff_system"
    ACTION_ID_QUARANTINE_SYSTEM = "quarantine_device"
    ACTION_ID_UNQUARANTINE_SYSTEM = "unquarantine_device"
    ACTION_ID_LIST_ENDPOINTS = "list_endpoints"
    ACTION_ID_GET_ENDPOINT = "get_endpoint"
    ACTION_ID_UPDATE_ENDPOINT = "update_endpoint"

    def __init__(self):

        # Call the BaseConnectors init first
        super(CiscoISEConnector, self).__init__()

        self._base_url = None
        self._auth = None

    def initialize(self):

        config = self.get_config()

        self._auth = HTTPBasicAuth(config[phantom.APP_JSON_USERNAME], config[phantom.APP_JSON_PASSWORD])
        ers_user = config.get("ers_user", None)
        if ers_user is not None:
            self._ers_auth = HTTPBasicAuth(config["ers_user"], config["ers_password"])
        self._base_url = 'https://{0}'.format(config[phantom.APP_JSON_DEVICE])

        return phantom.APP_SUCCESS

    def _call_ers_api(self, endpoint, action_result, data=None, allow_unknown=True):

        url = '{0}{1}'.format(self._base_url, endpoint)
        ret_data = None
        self.debug_print("REST Endpoint: ", url)

        config = self.get_config()
        verify = config[phantom.APP_JSON_VERIFY]
        try:
            headers = {"Content-Type": "application/json", "ACCEPT": "application/json"}
            if data is not None:
                resp = requests.put(url, json=data, verify=verify, headers=headers, auth=self._ers_auth)
            else:
                resp = requests.get(url, verify=verify, headers=headers, auth=self._ers_auth)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, CISCOISE_ERR_REST_API, e), ret_data

        self.debug_print("status_code", resp.status_code)

        if resp.status_code != 200:
            return action_result.set_status(phantom.APP_ERROR, CISCOISE_ERR_REST_API_ERR_CODE, code=resp.status_code, message=resp.text), ret_data

        ret_data = resp.json()
        self.debug_print(ret_data)

        return phantom.APP_SUCCESS, ret_data

    def _call_rest_api(self, endpoint, action_result, schema=None, data=None, allow_unknown=True):

        url = '{0}{1}'.format(self._base_url, endpoint)
        ret_data = None
        self.debug_print("REST Endpoint: ", url)

        config = self.get_config()
        verify = config[phantom.APP_JSON_VERIFY]

        try:
            resp = requests.get(url, verify=verify, auth=self._auth)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, CISCOISE_ERR_REST_API, e), ret_data

        self.debug_print("status_code", resp.status_code)

        if resp.status_code != 200:
            return action_result.set_status(phantom.APP_ERROR, CISCOISE_ERR_REST_API_ERR_CODE, code=resp.status_code, message=resp.text), ret_data

        action_result.add_debug_data(resp.text)
        xml = resp.text

        try:
            response_dict = xmltodict.parse(xml)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, CISCOISE_ERR_UNABLE_TO_PARSE_REPLY, e), ret_data

        ret_data = response_dict

        if schema is not None:
            v = Validator(schema, allow_unknown=allow_unknown)
            if v.validate(ret_data) is False:
                action_result.set_status(phantom.APP_ERROR, CISCOISE_ERR_UNABLE_TO_PARSE_REPLY)
                action_result.append_to_message(v.errors)
                return action_result.get_status(), ret_data

        return phantom.APP_SUCCESS, ret_data

    def _list_sessions(self, param):

        ret_val = phantom.APP_SUCCESS

        action_result = self.add_action_result(ActionResult(dict(param)))

        summary = action_result.update_summary({CISCOISE_JSON_TOTAL_SESSIONS: 0})

        ret_data = None

        ret_val, ret_data = self._call_rest_api(ACTIVE_LIST_REST, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.debug_print("ret_data", ret_data)

        if 'activeList' not in ret_data:
            return action_result.set_status(phantom.APP_SUCCESS)

        active_sessions = ret_data['activeList'].get('activeSession')

        if active_sessions is None:
            return action_result.set_status(phantom.APP_SUCCESS)

        # Convert the dict into list, so the rest of the code is the same
        if isinstance(active_sessions, dict):
            act_sess_list = []
            act_sess_list.append(active_sessions)
            active_sessions = act_sess_list

        for session in active_sessions:

            action_result.add_data(session)

            # Init the value of the quarantine status of the session to unknown
            session['is_quarantined'] = "Unknown"

            # Get the quarantined state of the mac address
            is_quarantined_rest = "{0}/{1}".format(IS_MAC_QUARANTINED_REST, session['calling_station_id'])

            ret_val, ret_data = self._call_rest_api(is_quarantined_rest, action_result, IS_MAC_QUARAN_RESP_SCHEMA)

            if phantom.is_fail(ret_val):
                continue

            # Can safely access the members of ret_data, since they have been parsed as by the rules of
            # IS_MAC_QUARAN_RESP_SCHEMA
            session['is_quarantined'] = "Yes" if ret_data["EPS_RESULT"]["userData"] == "true" else "No"

        summary.update({CISCOISE_JSON_TOTAL_SESSIONS: len(active_sessions)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _list_endpoints(self, param):

        ret_val = phantom.APP_SUCCESS

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_data = None
        endpoint = ERS_ENDPOINT_REST

        mac_filter = param.get("mac_address", None)
        if mac_filter is not None:
            endpoint = ERS_ENDPOINT_REST + "?filter=mac.EQ." + mac_filter

        ret_val, ret_data = self._call_ers_api(endpoint, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        total = ret_data["SearchResult"]["total"]

        action_result.update_summary({"Endpoints found": total})

        action_result.add_data(ret_data)

        return action_result.set_status(phantom.APP_SUCCESS, CISCOISE_SUCC_LIST_ENDPOINTS.format(total))

    def _get_endpoint(self, param):

        ret_val = phantom.APP_SUCCESS

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_data = None
        endpoint = ERS_ENDPOINT_REST + "/" + param["endpoint_id"]

        ret_val, ret_data = self._call_ers_api(endpoint, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # total = ret_data["ns2:searchResult"]["@total"]
        # action_result.update_summary({"Endpoints found": total})

        action_result.add_data(ret_data)

        return action_result.set_status(phantom.APP_SUCCESS, CISCOISE_SUCC_GET_ENDPOINT)

    def _update_endpoint(self, param):

        action_result = self.add_action_result(ActionResult(dict(param)))

        endpoint = ERS_ENDPOINT_REST + "/" + param["endpoint_id"]
        attribute = param.get('attribute', None)
        attribute_value = param.get('attribute_value', None)
        custom_attribute = param.get('custom_attribute', None)
        custom_attribute_value = param.get('custom_attribute_value', None)

        final_data = {"ERSEndPoint": {}}

        if attribute is not None and attribute_value is not None:
            final_data['ERSEndPoint'][attribute] = attribute_value

        if custom_attribute is not None and custom_attribute_value is not None:
            custom_attribute_dict = {"customAttributes": {custom_attribute: custom_attribute_value}}
            final_data["ERSEndPoint"]["customAttributes"] = custom_attribute_dict

        ret_val, ret_data = self._call_ers_api(endpoint, action_result, data=final_data)
        action_result.add_data(ret_data)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, "Endpoint Updated")

    def _quarantine_system(self, param):

        ret_val = phantom.APP_SUCCESS

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_data = None

        mac_ip_address = param[phantom.APP_JSON_IP_MACADDRESS]

        if phantom.is_mac(mac_ip_address):
            endpoint = '{0}/{1}'.format(QUARANTINE_MAC_REST, mac_ip_address)
        elif phantom.is_ip(mac_ip_address):
            endpoint = '{0}/{1}'.format(QUARANTINE_IP_REST, mac_ip_address)
        else:
            return action_result.set_status(phantom.APP_ERROR, CISCOISE_ERR_MAC_AND_IP_NOT_SPECIFIED)

        ret_val, ret_data = self._call_rest_api(endpoint, action_result, QUARANTINE_RESP_SCHEMA)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(ret_data)

        # Can safely access the members of ret_data, since they have been parsed as by the rules of
        # QUARANTINE_RESP_SCHEMA
        status = ret_data['EPS_RESULT']["status"]

        if status == "Failure":
            return action_result.set_status(phantom.APP_ERROR, CISCOISE_ERR_ACTION_FAILED, error_code=ret_data['EPS_RESULT']['errorCode'])

        # In cases where the radius authentication failed, the status is STILL set to success,
        # but failureType and failureMessage keys are added to the ret_data, so need to check for those
        failure_type = phantom.get_value(ret_data['EPS_RESULT'], 'failureType')
        failure_msg = phantom.get_value(ret_data['EPS_RESULT'], 'failureMessage')

        if (failure_type is not None) or (failure_msg is not None):
            action_result.set_status(phantom.APP_ERROR, CISCOISE_ERR_ACTION_FAILED, error_code=ret_data['EPS_RESULT']['errorCode'])
            if failure_type is not None:
                action_result.append_to_message(failure_type)
            if failure_msg is not None:
                action_result.append_to_message(failure_msg)
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, CISCOISE_SUCC_SYSTEM_QUARANTINED)

    def _unquarantine_system(self, param):

        ret_val = phantom.APP_SUCCESS

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_data = None

        mac_ip_address = param[phantom.APP_JSON_IP_MACADDRESS]

        if phantom.is_mac(mac_ip_address):
            endpoint = '{0}/{1}'.format(UNQUARANTINE_MAC_REST, mac_ip_address)
        elif phantom.is_ip(mac_ip_address):
            endpoint = '{0}/{1}'.format(UNQUARANTINE_IP_REST, mac_ip_address)
        else:
            return action_result.set_status(phantom.APP_ERROR, CISCOISE_ERR_MAC_AND_IP_NOT_SPECIFIED)

        ret_val, ret_data = self._call_rest_api(endpoint, action_result, QUARANTINE_RESP_SCHEMA)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(ret_data)

        status = ret_data['EPS_RESULT']["status"]

        if status == "Failure":
            return action_result.set_status(phantom.APP_ERROR, CISCOISE_ERR_ACTION_FAILED, error_code=ret_data['EPS_RESULT']['errorCode'])

        # In cases where the radius authentication failed, the status is STILL set to success,
        # but failureType and failureMessage keys are added to the ret_data, so need to check for those
        failure_type = phantom.get_value(ret_data['EPS_RESULT'], 'failureType')
        failure_msg = phantom.get_value(ret_data['EPS_RESULT'], 'failureMessage')

        if (failure_type is not None) or (failure_msg is not None):
            action_result.set_status(phantom.APP_ERROR, CISCOISE_ERR_ACTION_FAILED, error_code=ret_data['EPS_RESULT']['errorCode'])
            if failure_type is not None:
                action_result.append_to_message(failure_type)
            if failure_msg is not None:
                action_result.append_to_message(failure_msg)
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, CISCOISE_SUCC_SYSTEM_UNQUARANTINED)

    def _logoff_system(self, param):

        ret_val = phantom.APP_SUCCESS

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_data = None

        server = param[CISCOISE_JSON_SERVER]
        mac_address = param[CISCOISE_JSON_MACADDR]
        port = 2  # 0 is default, 1 is bounce, 2 is shutdown

        endpoint = '{0}/{1}/{2}/{3}'.format(REAUTH_MAC_REST, server, mac_address, port)

        ret_val, ret_data = self._call_rest_api(endpoint, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(ret_data)

        remote_coa = ret_data.get('remoteCoA')

        if remote_coa is None:
            return action_result.set_status(phantom.APP_ERROR, CISCOISE_ERR_PARSE_REPLY)

        result = remote_coa.get('results')

        if result is None:
            return action_result.set_status(phantom.APP_ERROR, CISCOISE_ERR_PARSE_REPLY)

        if result == "false":
            return action_result.set_status(phantom.APP_ERROR, CISCOISE_ERR_LOGOFF_SYSTEM)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _terminate_session(self, param):

        ret_val = phantom.APP_SUCCESS

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_data = None

        mac_address = param[phantom.APP_JSON_MACADDRESS]
        port = 2  # 0 is default, 1 is bounce, 2 is shutdown

        # First try to find the server that we should use
        endpoint = '{0}/{1}'.format(MAC_SESSION_DETAILS_REST, mac_address)

        ret_val, ret_data = self._call_rest_api(endpoint, action_result, MAC_SESSION_RESP_SCHEMA)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        acs_server = ret_data['sessionParameters']['acs_server']

        # now terminate the session
        endpoint = '{0}/{1}/{2}/{3}'.format(DISCONNECT_MAC_REST, acs_server, mac_address, port)

        ret_val, ret_data = self._call_rest_api(endpoint, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        remote_coa = ret_data.get('remoteCoA')

        if remote_coa is None:
            return action_result.set_status(phantom.APP_ERROR, CISCOISE_ERR_PARSE_REPLY)

        result = remote_coa.get('results')

        if result is None:
            return action_result.set_status(phantom.APP_ERROR, CISCOISE_ERR_PARSE_REPLY)

        if result == "false":
            return action_result.set_status(phantom.APP_ERROR, CISCOISE_ERR_TERMINATE_SESSION)

        return action_result.set_status(phantom.APP_SUCCESS, CISCOISE_SUCC_SESSION_TERMINATED)

    def _test_connectivity(self, param):

        rest_endpoint = '{0}/{1}'.format(self._base_url, ACTIVE_COUNT_REST_ENDPOINT)

        config = self.get_config()

        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, config[phantom.APP_JSON_DEVICE])
        verify = config[phantom.APP_JSON_VERIFY]

        try:
            resp = requests.get(rest_endpoint, auth=self._auth, verify=verify)
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, CISCOISE_ERR_TEST_CONNECTIVITY_FAILED, e)

        if resp.status_code != 200:
            return self.set_status(phantom.APP_ERROR, CISCOISE_ERR_TEST_CONNECTIVITY_FAILED_ERR_CODE, code=resp.status_code)

        return self.set_status_save_progress(phantom.APP_SUCCESS, CISCOISE_SUCC_TEST_CONNECTIVITY_PASSED)

    def handle_action(self, param):

        result = None
        action = self.get_action_identifier()

        if action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            result = self._test_connectivity(param)
        elif action == self.ACTION_ID_LIST_SESSIONS:
            result = self._list_sessions(param)
        elif action == self.ACTION_ID_TERMINATE_SESSION:
            result = self._terminate_session(param)
        elif action == self.ACTION_ID_LOGOFF_SYSTEM:
            result = self._logoff_system(param)
        elif action == self.ACTION_ID_QUARANTINE_SYSTEM:
            result = self._quarantine_system(param)
        elif action == self.ACTION_ID_UNQUARANTINE_SYSTEM:
            result = self._unquarantine_system(param)
        elif action == self.ACTION_ID_LIST_ENDPOINTS:
            result = self._list_endpoints(param)
        elif action == self.ACTION_ID_GET_ENDPOINT:
            result = self._get_endpoint(param)
        elif action == self.ACTION_ID_UPDATE_ENDPOINT:
            result = self._update_endpoint(param)

        return result


if __name__ == '__main__':

    import sys
    import json
    import pudb
    pudb.set_trace()

    if len(sys.argv) < 2:
        print("No test json specified as input")
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CiscoISEConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
