#!/usr/bin/env python
# -*- coding: utf-8 -*-

import copy
import ftplib
# from core.utility import reverse_and_regex_condition
from core.utility import process_conditions
from core.utility import get_dependent_results_from_database
from core.utility import replace_dependent_values


# def response_conditions_matched(sub_step, response):
#     return response


class NettackFTPLib:
    def ftp_brute_force(self, ports, usernames, passwords, timeout):
        ftp_connection = ftplib.FTP(timeout=int(timeout))
        ftp_connection.connect(self, int(ports))
        ftp_connection.login(usernames, passwords)
        ftp_connection.close()
        return {
            "host": self,
            "username": usernames,
            "password": passwords,
            "port": ports,
        }

    def ftps_brute_force(self, ports, usernames, passwords, timeout):
        ftp_connection = ftplib.FTP_TLS(timeout=int(timeout))
        ftp_connection.connect(self, int(ports))
        ftp_connection.login(usernames, passwords)
        ftp_connection.close()
        return {
            "host": self,
            "username": usernames,
            "password": passwords,
            "port": ports,
        }


class Engine:
    def run(self, module_name, target, scan_unique_id, options, process_number, module_thread_number, total_module_thread_number, request_number_counter, total_number_of_requests):
        backup_method = copy.deepcopy(self['method'])
        backup_response = copy.deepcopy(self['response'])
        del self['method']
        del self['response']
        if 'dependent_on_temp_event' in backup_response:
            temp_event = get_dependent_results_from_database(
                target,
                module_name,
                scan_unique_id,
                backup_response['dependent_on_temp_event']
            )
            self = replace_dependent_values(self, temp_event)
        action = getattr(NettackFTPLib, backup_method, None)
        for _ in range(options['retries']):
            try:
                response = action(**self)
                break
            except Exception as _:
                response = []
        self['method'] = backup_method
        self['response'] = backup_response
        self['response']['conditions_results'] = response
        # sub_step['response']['conditions_results'] = response_conditions_matched(sub_step, response)
        return process_conditions(
            self,
            module_name,
            target,
            scan_unique_id,
            options,
            response,
            process_number,
            module_thread_number,
            total_module_thread_number,
            request_number_counter,
            total_number_of_requests,
        )
