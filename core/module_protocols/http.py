#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import requests
import copy
import random
from core.utility import reverse_and_regex_condition
from core.utility import process_conditions
from core.utility import get_dependent_results_from_database
from core.utility import replace_dependent_values


def response_conditions_matched(sub_step, response):
    if not response:
        return []
    condition_type = sub_step['response']['condition_type']
    conditions = sub_step['response']['conditions']
    condition_results = {}
    for condition in conditions:
        if condition in ['reason', 'status_code', 'content']:
            regex = re.findall(re.compile(conditions[condition]['regex']), response[condition])
            reverse = conditions[condition]['reverse']
            if 'reason' in conditions:
                condition_results['reason'] = reverse_and_regex_condition(regex, reverse)
            if 'status_code' in conditions:
                condition_results['status_code'] = reverse_and_regex_condition(regex, reverse)
            if 'content' in conditions:
                condition_results['content'] = reverse_and_regex_condition(regex, reverse)
        if condition == 'headers':
            # convert headers to case insensitive dict
            for key in response["headers"].copy():
                response['headers'][key.lower()] = response['headers'][key]
            condition_results['headers'] = {}
            for header in conditions['headers']:
                reverse = conditions['headers'][header]['reverse']
                regex = re.findall(
                    re.compile(conditions['headers'][header]['regex']),
                    response['headers'][header.lower()] if header.lower() in response['headers'] else ""
                )
                condition_results['headers'][header] = reverse_and_regex_condition(regex, reverse)
        if condition == 'responsetime':
            if len(conditions[condition].split()) == 2 and conditions[condition].split()[0] in [
                "==",
                "!=",
                ">=",
                "<=",
                ">",
                "<"
            ]:
                exec(
                    "condition_results['responsetime'] = response['responsetime'] if (" +
                    "response['responsetime'] {0} float(conditions['responsetime'].split()[-1])".format(
                        conditions['responsetime'].split()[0]
                    ) +
                    ") else []"

                )
            else:
                condition_results['responsetime'] = []
    if condition_type.lower() == "or":
        # if one of the values are matched, it will be a string or float object in the array
        # we count False in the array and if it's not all []; then we know one of the conditions is matched.
        if (
                'headers' not in condition_results and
                (
                        list(condition_results.values()).count([]) != len(list(condition_results.values()))
                )
        ) or (
                'headers' in condition_results and
                (
                        (
                                list(condition_results.values()).count([]) - 1 !=
                                len(list(condition_results.values()))
                        ) and
                        (
                                list(condition_results['headers'].values()).count([]) !=
                                len(list(condition_results['headers'].values()))
                        )
                )
        ):
            return condition_results
        else:
            return []
    if condition_type.lower() == "and":
        if [] in condition_results.values() or \
                ('headers' in condition_results and [] in condition_results['headers'].values()):
            return []
        else:
            return condition_results
    return []


class Engine:
    def run(self, module_name, target, scan_unique_id, options, process_number, module_thread_number, total_module_thread_number, request_number_counter, total_number_of_requests):
        backup_method = copy.deepcopy(self['method'])
        backup_response = copy.deepcopy(self['response'])
        action = getattr(requests, backup_method, None)
        if options['user_agent'] == 'random_user_agent':
            self['headers']['User-Agent'] = random.choice(options['user_agents'])
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
        for _ in range(options['retries']):
            try:
                response = action(**self)
                response = {
                    "reason": response.reason,
                    "status_code": str(response.status_code),
                    "content": response.content.decode(errors="ignore"),
                    "headers": dict(response.headers),
                    "responsetime": response.elapsed.total_seconds()
                }
                break
            except Exception:
                response = []
        self['method'] = backup_method
        self['response'] = backup_response
        self['response']['conditions_results'] = response_conditions_matched(
            self, response
        )

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
