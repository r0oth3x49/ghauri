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
from ghauri.core.request import request
from ghauri.logger.colored_logger import logger
from ghauri.common.lib import re, time, collections, quote, unquote, URLError
from ghauri.common.utils import prepare_attack_request, urldecode


def inject_expression(
    url,
    data,
    proxy,
    delay=0,
    timesec=5,
    timeout=30,
    headers=None,
    parameter=None,
    expression=None,
    is_multipart=False,
    injection_type=None,
    connection_test=False,
):
    attack = None
    attack_url = url
    attack_data = data
    attack_headers = headers
    param_value = parameter.value
    if expression:
        expression = expression.replace("[ORIGVALUE]", param_value.replace("*", ""))
        logger.payload(f"{urldecode(expression)}")
    if conf.timeout and conf.timeout > 30:
        timeout = conf.timeout
    if not connection_test:
        if injection_type == "HEADER":
            attack_headers = prepare_attack_request(
                headers,
                expression,
                param=parameter,
                injection_type=injection_type,
            )
        if injection_type == "COOKIE":
            if not conf._is_cookie_choice_taken and not conf.skip_urlencoding:
                choice = logger.read_input(
                    "do you want to URL encode cookie values (implementation specific)? [Y/n] ",
                    batch=conf.batch,
                    user_input="Y",
                )
                if choice and choice != "n":
                    conf._encode_cookie = True
                conf._is_cookie_choice_taken = True
            attack_headers = prepare_attack_request(
                headers,
                expression,
                param=parameter,
                encode=conf._encode_cookie,
                injection_type=injection_type,
            )
        if injection_type == "GET":
            attack_url = prepare_attack_request(
                url,
                expression,
                param=parameter,
                encode=True,
                injection_type=injection_type,
            )

        if injection_type == "POST":
            attack_data = prepare_attack_request(
                data,
                expression,
                param=parameter,
                encode=True,
                injection_type=injection_type,
            )
    try:
        attack = request.perform(
            url=attack_url,
            data=attack_data,
            proxy=conf.proxy,
            headers=attack_headers,
            connection_test=connection_test,
            is_multipart=conf.is_multipart,
            timeout=timeout,
        )
        status_code = attack.status_code
        if status_code == 401:
            ignore_codes = conf.ignore_code
            show_err = False
            if not conf._shw_ignc and ignore_codes:
                logger.debug(
                    f"ghauri is going to ignore http status codes: '{ignore_codes}'"
                )
                conf._shw_ignc = True
            if ignore_codes and status_code in ignore_codes:
                show_err = False
            if not ignore_codes:
                show_err = True
            if show_err:
                errMsg = "not authorized, try to provide right HTTP "
                errMsg += "authentication type and valid credentials"
                errMsg += "If this is intended, try to rerun by providing "
                errMsg += "a valid value for option '--ignore-code'"
                logger.error(errMsg)
                logger.end("ending")
                exit(0)
    except URLError as e:
        response_ok = False
        conf.retry_counter += 1
        logger.critical(f"target URL is not responding, Ghauri is going to retry")
        if conf.retry_counter == conf.retry:
            logger.debug(f"Reason error: {e.reason}")
            logger.debug(
                "Ghauri was not able to establish connection, retry again later of check if target manually.."
            )
            logger.end("ending")
            exit(0)
        if conf.retry_counter <= conf.retry:
            attack = inject_expression(
                url,
                data,
                proxy,
                delay=delay,
                timesec=timesec,
                timeout=timeout,
                headers=headers,
                parameter=parameter,
                expression=expression,
                is_multipart=is_multipart,
                injection_type=injection_type,
            )
            if attack.ok:
                response_ok = True
                # start counting from 0 as we have found our response for the current character guess in
                # configured retries..
                conf.retry_counter = 0
        if response_ok:
            return attack
        else:
            logger.end("ending")
            exit(0)
    except ConnectionAbortedError as e:
        raise e
    except ConnectionRefusedError as e:
        raise e
    except ConnectionResetError as e:
        raise e
    except KeyboardInterrupt as e:
        raise e
    except TimeoutError as e:
        raise e
    except Exception as e:
        response_ok = False
        conf.retry_counter += 1
        logger.critical(f"target URL is not responding, Ghauri is going to retry")
        if conf.retry_counter == conf.retry:
            logger.critical(
                "Ghauri was not able to establish connection, retry again later of check if target manually.."
            )
            logger.debug(f"Reason error: {e.reason}")
            logger.end("ending")
            exit(0)
        if conf.retry_counter <= conf.retry:
            attack = inject_expression(
                url,
                data,
                proxy,
                delay=delay,
                timesec=timesec,
                timeout=timeout,
                headers=headers,
                parameter=parameter,
                expression=expression,
                is_multipart=is_multipart,
                injection_type=injection_type,
            )
            if attack.ok:
                # start counting from 0 as we have found our response for the current character guess in
                # configured retries..
                conf.retry_counter = 0
                response_ok = True
        if response_ok:
            return attack
        raise e
    return attack
