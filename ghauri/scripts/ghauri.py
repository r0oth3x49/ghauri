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
import ghauri
import argparse
from ghauri.common import banner
from ghauri.common.utils import dbms_full_name
from ghauri.logger.colored_logger import logger


def main():
    examples = "%(prog)s http://www.site.com/vuln.php?id=1 --dbs\n\n"
    version = "Ghauri {version}".format(version=f"{ghauri.__version__}")
    description = "A cross-platform python based advanced sql injections detection & exploitation tool."
    parser = argparse.ArgumentParser(
        usage="%(prog)s -u URL [OPTIONS]",
        description=description,
        conflict_handler="resolve",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    general = parser.add_argument_group("General")
    general.add_argument("-h", "--help", action="help", help="Shows the help.")
    general.add_argument(
        "--version", action="version", version=version, help="Shows the version."
    )
    general.add_argument(
        "-v",
        dest="verbose",
        type=int,
        default=1,
        help="Verbosity level: 1-5 (default 1).",
    )
    general.add_argument(
        "--batch",
        dest="batch",
        action="store_true",
        help="Never ask for user input, use the default behavior",
    )
    general.add_argument(
        "--flush-session",
        dest="flush_session",
        action="store_true",
        help="Flush session files for current target",
    )

    target = parser.add_argument_group(
        "Target",
        description="At least one of these options has to be provided to define the\ntarget(s)",
    )
    target.add_argument(
        "-u",
        "--url",
        dest="url",
        type=str,
        help="Target URL (e.g. 'http://www.site.com/vuln.php?id=1).",
    )
    target.add_argument(
        "-r",
        dest="requestfile",
        type=str,
        help="Load HTTP request from a file",
    )
    request = parser.add_argument_group(
        "Request",
        description="These options can be used to specify how to connect to the target URL",
    )
    request.add_argument(
        "-A",
        "--user-agent",
        dest="user_agent",
        type=str,
        help="HTTP User-Agent header value",
        default="",
        metavar="",
    )
    request.add_argument(
        "-H",
        "--header",
        dest="header",
        type=str,
        help='Extra header (e.g. "X-Forwarded-For: 127.0.0.1")',
        default="",
        metavar="",
    )
    request.add_argument(
        "--host",
        dest="host",
        type=str,
        help="HTTP Host header value",
        default="",
        metavar="",
    )
    request.add_argument(
        "--data",
        dest="data",
        type=str,
        help='Data string to be sent through POST (e.g. "id=1")',
        default="",
        metavar="",
    )
    request.add_argument(
        "--cookie",
        dest="cookie",
        type=str,
        help='HTTP Cookie header value (e.g. "PHPSESSID=a8d127e..")',
        default="",
        metavar="",
    )
    request.add_argument(
        "--referer",
        dest="referer",
        type=str,
        help="HTTP Referer header value",
        default="",
        metavar="",
    )
    request.add_argument(
        "--headers",
        dest="headers",
        type=str,
        help='Extra headers (e.g. "Accept-Language: fr\\nETag: 123")',
        default="",
        metavar="",
    )
    request.add_argument(
        "--proxy",
        dest="proxy",
        type=str,
        help="Use a proxy to connect to the target URL",
        default="",
        metavar="",
    )
    request.add_argument(
        "--delay",
        dest="delay",
        type=int,
        help="Delay in seconds between each HTTP request",
        default=0,
        metavar="",
    )
    request.add_argument(
        "--timeout",
        dest="timeout",
        type=int,
        help="Seconds to wait before timeout connection (default 30)",
        default=30,
        metavar="",
    )
    request.add_argument(
        "--retries",
        dest="retries",
        type=int,
        help="Retries when the connection related error occurs (default 3)",
        default=3,
        metavar="",
    )
    request.add_argument(
        "--confirm",
        dest="confirm_payloads",
        action="store_true",
        help="Confirm the injected payloads.",
    )
    request.add_argument(
        "--skip-urlencode",
        dest="skip_urlencoding",
        action="store_true",
        help="Skip URL encoding of payload data",
    )
    request.add_argument(
        "--force-ssl",
        dest="force_ssl",
        action="store_true",
        help="Force usage of SSL/HTTPS",
    )
    optimization = parser.add_argument_group(
        "Optimization",
        description="These options can be used to optimize the performance of ghauri",
    )
    optimization.add_argument(
        "--threads",
        dest="threads",
        type=int,
        help="Max number of concurrent HTTP(s) requests (default 1)",
        default=1,
    )
    injection = parser.add_argument_group(
        "Injection",
        description="These options can be used to specify which parameters to test for, \nprovide custom injection payloads and optional tampering scripts",
    )
    injection.add_argument(
        "-p",
        dest="testparameter",
        type=str,
        help="Testable parameter(s)",
        default=None,
    )
    injection.add_argument(
        "--dbms",
        dest="dbms",
        type=str,
        help="Force back-end DBMS to provided value",
        default=None,
    )
    injection.add_argument(
        "--prefix",
        dest="prefix",
        type=str,
        help="Injection payload prefix string",
        default=None,
        metavar="",
    )
    injection.add_argument(
        "--suffix",
        dest="suffix",
        type=str,
        help="Injection payload suffix string",
        default=None,
        metavar="",
    )
    detection = parser.add_argument_group(
        "Detection",
        description="These options can be used to customize the detection phase",
    )
    detection.add_argument(
        "--level",
        dest="level",
        type=int,
        help="Level of tests to perform (1-3, default 1)",
        default=1,
        # metavar="",
    )
    detection.add_argument(
        "--code",
        dest="code",
        type=int,
        help="HTTP code to match when query is evaluated to True",
        default=200,
        # metavar="",
    )
    detection.add_argument(
        "--string",
        dest="string",
        type=str,
        help="String to match when query is evaluated to True",
        default=None,
        metavar="",
    )
    detection.add_argument(
        "--not-string",
        dest="not_string",
        type=str,
        help="String to match when query is evaluated to False",
        default=None,
        metavar="",
    )
    detection.add_argument(
        "--text-only",
        dest="text_only",
        action="store_true",
        help="Compare pages based only on the textual content",
    )
    techniques = parser.add_argument_group(
        "Techniques",
        description="These options can be used to tweak testing of specific SQL injection\ntechniques",
    )
    techniques.add_argument(
        "--technique",
        dest="tech",
        type=str,
        help='SQL injection techniques to use (default "BEST")',
        default="BEST",
    )
    techniques.add_argument(
        "--time-sec",
        dest="timesec",
        type=int,
        help="Seconds to delay the DBMS response (default 5)",
        default=5,
        # metavar="",
    )
    enumeration = parser.add_argument_group(
        "Enumeration",
        description=(
            "These options can be used to enumerate the back-end database"
            "\nmanagement system information, structure and data contained in the\ntables."
        ),
    )
    enumeration.add_argument(
        "-b",
        "--banner",
        dest="banner",
        action="store_true",
        help="Retrieve DBMS banner",
    )
    enumeration.add_argument(
        "--current-user",
        dest="current_user",
        action="store_true",
        help="Retrieve DBMS current user",
    )
    enumeration.add_argument(
        "--current-db",
        dest="current_db",
        action="store_true",
        help="Retrieve DBMS current database",
    )
    enumeration.add_argument(
        "--hostname",
        dest="hostname",
        action="store_true",
        help="Retrieve DBMS server hostname",
    )
    enumeration.add_argument(
        "--dbs",
        dest="dbs",
        action="store_true",
        help="Enumerate DBMS databases",
    )
    enumeration.add_argument(
        "--tables",
        dest="tables",
        action="store_true",
        help="Enumerate DBMS database tables",
    )
    enumeration.add_argument(
        "--columns",
        dest="columns",
        action="store_true",
        help="Enumerate DBMS database table columns",
    )
    enumeration.add_argument(
        "--dump",
        dest="dump",
        action="store_true",
        help="Dump DBMS database table entries",
    )
    enumeration.add_argument(
        "-D",
        dest="db",
        type=str,
        help="DBMS database to enumerate",
        default=None,
    )
    enumeration.add_argument(
        "-T",
        dest="tbl",
        type=str,
        help="DBMS database tables(s) to enumerate",
        default=None,
    )
    enumeration.add_argument(
        "-C",
        dest="cols",
        type=str,
        help="DBMS database table column(s) to enumerate",
        default=None,
    )
    enumeration.add_argument(
        "--start",
        dest="limitstart",
        type=int,
        help="Retrieve entries from offset for dbs/tables/columns/dump",
        default=0,
        metavar="",
    )
    enumeration.add_argument(
        "--stop",
        dest="limitstop",
        type=int,
        help="Retrieve entries till offset for dbs/tables/columns/dump",
        default=None,
        metavar="",
    )
    examples = parser.add_argument_group("Example", description=examples)

    args = parser.parse_args()

    raw = ""
    if not args.url and not args.requestfile:
        parser.print_help()
        exit(0)

    if args.testparameter:
        args.testparameter = [i.strip() for i in args.testparameter.split(",")]

    resp = ghauri.perform_injection(
        url=args.url,
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
    )
    if resp.is_injected:
        target = ghauri.Ghauri(
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
        if not args.dbs and (
            args.hostname or args.current_user or args.current_db or args.banner
        ):
            if args.banner:
                target.extract_banner()
            if args.current_user:
                target.extract_current_user()
            if args.current_db:
                target.extract_current_db()
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


if __name__ == "__main__":
    main()
