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
from ghauri.common.utils import dbms_full_name, register_cmdline_args
from ghauri.logger.colored_logger import logger


def main():
    examples = "%(prog)s -u http://www.site.com/vuln.php?id=1 --dbs\n\n"
    description = "A cross-platform python based advanced sql injections detection & exploitation tool."
    parser = argparse.ArgumentParser(
        usage="%(prog)s -u URL [OPTIONS]",
        description=description,
        conflict_handler="resolve",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    register_cmdline_args(parser)

    examples = parser.add_argument_group("Example", description=examples)

    args = parser.parse_args()

    raw = ""
    if not args.url and not args.requestfile:
        if not args.update:
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
        safe_chars=args.safe_chars,
        fetch_using=args.fetch_using,
        test_filter=args.test_filter,
        sql_shell=args.sql_shell,
        fresh_queries=args.fresh_queries,
        update=args.update,
        ignore_code=args.ignore_code,
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
            target.dump_current_db(current_db=current_db, dump_requested=True)
        logger.success("")
        target._end()


if __name__ == "__main__":
    main()
