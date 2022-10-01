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

import re
import io
import os
import ssl
import sys
import csv
import stat
import time
import html
import gzip
import json
import uuid
import urllib
import codecs
import shutil
import socket
import chardet
import urllib3
import sqlite3
import logging
import argparse
import requests
import binascii
import itertools
import collections
from os.path import expanduser
from io import BytesIO, StringIO
from difflib import SequenceMatcher
from colorama import init, Fore, Back, Style
from urllib.error import HTTPError, URLError
from http.server import BaseHTTPRequestHandler
from urllib.parse import (
    urlparse,
    quote,
    quote_plus,
    unquote,
    parse_qs,
    urljoin,
    urlencode,
)
from urllib.request import (
    build_opener,
    Request,
    urlopen,
    addinfourl,
    ProxyHandler,
    HTTPRedirectHandler,
    BaseHandler,
    HTTPHandler,
    install_opener,
)

NO_DEFAULT = object()

INJECTABLE_HEADERS_DEFAULT = [
    "X-Forwarded-For",
    "User-Agent",
    "Referer",
    "Accept-Language",
]

DBMS_DICT = {
    "mssql": "Microsoft SQL Server",
    "postgresql": "PostgreSQL",
    "mysql": "MySQL",
    "microsoft sql server": "Microsoft SQL Server",
    "oracle": "Oracle",
}

SQL_ERRORS = {
    "MySQL": (
        r"SQL syntax.*?MySQL",
        r"Warning.*?mysql_.*",
        r"Warning.*?\Wmysqli?_",
        r"MySQL Query fail.*",
        r"valid MySQL result",
        r"SQL syntax.*MariaDB server",
        r".ou\s+.*SQL\s+syntax.*",
        r".atabase\s*Query\s*Failed.*",
        r"MySqlException \(0x",
        r"valid MySQL result",
        r"check the manual that (corresponds to|fits) your (MySQL|MariaDB|Drizzle) server version",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
        r"Zend_Db_(Adapter|Statement)_Mysqli_Exception",
        r"SQLSTATE\[\d+\]: Syntax error or access violation",
        r"MemSQL does not support this type of query",
        r"is not supported by MemSQL",
        r"unsupported nested scalar subselect",
        r"MySqlException",
        r"valid MySQL result",
        r"Pdo[./_\\]Mysql",
        r"Unknown column '[^ ]+' in 'field list'",
        r"(?is)(?:A Database error Occurred)",
    ),
    "PostgreSQL": (
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_.*",
        r"Warning.*PostgreSQL",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s\ssyntax error at or near ",
        r"ERROR: parser: parse error at or near",
        r"PostgreSQL query failed",
        r"org\.postgresql\.jdbc",
        r"Pdo[./_\\]Pgsql",
        r"PSQLException",
    ),
    "Microsoft SQL Server": (
        r"Driver.* SQL[\-\_\ ]*Server",
        r"OLE DB.* SQL Server",
        r"(\W|\A)SQL Server.*Driver",
        r"Warning.*odbc_.*",
        r"\bSQL Server[^&lt;&quot;]+Driver",
        r"Warning.*mssql_",
        r"Warning.*?\W(mssql|sqlsrv)_",
        r"Msg \d+, Level \d+, State \d+",
        r"Unclosed quotation mark after the character string",
        r"Microsoft OLE DB Provider for ODBC Drivers",
        r"Warning.*(mssql|sqlsrv)_",
        r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
        r"System\.Data\.SqlClient\.SqlException",
        r"(?s)Exception.*\WRoadhouse\.Cms\.",
        r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
        r"com\.microsoft\.sqlserver\.jdbc\.SQLServerException",
        r"\[SQL Server\]",
        r"ODBC SQL Server Driver",
        r"ODBC Driver \d+ for SQL Server",
        r"SQLServer JDBC Driver",
        r"macromedia\.jdbc\.sqlserver",
        r"com\.jnetdirect\.jsql",
        r".*icrosoft\s+VBScript\s+runtime\s+error\s+.*",
        r"Zend_Db_(Adapter|Statement)_Sqlsrv_Exception",
        r"Pdo[./_\\](Mssql|SqlSrv)",
        r"SQL(Srv|Server)Exception",
        r"(?is)(?:Microsoft SQL (?:Server\s)?Native Client (?:[\d\.]+ )?error '[0-9a-fA-F]{8})",
    ),
    "Microsoft Access": (
        r"Microsoft Access Driver",
        r"Access Database Engine",
        r"Microsoft JET Database Engine",
        r".*Syntax error.*query expression",
    ),
    "Oracle": (
        r"\bORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Warning.*oci_.*",
        "Microsoft OLE DB Provider for Oracle",
    ),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error"),
    "SQLite": (r"SQLite/JDBCDriver", r"System.Data.SQLite.SQLiteException"),
    "Informix": (r"Warning.*ibase_.*", r"com.informix.jdbc"),
    "Sybase": (r"Warning.*sybase.*", r"Sybase message"),
}


SESSION_STATEMENETS = """
DROP TABLE IF EXISTS tbl_payload;
CREATE TABLE tbl_payload (
 id integer PRIMARY KEY AUTOINCREMENT,
 title text NOT NULL,
 attempts integer NOT NULL,
 payload text NOT NULL,
 vector text NOT NULL,
 backend text NOT NULL,
 parameter text NOT NULL,
 injection_type text NOT NULL,
 payload_type text NOT NULL,
 endpoint text NOT NULL
);
"""

DB_TABLES = """
DROP TABLE IF EXISTS `{name}`;
CREATE TABLE `{tbl_name}` (
 tbl_id integer PRIMARY KEY AUTOINCREMENT,
 tblname text
);
"""

TBL_COLUMNS = """
DROP TABLE IF EXISTS `{name}`;
CREATE TABLE `{tbl_name}` (
 col_id integer PRIMARY KEY AUTOINCREMENT,
 colname text
);
"""

TBL_RECS = """
DROP TABLE IF EXISTS `{name}`;
CREATE TABLE `{tbl_name}` (
 `index` integer,
 `column_name` text,
 `column_value` text
);
"""

TBL_SEARCH = """
DROP TABLE IF EXISTS `{name}`;
CREATE TABLE `{name}` (
 `index` integer,
 `value` text,
 `search_type` text
);
"""

PAYLOAD_STATEMENT = """
INSERT 
    INTO tbl_payload (`title`, `attempts`, `payload`, `vector`, `backend`, `parameter`, `injection_type`, `payload_type`, `endpoint`)
VALUES  (?, ?, ?, ?, ?, ?, ?, ?, ?);
"""
DBS_STATEMENT = """
INSERT 
    INTO tbl_databases (`dbname`)
VALUES  ("{dbname}");
"""
TBLS_STATEMENT = """
INSERT 
    INTO `{tbl_name}` (`tblname`)
VALUES  ('{tblname}');
"""
COLS_STATEMENT = """
INSERT 
    INTO `{tbl_name}` (`colname`)
VALUES  ("{colname}");
"""

SEARCH_STATEMENT = """
INSERT 
    INTO `{name}` (`index`, `value`, `search_type`)
VALUES  (?, ?, ?);
"""
