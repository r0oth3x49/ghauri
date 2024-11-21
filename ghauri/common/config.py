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

from ghauri.common.lib import Lock


class GhauriConfigs:
    """
    This class will be used for configruations
    """

    def __init__(
        self,
        vectors="",
        is_string=False,
        is_json=False,
        is_xml=False,
        is_multipart=False,
        skip_urlencoding=False,
        filepaths=None,
        proxy=None,
        text_only=False,
        string=None,
        not_string=None,
        code=None,
        match_ratio=None,
        retry=3,
        base=None,
        attack01=None,
        delay=0,
        timesec=5,
        timeout=None,
        backend=None,
        batch=False,
        continue_on_http_error=False,
        follow_redirects=None,
        threads=None,
    ):
        self.vectors = vectors
        self.is_string = is_string
        self.is_json = is_json
        self.is_xml = is_xml
        self.is_multipart = is_multipart
        self.skip_urlencoding = skip_urlencoding
        self.filepaths = filepaths
        self._session_filepath = None
        self.proxy = proxy
        self.text_only = text_only
        self.string = string
        self.not_string = not_string
        self.code = code
        self.match_ratio = match_ratio
        self.retry = retry
        self.base = base
        self.attack01 = attack01
        self.backend = backend
        self.batch = batch
        self.http_codes = {}
        self.timeout = timeout
        self.delay = delay
        self.timesec = timesec
        self.continue_on_http_error = continue_on_http_error
        self.follow_redirects = follow_redirects
        self.threads = threads
        self._max_threads = 10
        self._thread_chars_query = {}
        self.lock = Lock()
        self.thread_warning = False
        self.max_threads_warning = False
        self._readtimout_counter = 0
        self._json_post_data = []
        self.request_counter = 1
        self.req_counter_injected = 0
        self.params_count = 0
        self.confirm_payloads = False
        self.safe_chars = None
        self.rto_warning = False
        self.fetch_using = None
        self.rtom_warning = False
        self.test_filter = None
        self.prioritize = False
        self._is_asked_for_priority = False
        self._bool_check_on_ct = True
        self._bool_ctb = None
        self._bool_ctt = None
        self._bool_ctf = None
        self._match_ratio_check = False
        self.fresh_queries = False
        self.retry_counter = 0
        self._is_cookie_choice_taken = False
        self._encode_cookie = False
        self._ignore_code = ""
        self._shw_ignc = False
        self.cases = []
        self._mt_mode = False
        self._multitarget_csv = None
        self._technique = None
        self._isb64serialized = False
        self._b64serialized_choice = False
        self._deserialized_data = {}
        self._deserialized_data_param = ""
        self._deserialized_data_param_value = ""
        self._random_ua_string = None
        self._random_ua = False
        self._is_mobile_ua = False
        self._random_agent_dict = {}

    @property
    def ignore_code(self):
        codes = []
        if self._ignore_code == "*":
            codes == [401]
        if self._ignore_code and isinstance(self._ignore_code, str):
            try:
                codes = [int(i) for i in self._ignore_code.replace(" ", "").split(",")]
            except ValueError:
                errMsg = "option '--ignore-code' should contain a list of integer values or a wildcard value '*'"
                # raise Exception(errMsg)
                logger.critical(errMsg)
                logger.end("ending")
                exit(0)
        return codes

    @property
    def session_filepath(self):
        if self.filepaths:
            self._session_filepath = self.filepaths.session
        return self._session_filepath


conf = GhauriConfigs()
