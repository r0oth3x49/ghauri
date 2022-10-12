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


class GhauriConfigs:
    """
    This class will be used for configruations
    """

    def __init__(
        self,
        vectors="",
        is_string=False,
        is_json=False,
        is_multipart=False,
        skip_urlencodig=False,
        filepaths=None,
        proxy=None,
        text_only=False,
    ):
        self.vectors = vectors
        self.is_string = is_string
        self.is_json = is_json
        self.is_multipart = is_multipart
        self.skip_urlencodig = skip_urlencodig
        self.filepaths = filepaths
        self._session_filepath = None
        self.proxy = proxy
        self.text_only = text_only

    @property
    def session_filepath(self):
        if self.filepaths:
            self._session_filepath = self.filepaths.session
        return self._session_filepath


conf = GhauriConfigs()
