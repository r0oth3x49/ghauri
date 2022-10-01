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
from ghauri.common.colors import *
from ghauri.common.colors import colorize


LEGAL_DISCLAIMER = "\n[!] Legal disclaimer: Usage of Ghauri for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local,\nstate and federal laws. Developer assume no liability and is not responsible for any misuse or damage caused by this program."
LEGAL_DISCLAIMER = colorize(string=LEGAL_DISCLAIMER, color="white", normal=True)
I1 = colorize(string="'", color="yellow", normal=True, background="red")
I1 = f"{I1}{BRIGHT}{yellow}"
I2 = colorize(string='"', color="yellow", normal=True, background="red")
I2 = f"{I2}{BRIGHT}{yellow}"
I3 = colorize(string=")", color="yellow", normal=True, background="red")
I3 = f"{I3}{BRIGHT}{yellow}"


VERSION = colorize(string=ghauri.__version__, color="bright_yellow", bold=True)
START_BRACES = colorize(string="{", color="bright_white", normal=True)
END_BRACES = f'{colorize(string="}", color="bright_white", normal=True)}'
END_BRACES = f"{END_BRACES}{BRIGHT}{yellow}"
VERSION_STRING = f"{START_BRACES}{VERSION}{END_BRACES}"
GITHUB_URL = colorize(
    string="https://github.com/r0oth3x49", color="bright_white", faint=True
)
by = colorize(string="Author:", color="bright_cyan", bold=True)
name = colorize(string="r0ot", color="bright_green", bold=True)
name += colorize(string="@", color="bright_red", bold=True)
name += colorize(string="h3x49", color="bright_cyan", bold=True)
desc = colorize(
    string="An advanced SQL injection detection & exploitation tool.",
    color="bright_green",
)
line = colorize(string="", color="green", bold=True)

banner = """
%s
  ________.__                        .__  %s
 /  _____/|  |__ _____   __ _________|__|
%s/   \\  ___|  |  \\\\__  \\ |  |  \\_  __ \\  |
\\    \\_\\  \\   Y  \\/ __ \\|  |  /|  | \\/  |
%s \\______  /___|  (____  /____/ |__|  |__|
        \\/     \\/     \\/         %s
                                 %s
  
""" % (
    bright_cyan,
    VERSION_STRING,
    bright_magenta,
    bright_green,
    GITHUB_URL,
    desc,
)

BANNER = colorize(string=banner, color="yellow", bold=True)
print(BANNER)
