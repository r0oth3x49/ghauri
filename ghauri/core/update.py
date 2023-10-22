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

import os
import re
import json
import subprocess
from ghauri.core.request import request
from ghauri import __version__ as VERSION
from ghauri.logger.colored_logger import logger
from ghauri.common.lib import GIT_REPOSITORY, LATEST_VERSION


def version_check(show=True):
    is_latest = True
    try:
        logger.debug("checking latest version on github...")
        response = request.perform(url=LATEST_VERSION)
        ok = json.loads(response.text)
        tag = ok.get("tag_name")
        ver = [int(i) for i in tag.split(".")]
        current_version = [int(i) for i in VERSION.split(".")]
        if show:
            if ver > current_version:
                logger.info(
                    "You are using an old version 'v{}' of ghauri, update to latest version: 'v{}'..".format(
                        VERSION, tag
                    )
                )
                is_latest = False
            else:
                logger.info("already at the latest version 'v%s'" % (tag or VERSION))
    except Exception as error:
        logger.debug("update could not be completed ('%s')" % str(error))
        logger.end("ending")
        exit(0)
    return is_latest, tag


def update_ghauri():
    success = False
    GHAURI_ROOT_PATH = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    here = os.path.join(GHAURI_ROOT_PATH, ".git")
    if not os.path.exists(here):
        warnMsg = "not a git repository. It is recommended to clone the 'r0oth3x49/ghauri' repository "
        warnMsg += "from GitHub (e.g. 'git clone %s ghauri')" % GIT_REPOSITORY
        logger.warning(warnMsg)
    else:
        infoMsg = "updating ghauri to the latest development revision from the "
        infoMsg += "GitHub repository"
        logger.info(infoMsg)

        debugMsg = "ghauri will try to update itself using 'git' command"
        logger.debug(debugMsg)

        logger.info("update in progress....")

        output = ""
        try:
            process = subprocess.Popen(
                "git checkout . && git pull %s HEAD" % GIT_REPOSITORY,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=GHAURI_ROOT_PATH,
            )
            output, _ = process.communicate()
            success = not process.returncode
        except Exception as ex:
            success = False
            output = str(ex)
        finally:
            output = output.decode()

        _, ver = version_check(show=False)

        if success:
            logger.info(
                "%s the latest version 'v%s'"
                % (
                    "already at" if "Already" in output else "updated to",
                    ver,
                )
            )
        else:
            if "Not a git repository" in output:
                errMsg = "not a valid git repository. Please checkout the 'r0oth3x49/ghauri' repository "
                errMsg += "from GitHub (e.g. 'git clone %s ghauri')" % GIT_REPOSITORY
                logger.error(errMsg)
            else:
                logger.error(
                    "update could not be completed ('%s')"
                    % re.sub(r"\W+", " ", output).strip()
                )

    if not success:
        if os.name == "nt":
            infoMsg = "for Windows platform it's recommended "
            infoMsg += "to use a GitHub for Windows client for updating "
            infoMsg += "purposes (https://desktop.github.com/) or just "
            infoMsg += "download the latest snapshot from "
            infoMsg += "https://github.com/r0oth3x49/ghauri and install"
        else:
            infoMsg = "for Linux platform it's recommended "
            infoMsg += "to install a standard 'git' package (e.g.: 'apt install git')"

        logger.info(infoMsg)
