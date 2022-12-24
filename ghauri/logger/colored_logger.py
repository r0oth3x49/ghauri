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

from ghauri.common.colors import (
    colorize,
    level_map,
    color_map,
    bgcolor_map,
    DIM,
    BRIGHT,
    NORMAL,
    RESET,
)
from ghauri.common.lib import os, sys, time, logging, collections
from ghauri.common.config import conf

log = logging.getLogger("ghauri-logs")


class ColoredFormatter(logging.Formatter):
    """
    Ghauri custom color logger..
    """

    def format(self, record):
        message = record.getMessage()
        spaces = ""
        leading_spaces_count = len(message) - len(message.lstrip())
        if message.startswith("\n"):
            spaces = "\n" * leading_spaces_count
            message = message.lstrip()
        if message.startswith("\t"):
            spaces = "\t" * leading_spaces_count
            message = message.lstrip()
        if message.startswith(" "):
            spaces = " " * leading_spaces_count
            message = message.lstrip()
        levelname = record.levelname
        uses_time = self.usesTime()
        if not uses_time:
            asctime = time.strftime("%H:%M:%S")
        if uses_time:
            asctime = self.formatTime(record, datefmt=self.datefmt)
        color_conf = level_map.get(levelname)
        levelname = colorize(levelname, **color_conf)
        asctime = colorize(asctime, color="cyan")
        start = colorize("[", color="white")
        end = colorize("]", color="white")
        formatted_message = None
        if record.levelname == "INFO":
            message = colorize(message)
        elif record.levelname == "NOTICE":
            if (
                "might not be injectable" in message
                or "does not seem to be injectable" in message
            ):
                levelname = colorize("WARNING", color="bright_yellow", bold=True)
            else:
                levelname = colorize("INFO", color="bright_green", bold=True)
            message = colorize(message, **color_conf)
        elif record.levelname == "CRITICAL":
            message = colorize(message)
        elif record.levelname == "DEBUG":
            message = colorize(message)
        elif record.levelname == "ERROR":
            message = colorize(message, color="white")
        elif record.levelname == "SUCCESS":
            message = colorize(message, **color_conf)
            formatted_message = f"{spaces}{message}"
        elif record.levelname == "START":
            message = f"\n[*] starting @ {time.strftime('%H:%M:%S')} /{time.strftime('%Y-%m-%d')}/\n"
            formatted_message = colorize(message, **color_conf)
        elif record.levelname == "END":
            message = f"\n[*] ending @ {time.strftime('%H:%M:%S')} /{time.strftime('%Y-%m-%d')}/\n"
            formatted_message = colorize(message, **color_conf)
        elif record.levelname == "TRAFFIC_IN":
            message = colorize(message)
        elif record.levelname == "TRAFFIC_OUT":
            message = colorize(message)
        elif record.levelname == "PAYLOAD":
            message = colorize(message, normal=True)
            spaces = ""
        else:
            message = colorize(f"{spaces}{message}", normal=True)
        if not formatted_message:
            formatted_message = (
                f"{start}{asctime}{end} {start}{levelname}{end} {message}"
            )
        return formatted_message


class ColoredLogger:
    """Custom colored logger"""

    def __init__(self, logger):

        # set success level
        logging.TRAFFIC_IN = 1
        logging.TRAFFIC_OUT = 8
        logging.PAYLOAD = 9
        logging.NOTICE = 26
        logging.START = 27
        logging.END = 28
        logging.PROGRESS = 29
        logging.SUCCESS = 70
        logging.addLevelName(logging.END, "END")
        logging.addLevelName(logging.START, "START")
        logging.addLevelName(logging.SUCCESS, "SUCCESS")
        logging.addLevelName(logging.NOTICE, "NOTICE")
        logging.addLevelName(logging.PAYLOAD, "PAYLOAD")
        logging.addLevelName(logging.PROGRESS, "PROGRESS")
        logging.addLevelName(logging.TRAFFIC_IN, "TRAFFIC_IN")
        logging.addLevelName(logging.TRAFFIC_OUT, "TRAFFIC_OUT")

        stream_handler = logging.StreamHandler()
        stream_formatter = ColoredFormatter(
            "[%(asctime)s] [%(levelname)s] %(message)s", "%H:%M:%S"
        )
        stream_handler.setFormatter(stream_formatter)
        logger.addHandler(stream_handler)
        setattr(
            logger,
            "success",
            lambda message, *args: logger._log(logging.SUCCESS, message, args),
        )
        setattr(
            logger,
            "payload",
            lambda message, *args: logger._log(logging.PAYLOAD, message, args),
        )
        setattr(
            logger,
            "notice",
            lambda message, *args: logger._log(logging.NOTICE, message, args),
        )
        setattr(
            logger,
            "traffic_in",
            lambda message, *args: logger._log(logging.TRAFFIC_IN, message, args),
        )
        setattr(
            logger,
            "traffic_out",
            lambda message, *args: logger._log(logging.TRAFFIC_OUT, message, args),
        )
        setattr(
            logger,
            "start",
            lambda message, *args: logger._log(logging.START, message, args),
        )
        setattr(
            logger,
            "end",
            lambda message, *args: logger._log(logging.END, message, args),
        )
        setattr(
            logger,
            "progress",
            self.progress,
        )
        setattr(
            logger,
            "read_input",
            self.read_input,
        )
        self.logger = logger
        self.stream_handler = stream_handler

    def set_level(self, level, filepath):
        if filepath and not os.path.isfile(filepath):
            with open(filepath, "a", encoding="utf-8") as fd:
                pass
        self.stream_handler.setLevel(level)
        if filepath:
            handler = logging.FileHandler(filepath, mode="a", encoding="utf-8")
            ff = logging.Formatter("%(message)s")
            handler.setFormatter(ff)
            handler.setLevel(logging.SUCCESS)
            self.logger.addHandler(handler)
        self.logger.setLevel(level)

    def progress(self, message, done=False, *args, **kwargs):
        message = colorize(
            string=f"{message.strip()} ",
            color="white",
            faint=False,
            normal=False,
            background="",
        )
        asctime = time.strftime("%H:%M:%S")
        start = colorize("[", color="white", faint=True)
        end = colorize("]", color="white", faint=True)
        asctime = colorize(asctime, color="cyan", faint=True)
        levelname = colorize("INFO", color="green", normal=True)
        message = f"{start}{asctime}{end} {start}{levelname}{end} {message}"
        if not done:
            if not conf.threads:
                sys.stdout.write("\r\r\r\033[2K\033[1G\r")
                sys.stdout.flush()
                sys.stdout.write("\r\r\r\033[2K\033[1G\r{}\r".format(message))
                sys.stdout.flush()
            if conf.threads:
                with conf.lock:
                    print(
                        message,
                        end="\r" * len(message),
                        flush=True,
                    )
        if done:
            sys.stdout.write("\033[2K\033[1G\r\r{}\r\n".format(message))
            sys.stdout.flush()

    def read_input(
        self, message, batch=False, user_input="", new_line=True, *args, **kwargs
    ):
        """
        :params:
            string: String to show on user stdout
            color: color to set on string for stdout (default: white)
            faint: true/false (default: false)
            bold: true/false (default: true)
            background: background color if you want to set. (default: none)
        """
        message = colorize(
            string=f"{message.strip()} ",
            color="white",
            faint=False,
            bold=True,
            normal=False,
            background="",
        )
        choice = ""
        default_input = user_input
        try:
            if not batch:
                sys.stdout.write("{}".format(message))
                sys.stdout.flush()
                ui = input()
                if ui:
                    choice = ui
                if new_line:
                    print("")
            if batch:
                sys.stdout.write("{}{}".format(message, user_input))
                sys.stdout.flush()
                print("\n")
        except KeyboardInterrupt:
            print("")
            logger.error("user quit")
            logger.end("ending")
            print("")
            sys.exit(0)
        except (Exception, EOFError) as e:
            print("")
        if choice:
            default_input = choice.strip()
        return default_input.lower()


colored_logger = ColoredLogger(logger=log)
logger = colored_logger.logger
set_level = colored_logger.set_level
