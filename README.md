[![GitHub release](https://img.shields.io/badge/release-v1.1.2-brightgreen?style=flat-square)](https://github.com/r0oth3x49/ghauri/releases/tag/1.1.2)
[![GitHub stars](https://img.shields.io/github/stars/r0oth3x49/ghauri?style=flat-square)](https://github.com/r0oth3x49/ghauri/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/r0oth3x49/ghauri?style=flat-square)](https://github.com/r0oth3x49/ghauri/network)
[![GitHub issues](https://img.shields.io/github/issues/r0oth3x49/ghauri?style=flat-square)](https://github.com/r0oth3x49/ghauri/issues)
[![GitHub license](https://img.shields.io/github/license/r0oth3x49/ghauri?style=flat-square)](https://github.com/r0oth3x49/ghauri/blob/main/LICENSE)


# Ghauri
**An advanced cross-platform tool that automates the process of detecting and exploiting SQL injection security flaws**

![ghauri-banner](https://user-images.githubusercontent.com/11024397/193408429-418a75e0-a070-4491-9f92-5799b2509cdf.PNG)

## ***Requirements***

- Python 3
- Python `pip3`

## ***Installation***

 - cd to **ghauri** directory.
 - install requirements: `python3 -m pip install --upgrade -r requirements.txt`
 - run: `python3 setup.py install` or `python3 -m pip install -e .`
 - you will be able to access and run the ghauri with simple `ghauri --help` command.

## ***Download Ghauri***

You can download the latest version of Ghauri by cloning the GitHub repository.

    git clone https://github.com/r0oth3x49/ghauri.git

## ***Features***
 - Supports following types of injection payloads:
   - Boolean based.
   - Error Based
   - Time Based
   - Stacked Queries
 - Support SQL injection for following DBMS.
   - MySQL
   - Microsoft SQL Server
   - Postgres
   - Oracle
   - Microsoft Access (only supports fingerprint for now in case of boolean based blind)
 - Supports following injection types.
   - GET/POST Based injections
   - Headers Based injections
   - Cookies Based injections
   - Mulitipart Form data injections
   - JSON based injections
 - support proxy option `--proxy`.
 - supports parsing request from txt file: switch for that `-r file.txt`
 - supports limiting data extraction for dbs/tables/columns/dump: switch `--start 1 --stop 2`
 - added support for resuming of all phases.
 - added support for skip urlencoding switch: `--skip-urlencode`
 - added support to verify extracted characters in case of boolean/time based injections.
 - added support for handling redirects on user demand.


## **Advanced Usage**

<pre><code>
Author: Nasir khan (<a href="https://pk.linkedin.com/in/r0oth3x49">r0ot h3x49</a>)

usage: ghauri -u URL [OPTIONS]

A cross-platform python based advanced sql injections detection & exploitation tool.

General:
  -h, --help          Shows the help.
  --version           Shows the version.
  -v VERBOSE          Verbosity level: 1-5 (default 1).
  --batch             Never ask for user input, use the default behavior
  --flush-session     Flush session files for current target

Target:
  At least one of these options has to be provided to define the
  target(s)

  -u URL, --url URL   Target URL (e.g. 'http://www.site.com/vuln.php?id=1).
  -r REQUESTFILE      Load HTTP request from a file

Request:
  These options can be used to specify how to connect to the target URL

  -A , --user-agent   HTTP User-Agent header value
  -H , --header       Extra header (e.g. "X-Forwarded-For: 127.0.0.1")
  --host              HTTP Host header value
  --data              Data string to be sent through POST (e.g. "id=1")
  --cookie            HTTP Cookie header value (e.g. "PHPSESSID=a8d127e..")
  --referer           HTTP Referer header value
  --headers           Extra headers (e.g. "Accept-Language: fr\nETag: 123")
  --proxy             Use a proxy to connect to the target URL
  --delay             Delay in seconds between each HTTP request
  --timeout           Seconds to wait before timeout connection (default 30)
  --retries           Retries when the connection related error occurs (default 3)
  --skip-urlencode    Skip URL encoding of payload data
  --force-ssl         Force usage of SSL/HTTPS

Optimization:
  These options can be used to optimize the performance of ghauri

  --threads THREADS   Max number of concurrent HTTP(s) requests (default 1)

Injection:
  These options can be used to specify which parameters to test for,
  provide custom injection payloads and optional tampering scripts

  -p TESTPARAMETER    Testable parameter(s)
  --dbms DBMS         Force back-end DBMS to provided value
  --prefix            Injection payload prefix string
  --suffix            Injection payload suffix string

Detection:
  These options can be used to customize the detection phase

  --level LEVEL       Level of tests to perform (1-3, default 1)
  --code CODE         HTTP code to match when query is evaluated to True
  --string            String to match when query is evaluated to True
  --not-string        String to match when query is evaluated to False
  --text-only         Compare pages based only on the textual content

Techniques:
  These options can be used to tweak testing of specific SQL injection
  techniques

  --technique TECH    SQL injection techniques to use (default "BEST")
  --time-sec TIMESEC  Seconds to delay the DBMS response (default 5)

Enumeration:
  These options can be used to enumerate the back-end database
  management system information, structure and data contained in the
  tables.

  -b, --banner        Retrieve DBMS banner
  --current-user      Retrieve DBMS current user
  --current-db        Retrieve DBMS current database
  --hostname          Retrieve DBMS server hostname
  --dbs               Enumerate DBMS databases
  --tables            Enumerate DBMS database tables
  --columns           Enumerate DBMS database table columns
  --dump              Dump DBMS database table entries
  -D DB               DBMS database to enumerate
  -T TBL              DBMS database tables(s) to enumerate
  -C COLS             DBMS database table column(s) to enumerate
  --start             Retrieve entries from offset for dbs/tables/columns/dump
  --stop              Retrieve entries till offset for dbs/tables/columns/dump

Example:
  ghauri http://www.site.com/vuln.php?id=1 --dbs
</code></pre>


## **Legal disclaimer**

    Usage of Ghauri for attacking targets without prior mutual consent is illegal.
    It is the end user's responsibility to obey all applicable local,state and federal laws. 
    Developer assume no liability and is not responsible for any misuse or damage caused by this program.

## **TODO**
  - Add support for inline queries.
  - Add support for Union based queries
