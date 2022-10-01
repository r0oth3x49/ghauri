# Ghauri
**An advanced cross-platform tool that automates the process of detecting and exploiting SQL injection security flaws**


## ***Requirements***

- Python 3
- Python `pip3`

## ***Module Installation***

    pip install -r requirements.txt

## ***Download Ghauri***

You can download the latest version of Ghauri by cloning the GitHub repository.

    git clone https://github.com/r0oth3x49/ghauri.git

## ***Features***
 - Supports boolean/time/error based MySQL/PostgreSQL/MSSQL/Oracle injections.
 - Supports all types (HEADERS/COOKIE/POST/GET) for the listed dbms.
 - Added switch to support proxy option `--proxy`.
 - Added swicth to force SSL connection `--force-ssl`.


## **Advanced Usage**

<pre><code>
Author: Nasir khan (<a href="http://r0oth3x49.herokuapp.com/">r0ot h3x49</a>)

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
  --force-ssl         Force usage of SSL/HTTPS

Injection:
  These options can be used to specify which parameters to test for,
  provide custom injection payloads and optional tampering scripts

  -p TESTPARAMETER    Testable parameter(s)
  --dbms DBMS         Force back-end DBMS to provided value
  --prefix            Injection payload prefix string
  --suffix            Injection payload suffix string

Detection:
  These options can be used to customize the detection phase

  --level             Level of tests to perform (1-3, default 1)

Techniques:
  These options can be used to tweak testing of specific SQL injection
  techniques

  --technique TECH    SQL injection techniques to use (default "BTE")
  --time-sec TIMESEC  Seconds to delay the DBMS response (default 5)

Enumeration:
  These options can be used to enumerate the back-end database
  managment system information, structure and data contained in the
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
  --start             Retrive entries from offset for dbs/tables/columns/dump
  --stop              Retrive entries till offset for dbs/tables/columns/dump

Example:
  ghauri http://www.site.com/vuln.php?id=1 --dbs
</code></pre>


## **Legal disclaimer**

    Usage of Ghauri for attacking targets without prior mutual consent is illegal.
    It is the end user's responsibility to obey all applicable local,state and federal laws. 
    Developer assume no liability and is not responsible for any misuse or damage caused by this program.