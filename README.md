[![GitHub release](https://img.shields.io/badge/release-v1.4.2-brightgreen?style=flat-square)](https://github.com/r0oth3x49/ghauri/releases/tag/1.4.2)
[![GitHub stars](https://img.shields.io/github/stars/r0oth3x49/ghauri?style=flat-square)](https://github.com/r0oth3x49/ghauri/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/r0oth3x49/ghauri?style=flat-square)](https://github.com/r0oth3x49/ghauri/network)
[![GitHub issues](https://img.shields.io/github/issues/r0oth3x49/ghauri?style=flat-square)](https://github.com/r0oth3x49/ghauri/issues)
[![GitHub license](https://img.shields.io/github/license/r0oth3x49/ghauri?style=flat-square)](https://github.com/r0oth3x49/ghauri/blob/main/LICENSE)


## ***Like Ghauri, consider supporting the developer***
<a href="https://www.buymeacoffee.com/r0oth3x49" target="_blank"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black" alt="Buy Me A Coffee"></a> <a href="https://ko-fi.com/r0oth3x49" target="_blank"><img src="https://img.shields.io/badge/Ko--fi-F16061?style=for-the-badge&logo=ko-fi&logoColor=white"></a>


# Ghauri
**An advanced cross-platform tool that automates the process of detecting and exploiting SQL injection security flaws.**

![ghauri-banner](https://user-images.githubusercontent.com/11024397/193408429-418a75e0-a070-4491-9f92-5799b2509cdf.PNG)

## ***Requirements***

- Python 3
- Python `pip3`

## ***Installation***

 - cd to **ghauri** directory.
 - install requirements: `python3 -m pip install --upgrade -r requirements.txt`
 - run: `python3 setup.py install` or `python3 -m pip install -e .`
 - you will be able to access and run the ghauri with simple `ghauri --help` command.

 ***OR***
  
 - Follow this [installation guideline](https://github.com/r0oth3x49/ghauri/issues/119#issuecomment-1873049386) if facing an installation issue.

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
   - SOAP/XML based injections
 - support proxy option `--proxy`.
 - supports parsing request from txt file: switch for that `-r file.txt`
 - supports limiting data extraction for dbs/tables/columns/dump: switch `--start 1 --stop 2`
 - added support for resuming of all phases.
 - added support for skip urlencoding switch: `--skip-urlencode`
 - added support to verify extracted characters in case of boolean/time based injections.
 - added support for handling redirects on user demand.
 - added support for sql-shell switch: `--sql-shell` (experimental)
 - added support for fresh queries switch: `--fresh-queries`
 - added switch for hostname extraction: `--hostname`
 - added switch to update ghauri from github: `--update` 
    - Note: ghauri has to be cloned/installed from github for this switch to work for futures updates,
      for older version users they have to run git pull (if installed using git) to get this update
      and for futures updates the update will be possible with `ghauri --update` command to get the
      latest version of ghauri.
 - added switch for ignore problematic HTTP codes. (e.g 401): `--ignore-code`
 - added switch for retreiving entries count for table.: `--count`
 - added switch for Scanning multiple targets given in a textual fil. `-m` (experimental)
 - added auto detection and exploitation of base64 deserializable GET parameters. (experimental)
 - added support for random HTTP user agent: `--random-agent, --mobile`

## **Advanced Usage**

<pre><code>
Author: Nasir khan (<a href="https://pk.linkedin.com/in/r0oth3x49">r0ot h3x49</a>)

usage: ghauri -u URL [OPTIONS]

A cross-platform python based advanced sql injections detection & exploitation tool.

General:
  -h, --help          Shows the help.
  --version           Shows the version.
  --update            update ghauri
  -v VERBOSE          Verbosity level: 1-5 (default 1).
  --batch             Never ask for user input, use the default behavior
  --flush-session     Flush session files for current target
  --fresh-queries     Ignore query results stored in session file
  --test-filter       Select test payloads by titles (experimental)

Target:
  At least one of these options has to be provided to define the
  target(s)

  -u URL, --url URL   Target URL (e.g. 'http://www.site.com/vuln.php?id=1).
  -m BULKFILE         Scan multiple targets given in a textual file
  -r REQUESTFILE      Load HTTP request from a file

Request:
  These options can be used to specify how to connect to the target URL

  -A , --user-agent   HTTP User-Agent header value
  -H , --header       Extra header (e.g. "X-Forwarded-For: 127.0.0.1")
  --mobile            Imitate smartphone through HTTP User-Agent header
  --random-agent      Use randomly selected HTTP User-Agent header value
  --host              HTTP Host header value
  --data              Data string to be sent through POST (e.g. "id=1")
  --cookie            HTTP Cookie header value (e.g. "PHPSESSID=a8d127e..")
  --referer           HTTP Referer header value
  --headers           Extra headers (e.g. "Accept-Language: fr\nETag: 123")
  --proxy             Use a proxy to connect to the target URL
  --delay             Delay in seconds between each HTTP request
  --timeout           Seconds to wait before timeout connection (default 30)
  --retries           Retries when the connection related error occurs (default 3)
  --confirm           Confirm the injected payloads.
  --ignore-code       Ignore (problematic) HTTP error code(s) (e.g. 401)
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
  --safe-chars        Skip URL encoding of specific character(s): (e.g:- --safe-chars="[]")
  --fetch-using       Fetch data using different operator(s): (e.g: --fetch-using=between/in)

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
  --count             Retrieve number of entries for table(s)
  --dump              Dump DBMS database table entries
  -D DB               DBMS database to enumerate
  -T TBL              DBMS database tables(s) to enumerate
  -C COLS             DBMS database table column(s) to enumerate
  --start             Retrieve entries from offset for dbs/tables/columns/dump
  --stop              Retrieve entries till offset for dbs/tables/columns/dump
  --sql-shell         Prompt for an interactive SQL shell (experimental)

Example:
  ghauri -u http://www.site.com/vuln.php?id=1 --dbs


</code></pre>


## **Legal disclaimer**

    Usage of Ghauri for attacking targets without prior mutual consent is illegal.
    It is the end user's responsibility to obey all applicable local,state and federal laws. 
    Developer assume no liability and is not responsible for any misuse or damage caused by this program.

## **TODO**
  - Add support for inline queries.
  - Add support for Union based queries

## ***Why choose Ghauri***

There are numerous articles and posts highlighting the success users have had with Ghauri compared to SQLMap. While I am not directly comparing Ghauri to SQLMap, many users have done so. I initiated this project because, in my daily work, I frequently encountered significant challenges in configuring and using SQLMap effectively, even for seemingly simple SQL injections. Despite these injections appearing straightforward, SQLMap often failed to detect them. Encouraged by a friend, I decided to create my own tool. I had developed numerous scripts for exploitation, each tailored for specific cases, and I realized the potential benefit of integrating these techniques into a single module. This led to the creation of Ghauri, which has been well-received by the community, earning positive feedback and stars due to its effectiveness.

Even ***Stamparam*** acknowledged Ghauri, describing it as a "rewrite of internals" in a tweet, underscoring the importance of its internal mechanics.

For example, you can save a vulnerable HTTP request to a file (an SQLi behind authentication) and provide it to both Ghauri and SQLMap using the -r switch. The results will speak for themselves without requiring custom configurations.

Ghauri operates both in a browser-like manner and with its own unique methods, automatically switching to different exfiltration techniques and bypasses. Again, this is not a direct comparison since Ghauri still has many features to be implemented, while SQLMap is already feature-rich. However, Ghauri consistently performs the tasks required.

Since developing this tool, I seldom use SQLMap, except in a few cases where Ghauri is still being improved.

I encourage you to try it for yourself.
Thank you.