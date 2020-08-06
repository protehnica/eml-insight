import itertools
import json
import os
import re
import subprocess
import sys
from collections import OrderedDict
from email import message_from_string
from pathlib import Path
from typing import List, Generator, Tuple, Dict
from urllib import request
import time


#
# header parsing generator, produces a key-value tuple
#
# https://docs.python.org/3/library/typing.html
# If your generator will only yield values, set the SendType and ReturnType to None
#

def parse_headers(text: str) -> Generator[Tuple[str, str], None, None]:
    text = text.replace("\r", "")
    headers = text.split("\n\n")[0]
    headers = re.sub(r'\n[\s]+', ' ', headers)
    lines = headers.split("\n")

    for line in lines:
        k, v = line.lower().split(":", maxsplit=1)
        yield k, v


#
# caching mechanism
#

NOW = time.time()
CUTOFF = NOW - (3600 * 24 * 7)


def write_cached(path: str, text: str) -> None:
    with open(file=path, encoding="UTF-8", mode="w") as f:
        f.write(text)


def read_cached(path: str) -> str or None:
    if not os.path.isfile(path):
        return None

    age = int(os.path.getmtime(path))
    if age < CUTOFF:
        print("File existed, but was older: {0}".format(path))
        return None

    with open(file=path, encoding="UTF-8", mode="r") as f:
        return f.read()


def cached_or(path: str, fun) -> str:
    if (text := read_cached(path)) is not None:
        return text
    else:
        text = fun()
        write_cached(path, text)
        return text


#
# cache paths
#

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
CACHE_DIR = os.path.join(SCRIPT_DIR, "cache")
Path(CACHE_DIR).mkdir(parents=True, exist_ok=True)


def get_extreme_ip_lookup_path(ip: str) -> str:
    ip = ip.replace(":", "_")
    return "{0}/{1}.json".format(CACHE_DIR, ip)


def get_whois_path(ip: str) -> str:
    ip = ip.replace(":", "_")
    return "{0}/{1}.txt".format(CACHE_DIR, ip)


#
# API "Extreme IP Lookup"
#

def extreme_lookup_ip_live(ip: str) -> str:
    contents = request.urlopen("http://extreme-ip-lookup.com/json/{0}".format(ip)).read().decode('utf-8')
    return contents


def extreme_lookup_ip(ip: str) -> Dict[str, str]:
    path = get_extreme_ip_lookup_path(ip)
    j = cached_or(path, lambda: extreme_lookup_ip_live(ip))
    return json.loads(j)


#
# CERT emails
# https://www.first.org/members/teams/
#

CERT = {
    "DE": ["allgemeiner-spam@internet-beschwerdestelle.de", "besonderer-spam@internet-beschwerdestelle.de"],
    "ZA": ["ecs-csirt@ssa.gov.za"],
    "ES": ["info@ccn-cert.cni.es", "incidencias@incibe-cert.es"],
    "IP": ["team@cyber.gov.il"],
    "RO": ["office@cert.ro"],
    "BY": ["support@cert.by"],
    "HR": ["ncert@cert.hr"],
    "BR": ["cert@cert.br"],
    "ME": ["kontakt@cirt.me"],
    "CN": ["cncert@cert.org.cn"],
    "CY": ["info@csirt.cy"],
    "CZ": ["abuse@csirt.cz"],
    "CO": ["ponal.csirt@policia.gov.co"],
    "EG": ["incident@egcert.eg"],
    "GB": ["incidents@ncsc.gov.uk"],
    "KE": ["incidents@ke-cirt.go.ke"],
    "HU": ["team@nki.gov.hu"],
    "FI": ["cert@ncsc.fi"],
    "NL": ["cert@ncsc.nl"],
    "NO": ["post@cert.no"],
    "CH": ["incidents@ncsc.ch"],
    "KR": ["nirscert@korea.kr", "kn-cert@ncsc.go.kr"],
    "JP": ["first-team@nisc.go.jp"],
    "LT": ["cert@cert.lt"],
    "OM": ["ocert999@ita.gov.om"],
    "RS": ["office@cert.rs"],
    "TR": ["trcert@usom.gov.tr"],
    "TW": ["twncert@twncert.org.tw"],
    "NG": ["incident@cert.gov.ng"],
    "IL": ["csirt@cio.gov.il"],
    "AZ": ["team@cert.gov.az"],
    "AE": ["securityoperations@adgovcert.abudhabi.ae"],
    "BD": ["cirt@cirt.gov.bd"],
    "HK": ["cert@govcert.gov.hk"],
    "MT": ["securityoperations.mita@gov.mt"],
    "DK": ["cert@cert.dk"],
    # "": [""],
}


def cert_country(country: str) -> List[str] or None:
    if country in CERT:
        return CERT[country]


#
# abuse emails extraction
#

# https://www.tutorialspoint.com/Extracting-email-addresses-using-regular-expressions-in-Python
EMAIL_REGEX = r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)"


def extract_abuse_emails(text: str) -> List[str]:
    emails = []

    extracted = re.findall(EMAIL_REGEX, text)
    for email in extracted:
        if email.endswith("."):
            email = email[:-1]
        emails.append(email)

    return sorted(list(set(emails)), key=str.lower)


def decode_stdout(b: bytes) -> str or None:
    for codecs in ["UTF-8", "Latin-1"]:
        try:
            return b.decode(codecs)
        except UnicodeError:
            pass
    return None


def perform_whois_live(ip: str) -> str:
    whois_result = subprocess.run(["whois", ip], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    text = decode_stdout(whois_result.stdout)

    if text is None:
        print("Unable to decode WHOIS response for {0}".format(ip))
        exit(0)

    return text


def get_abuse_emails(ip: str) -> List[str]:
    path = get_whois_path(ip)
    text = cached_or(path, lambda: perform_whois_live(ip))
    return extract_abuse_emails(text)


#
# WHOIS
#

WHOIS_FIELDS = ["descr:", "netname:", "org-name:", "role:", "address:"]


def get_whois_info(ip: str) -> Dict[str, List[str]]:
    path = get_whois_path(ip)
    text = cached_or(path, lambda: perform_whois_live(ip))

    result: Dict[str, List[str]] = {}

    lines: List[str] = text.split("\n")
    for line in lines:
        if not any(f in line for f in WHOIS_FIELDS):
            continue
        [k, v] = list(map(lambda s: s.strip(), line.split(":", 1)))
        if k not in result:
            result[k] = []
        result[k].append(v)

    return result


#
# IPs
# regular expressions: https://gist.github.com/mnordhoff/2213179
#

IP_REGEXES = [re.compile(p) for p in [
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    r'(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)'
]]


def extract_ips(s: str) -> List[str]:
    nested = [x for x in (r.findall(s) for r in IP_REGEXES)]
    return list(set(itertools.chain.from_iterable(nested)))


def is_public_ip(ip: str) -> bool:
    return ip != "127.0.0.1" \
           and not ip.startswith("192.168") \
           and not ip.startswith("10.0")


def is_ipv4(ip: str) -> bool:
    return "." in ip


#
# header analysis
#

def header_contains_ip(k: str, v: str) -> bool:
    return "-ip" in k or \
           "spf" in k or \
           ("received" in k and "from" in v)


def header_is_webmail(v: str) -> bool:
    return "outlook.com" in v or "google.com" in v


def is_spf_pass(k: str, v: str) -> bool:
    return "spf" in k and v.startswith("pass")


#
# String operations
#

TITLE_SIZE = 32
BY_SEPARATOR = ' [BY];'


def separator() -> None:
    print("═" * (TITLE_SIZE + 2))


V_BAR = "│"
H_BAR = "─"


def print_table(data: List[List[str]]) -> None:
    if len(data) == 0:
        return None

    lengths: Dict[int, int] = {}

    for row in data:
        i = 0
        for cell in row:
            row[i] = cell = " {0} ".format(cell)

            length = len(cell)
            if i not in lengths:
                lengths[i] = length
            else:
                if length > lengths[i]:
                    lengths[i] = length
            i += 1

    top_border = "┌{0}┐".format("┬".join(map(lambda s: "".ljust(s, H_BAR), lengths.values())))
    mid_border = "├{0}┤".format("┼".join(map(lambda s: "".ljust(s, H_BAR), lengths.values())))
    end_border = "└{0}┘".format("┴".join(map(lambda s: "".ljust(s, H_BAR), lengths.values())))

    print(top_border)

    i = 0
    rows = len(data)

    for row in data:
        cells = {k: v for k, v in enumerate(row)}
        draw = "{0}{1}{2}".format(
            V_BAR,
            V_BAR.join(map(lambda k: cells[k].ljust(lengths[k]), cells.keys())),
            V_BAR
        )
        print(draw)

        if 0 <= i < rows - 1:
            print(mid_border)
        i += 1

    print(end_border)


def print_dict(d: Dict[str, str or List[str]]) -> None:
    pad = 0
    for k in d.keys():
        if (l := len(k)) > pad:
            pad = l

    pad += 5

    for k, v in d.items():
        key = "{0} ".format(k)
        print("- {0} {1}".format(key.ljust(pad, "·"), v))


# https://theasciicode.com.ar/extended-ascii-code/box-drawing-character-single-line-lower-left-corner-ascii-code-192.html
def print_title(s: str) -> None:
    text = " {0} ".format(s).ljust(TITLE_SIZE, " ")
    size = max(TITLE_SIZE, len(text))

    print()
    print("╔{0}╗".format("═" * size))
    print("║{0}║".format(text))
    print("╚{0}╝".format("═" * size))


# http://patorjk.com/software/taag/#p=display&f=ANSI%20Shadow&t=EML
def print_intro() -> None:
    print("""
    ███████╗███╗   ███╗██╗     
    ██╔════╝████╗ ████║██║     
    █████╗  ██╔████╔██║██║     
    ██╔══╝  ██║╚██╔╝██║██║     
    ███████╗██║ ╚═╝ ██║███████╗
    ╚══════╝╚═╝     ╚═╝╚══════╝""")


#
# main routine
#

def main() -> None:
    #
    # parameter check
    #
    if len(sys.argv) == 1:
        print("No input file")
        exit(0)

    filepath = sys.argv[1]

    if not filepath.endswith(".txt"):
        print("File is not a .txt file")
        exit(0)

    print_intro()

    #
    # state
    #
    headers_true_negative = []
    headers_false_negative = []
    headers_false_positive = []

    special_headers_google_apps = set()

    sender_hops: OrderedDict[str, List[List[str]]] = OrderedDict()
    webmail_hops = []

    #
    # parse file
    #
    with open(file=filepath, encoding="latin-1", mode="r") as fp:
        data = fp.read()
        m = message_from_string(data)

        for k, v in parse_headers(data):
            v = re.sub(r' by .*;', BY_SEPARATOR, v).strip()

            google_app = re.compile('=([^=]*.gappssmtp.com)').findall(v)
            if len(google_app) > 0:
                special_headers_google_apps.add(google_app[0])

            if header_contains_ip(k, v):
                ips = extract_ips(v)
                ips = list(filter(is_public_ip, ips))

                if len(ips) == 0:
                    headers_false_positive.append([k, v])
                    continue

                for ip in ips:
                    # if header_is_webmail(v) and not is_ipv4(ip):
                    #     webmail_hops.append([k, v])
                    #     continue

                    if ip not in sender_hops:
                        sender_hops[ip] = []
                    sender_hops[ip].append([k, v])

            else:
                ips = extract_ips(v)
                if len(ips) > 0:
                    headers_false_negative.append([k, v])
                else:
                    headers_true_negative.append(k)

    # reversing IP order
    sender_hops = OrderedDict(reversed(list(sender_hops.items())))

    #
    # from
    #
    print_title("From & Return-Path")
    print_dict({f: m[f] for f in ["from", "return-path"]})

    #
    # IPs
    #

    if len(sender_hops) > 0:
        print_title("IPs")
        ip_dates: Dict[str, str] = {}
        for [ip, headers] in sender_hops.items():
            for [_, v] in headers:
                if BY_SEPARATOR in v:
                    date = v.split(BY_SEPARATOR)[1]
                    ip_dates[ip] = date.strip()
            if ip not in ip_dates:
                ip_dates[ip] = headers
        print_dict(ip_dates)
        # print_table([[k, v] for [k, v] in ip_dates.items()])

    for [ip, headers] in sender_hops.items():
        print_title(ip)

        emails = set(get_abuse_emails(ip))
        print_dict({
            "TO": ', '.join(emails),
            "IP": ip
        })

        # if IPV4, lookup API
        if is_ipv4(ip):
            lookup = extreme_lookup_ip(ip)

            if "countryCode" in lookup:
                cert = cert_country(lookup["countryCode"])
                if cert is not None:
                    print_dict({"CC": ', '.join(cert)})

            print()
            print("API [eXTReMe-IP-Lookup]:")
            print_dict(lookup)

        # WHOIS info
        whois = get_whois_info(ip)
        if len(whois) > 0:
            print()
            print("WHOIS info:")
            print_dict(whois)

        # URLs with external resources
        print()
        print("External resources:")
        print("- https://anti-hacker-alliance.com/index.php?ip={0}&searching=yes".format(ip))

        # headers
        spf = False
        print()
        print("Headers:")
        print_dict({k: v for [k, v] in headers})

        # SPF
        for [k, v] in headers:
            if is_spf_pass(k, v):
                spf = True

        if spf:
            print()
            print("SPF passes")

    #
    # webmail hops
    #
    if len(webmail_hops) > 0:
        print_title("Webmail hops")

    for k, v in webmail_hops:
        print("- {0} {1}".format(k, v))

    #
    # Google App
    #
    if len(special_headers_google_apps) > 0:
        print_title("SPECIAL :: Google app:")
        print(special_headers_google_apps)

    #
    # false positives
    #
    if len(headers_false_positive) > 0:
        print_title("False positive headers [{0}]".format(len(headers_false_positive)))
        for k, v in headers_false_positive:
            print("{0}: {1}".format(k, v))

    #
    # false negatives
    #
    if len(headers_false_negative) > 0:
        print_title("False negative headers [{0}]".format(len(headers_false_negative)))
        print_dict({k: v for k, v in headers_false_negative})

    #
    # true negatives
    #
    if len(headers_true_negative) > 0:
        print_title("True negative headers: [{0}]".format(len(headers_true_negative)))
        print(headers_true_negative)


if __name__ == '__main__':
    main()
