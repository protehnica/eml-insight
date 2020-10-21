import itertools
import json
import os
import re
import subprocess
import sys
from collections import OrderedDict
from email import message_from_string
from pathlib import Path
from typing import Generator, Callable
from urllib import request
import time
from colorama import init, Fore, Back

init(autoreset=True)


#
# header parsing generator, produces a key-value tuple
#
# https://docs.python.org/3/library/typing.html
# If your generator will only yield values, set the SendType and ReturnType to None
#

def parse_headers(text: str) -> Generator[tuple[str, str], None, None]:
    text = text.replace("\r", "")
    headers = text.split("\n\n")[0]
    headers = re.sub(r'\n[\s]+', ' ', headers)
    lines = headers.split("\n")

    for line in lines:
        try:
            k, v = line.lower().split(":", maxsplit=1)
            yield k, v
        except ValueError:
            pass


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
        # print("File existed, but was older: {0}".format(path))
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


def extreme_lookup_ip(ip: str) -> dict[str, str]:
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
    "PL": ["cert@cert.pl"],
    "FR": ["cert-fr.cossi@ssi.gouv.fr"],
    "UA": ["cert@cert.gov.ua"],
    "AR": ["ciberseguridad@ba-csirt.gob.ar"],
    # "": [""],
}


def cert_country(country: str) -> list[str] or None:
    if country in CERT:
        return CERT[country]


#
# abuse emails extraction
#

# https://www.tutorialspoint.com/Extracting-email-addresses-using-regular-expressions-in-Python
EMAIL_REGEX = r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)"


def extract_abuse_emails(text: str) -> list[str]:
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


def get_abuse_emails(ip: str) -> list[str]:
    path = get_whois_path(ip)
    text = cached_or(path, lambda: perform_whois_live(ip))
    return extract_abuse_emails(text)


#
# WHOIS
#

WHOIS_FIELDS = ["descr:", "netname:", "org-name:", "role:", "address:"]


def get_whois_info(ip: str) -> dict[str, list[str]]:
    path = get_whois_path(ip)
    text = cached_or(path, lambda: perform_whois_live(ip))

    result: dict[str, list[str]] = {}

    lines: list[str] = text.split("\n")
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


def extract_ips(s: str) -> list[str]:
    nested = [x for x in (r.findall(s) for r in IP_REGEXES)]
    return list(set(itertools.chain.from_iterable(nested)))


def is_public_ip(ip: str) -> bool:
    return ip != "127.0.0.1" \
           and not ip.startswith("192.168.") \
           and not ip.startswith("10.") \
           and not ip.startswith("172.16")


def is_ipv4(ip: str) -> bool:
    return "." in ip


#
# header analysis
#

def header_contains_ip(k: str, v: str) -> bool:
    return "-ip" in k or \
           "spf" in k or \
           ("received" in k and "from" in v)


def is_spf_pass(k: str, v: str) -> bool:
    return "spf" in k and v.startswith("pass")


def date_from_headers(headers: list[str]) -> str:
    for [_, v] in headers:
        if BY_SEPARATOR in v:
            date = v.split(BY_SEPARATOR)[1].strip()
            if len(date) > 0:
                return date
    return headers[0]


#
# string operations
#

TITLE_SIZE = 32
BY_SEPARATOR = ' [BY];'


def separator() -> None:
    print("═" * (TITLE_SIZE + 2))


V_BAR = "│"
H_BAR = "─"


def print_table(data: list[list[str]]) -> None:
    if len(data) == 0:
        return None

    lengths: dict[int, int] = {}

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
    for row in data:
        cells = {k: v for k, v in enumerate(row)}
        draw = "{0}{1}{2}".format(
            V_BAR,
            V_BAR.join(map(lambda k: cells[k].ljust(lengths[k]), cells.keys())),
            V_BAR
        )
        print(draw)

        if i == 0:
            print(mid_border)
        i += 1

    print(end_border)


def format_dict(d: dict[str, str or list[str]]) -> str:
    result = []

    pad = 0
    for k in d.keys():
        if (l := len(k)) > pad:
            pad = l

    pad += 5

    for k, v in d.items():
        key = "{0} ".format(k)
        result += ["- {0} {1}".format(key.ljust(pad, "·"), v)]

    return "\n".join(result)


# https://theasciicode.com.ar/extended-ascii-code/box-drawing-character-single-line-lower-left-corner-ascii-code-192.html
def format_title(s: str) -> str:
    result = []

    text = " {0} ".format(s).ljust(TITLE_SIZE, " ")
    size = max(TITLE_SIZE, len(text))

    result += [""]
    result += ["╔{0}╗".format("═" * size)]
    result += ["║{0}║".format(text)]
    result += ["╚{0}╝".format("═" * size)]

    return "\n".join(result)


# http://patorjk.com/software/taag/#p=display&f=ANSI%20Shadow&t=EML
def build_intro() -> str:
    return """
    ███████╗███╗   ███╗██╗     
    ██╔════╝████╗ ████║██║     
    █████╗  ██╔████╔██║██║     
    ██╔══╝  ██║╚██╔╝██║██║     
    ███████╗██║ ╚═╝ ██║███████╗
    ╚══════╝╚═╝     ╚═╝╚══════╝"""


def extract_domain(s: str) -> str or None:
    if match := re.search('@([^>]+)', s, re.IGNORECASE):
        return match.group(1)


def highlight_domain(s: str) -> str:
    if domain := extract_domain(s):
        return s.replace(domain, color_red(domain))
    return s


#
# color string
#

def color_grey(s: str or list[str]) -> str:
    return color_with(s, Fore.LIGHTBLACK_EX)


def color_green(s: str or list[str]) -> str:
    return color_with(s, Fore.LIGHTGREEN_EX)


def color_cyan(s: str or list[str]) -> str:
    return color_with(s, Fore.LIGHTCYAN_EX)


def color_red(s: str or list[str]) -> str:
    return color_with(s, Fore.LIGHTRED_EX)


def color_with(s: str or list[str], f: str) -> str:
    return "{0}{1}{2}".format(f, str(s), Fore.RESET)


#
# type
#

class Hop:
    ip: str
    headers: list[str]
    date: str

    is_real: bool
    has_spf: bool

    formatter: Callable[[str], str]


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

    print(color_green(build_intro()))

    #
    # state
    #
    headers_true_negative = []
    headers_false_negative = []
    headers_false_positive = []

    special_headers_google_apps = set()

    sender_hops: OrderedDict[str, list[list[str]]] = OrderedDict()

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

                if len(ips) == 0:
                    headers_false_positive.append([k, v])
                    continue

                for ip in ips:
                    if ip not in sender_hops:
                        sender_hops[ip] = []
                    sender_hops[ip].append([k, v])

            else:
                ips = extract_ips(v)
                if len(ips) > 0:
                    headers_false_negative.append([k, v])
                else:
                    headers_true_negative.append(k)

    #
    # reversing IP order to make it desc by time
    #
    sender_hops: OrderedDict[str, list[str]] = OrderedDict(reversed(list(sender_hops.items())))

    #
    # from
    #
    print(format_title("From & Return-Path"))
    print(format_dict({f: highlight_domain(m[f]) for f in ["from", "return-path"]}))

    #
    # build hop entities
    #

    hops: list[Hop] = []
    for [ip, headers] in sender_hops.items():
        hop = Hop()
        hop.ip = ip
        hop.headers = headers
        hop.date = date_from_headers(headers)

        hop.has_spf = any(is_spf_pass(k, v) for [k, v] in headers)
        hop.is_real = any(BY_SEPARATOR in v for [_, v] in headers)

        hop.formatter = color_cyan
        if hop.has_spf:
            hop.formatter = color_green
        if not hop.is_real or not is_public_ip(hop.ip) or not is_ipv4(ip):
            hop.formatter = color_grey

        hops.append(hop)

    #
    # print chain
    #

    if len(hops) > 0:
        print(format_title("IP chain"))
        ip_dates: dict[str, str] = {}
        for hop in hops:
            ip_dates[hop.formatter(hop.ip)] = hop.formatter(hop.date)
        print(format_dict(ip_dates))

    #
    # print main hops
    #

    for hop in hops:
        if not is_ipv4(hop.ip):
            continue

        if not is_public_ip(hop.ip):
            continue

        # flags

        # title
        title = hop.ip
        if hop.has_spf:
            title = "{0} [SPF]".format(title)
        if not hop.is_real:
            title = "{0} [FORGED]".format(title)

        print(hop.formatter(format_title(title)))

        emails = set(get_abuse_emails(hop.ip))
        print(format_dict({
            color_red("TO"): ', '.join(emails),
            color_red("IP"): hop.ip,
            color_red("TS"): hop.date
        }))

        # if IPV4, lookup API
        if is_ipv4(hop.ip):
            lookup = extreme_lookup_ip(hop.ip)

            if "countryCode" in lookup:
                cert = cert_country(lookup["countryCode"])
                if cert is not None:
                    print(format_dict({"CC": ', '.join(cert)}))

            print()
            print("API [eXTReMe-IP-Lookup]:")
            print(format_dict(lookup))

        # WHOIS info
        whois = get_whois_info(hop.ip)
        if len(whois) > 0:
            print()
            print("WHOIS info:")
            print(format_dict(whois))

        # URLs with external resources
        external: dict[str, str] = {}

        if hop.has_spf:
            if match := re.search("domain of (.*) designates", str(hop.headers), re.IGNORECASE):
                spf_domain = match.group(1)
                if "@" in spf_domain:
                    spf_domain = spf_domain.split("@")[1]
                external["whois"] = "https://mxtoolbox.com/SuperTool.aspx?action=whois%3a+{0}".format(spf_domain)
                external["domain"] = "https://whois.domaintools.com/{0}".format(spf_domain)
                external["blacklist"] = "https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a{0}".format(spf_domain)
        external["IP"] = "https://anti-hacker-alliance.com/index.php?ip={0}&searching=yes".format(hop.ip)

        print()
        print("External resources:")
        print(format_dict(external))

        # headers
        print()
        print("Headers:")
        print(format_dict({color_red(k): v for [k, v] in hop.headers}))

    #
    # Google App
    #
    if len(special_headers_google_apps) > 0:
        print(format_title("SPECIAL :: Google app:"))
        print(special_headers_google_apps)

    #
    # false positives
    #
    if len(headers_false_positive) > 0:
        print(color_grey(format_title("False positive headers [{0}]".format(len(headers_false_positive)))))
        for k, v in headers_false_positive:
            print(color_grey("{0}: {1}".format(k, v)))

    #
    # false negatives
    #
    if len(headers_false_negative) > 0:
        print(color_grey(format_title("False negative headers [{0}]".format(len(headers_false_negative)))))
        print(color_grey(format_dict({k: v for k, v in headers_false_negative})))

    #
    # true negatives
    #
    if len(headers_true_negative) > 0:
        print(color_grey(format_title("True negative headers: [{0}]".format(len(headers_true_negative)))))
        print(color_grey(headers_true_negative))


if __name__ == '__main__':
    main()
