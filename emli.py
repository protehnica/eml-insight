import itertools
import os
import re
import subprocess
import sys
from email import message_from_string
from pathlib import Path
from typing import List, Generator, Tuple
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


def extreme_lookup_ip(ip: str) -> str:
    path = get_extreme_ip_lookup_path(ip)
    return cached_or(path, lambda: extreme_lookup_ip_live(ip))


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

STD_SIZE = 32


def separator() -> None:
    print("═" * (STD_SIZE + 2))


# https://theasciicode.com.ar/extended-ascii-code/box-drawing-character-single-line-lower-left-corner-ascii-code-192.html
def print_title(s: str) -> None:
    text = " {0} ".format(s).ljust(STD_SIZE, " ")
    size = max(STD_SIZE, len(text))

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

    special_headers_spf = []
    special_headers_google_apps = set()

    sender_hops = {}
    webmail_hops = []

    #
    # parse file
    #
    with open(file=filepath, encoding="latin-1", mode="r") as fp:
        data = fp.read()
        m = message_from_string(data)

        for k, v in parse_headers(data):
            v = re.sub(r' by .*', '', v).strip()

            google_app = re.compile('=([^=]*.gappssmtp.com)').findall(v)
            if len(google_app) > 0:
                special_headers_google_apps.add(google_app[0])

            if header_contains_ip(k, v):
                if is_spf_pass(k, v):
                    special_headers_spf.append([k, v])

                if header_is_webmail(v) and not is_spf_pass(k, v):
                    webmail_hops.append([k, v])
                    continue

                ips = extract_ips(v)
                ips = list(filter(is_public_ip, ips))

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
    # IPs
    #
    if len(sender_hops) > 0:
        print_title("IPs")

    for [ip, headers] in sender_hops.items():
        emails = set(get_abuse_emails(ip))
        print("TO: {0}".format(', '.join(emails)))
        print("IP: {0}".format(ip))

        print()
        print("Headers:")
        for [k, v] in headers:
            print("- {0} {1}".format(k, v))

        print()
        print("API:")
        lookup = extreme_lookup_ip(ip)
        print(lookup)

        separator()

    #
    # from
    #
    print_title("From")
    print(m["from"])

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
    # SPF
    #
    if len(special_headers_spf) > 0:
        print_title("SPECIAL :: SPF")
        print(special_headers_spf)

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
        for k, v in headers_false_negative:
            print("- {0}: {1}".format(k, v))

    #
    # true negatives
    #
    if len(headers_true_negative) > 0:
        print_title("True negative headers: [{0}]".format(len(headers_true_negative)))
        print(headers_true_negative)


if __name__ == '__main__':
    main()
