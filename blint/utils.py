import base64
import math
import os
import re
import string
from pathlib import Path

charset = string.digits + string.ascii_letters + r"""!&@"""

# Default ignore list
ignore_directories = [
    ".git",
    ".svn",
    ".mvn",
    ".idea",
    "backup",
    "docs",
    "tests",
    "test",
    "report",
    "reports",
    "node_modules",
    ".terraform",
    ".serverless",
    "venv",
    "examples",
    "tutorials",
    "samples",
    "migrations",
    "db_migrations",
    "unittests",
    "unittests_legacy",
    "stubs",
    "mock",
    "mocks",
]

ignore_files = [
    ".pyc",
    ".gz",
    ".tar",
    ".tar.gz",
    ".tar",
    ".log",
    ".tmp",
    ".gif",
    ".png",
    ".jpg",
    ".webp",
    ".webm",
    ".icns",
    ".pcm",
    ".wav",
    ".mp3",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".d.ts",
    ".min.js",
    ".min.css",
    ".eslintrc.js",
    ".babelrc.js",
    ".spec.js",
    ".spec.ts",
    ".component.spec.js",
    ".component.spec.ts",
    ".data.js",
    ".data.ts",
    ".bundle.js",
    ".snap",
    ".pb.go",
    ".tests.py",
    ".vdb",
    ".txt",
    ".strings",
    ".nib",
]

strings_allowlist = [
    "()",
    "[]",
    "{}",
    " ",
    "&*",
    "(*",
    "$*",
    "!*",
    "*func",
    "*map",
    "Enabled",
    "crypto/",
    "readBase",
    "toFloat",
    "encoding/",
    "*tls",
    "*http",
    "*grpc",
    "protobuf:",
    "*runtime",
    "*x509",
    "*[",
    "*struct",
    "github.com",
    "vendor/",
    "golang.org",
    "gopkg.in",
    "*reflect",
    "*base64",
    "*pgtype",
    "*dsa",
    "*log",
    "*sql",
    "*zip",
    "*json",
    "*yaml",
    "*xz",
    "*errors",
    "*flag",
    "*object",
    "*ssh",
    "*syntax",
    "*zip",
    "json:",
    "basic_string",
    "std::",
    "vector::",
    "coreclr_",
    "deps_resolver_",
    "deps_json_",
    "NativeExceptionHolder",
    "System.Runtime",
    "Microsoft-",
    "ProfilerEnum",
    "FastSerialization",
    "InlineDiscretionary",
    "src/libraries",
    "ECDHE-ECDSA-AES256-GCM",
    "setsockopt",
    ".jar",
]

secrets_regex = {
    "artifactory": [
        re.compile(r'(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}'),
        re.compile(r'(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}'),
    ],
    "aws": [
        re.compile(
            r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
        ),
        re.compile(r"""(?i)aws(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]"""),
        re.compile(
            r"""amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"""
        ),
        re.compile(r"da2-[a-z0-9]{26}"),
        re.compile(r"s3\\.amazonaws\\.com"),
        re.compile(r"ec2-[0-9a-z.\\-_]+\\.compute(-1)?\\.amazonaws\\.com"),
        re.compile(r"[0-9a-z.\\-_]+\\.elb\\.[0-9a-z.\\-_]+\\.amazonaws\\.com"),
        re.compile(r"[0-9a-z.\\-_]+\\.rds\\.amazonaws\\.com"),
        re.compile(r"[0-9a-z.\\-_]+\\.cache\\.amazonaws\\.com"),
        re.compile(r"[0-9a-z.\\-_]+\\.s3-website[0-9a-z.\\-_]+\\.amazonaws\\.com"),
        re.compile(r"[0-9a-z]+\\.execute-api\\.[0-9a-z.\\-_]+\\.amazonaws\\.com"),
    ],
    "github": [
        re.compile(r"""(?i)github.{0,3}(token|api|key).{0,10}?([0-9a-zA-Z]{35,40})""")
    ],
    "slack": [re.compile(r"""xox[baprs]-([0-9a-zA-Z]{10,48})?""")],
    "EC": [re.compile(r"""-----BEGIN EC PRIVATE KEY-----""")],
    "DSA": [re.compile(r"""-----BEGIN DSA PRIVATE KEY-----""")],
    "OPENSSH": [re.compile(r"""-----BEGIN OPENSSH PRIVATE KEY-----""")],
    "RSA": [re.compile(r"""-----BEGIN RSA PRIVATE KEY-----""")],
    "PGP": [re.compile(r"""-----BEGIN PGP PRIVATE KEY-----""")],
    "google": [
        re.compile(r"""AIza[0-9A-Za-z\\-_]{35}"""),
        re.compile(r"""[sS][eE][cC][rR][eE][tT].*['|"][0-9a-zA-Z]{32,45}['|"]"""),
        re.compile(r"""[sS][eE][cC][rR][eE][tT].*['|"][0-9a-zA-Z]{32,45}['|"]"""),
        re.compile(r"""[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"""),
    ],
    "heroku": [
        re.compile(
            r"""(?i)heroku(.{0,20})?['"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]"""
        )
    ],
    "mailchimp": [
        re.compile(r"""(?i)(mailchimp|mc)(.{0,20})?['"][0-9a-f]{32}-us[0-9]{1,2}['"]""")
    ],
    "mailgun": [re.compile(r"""(?i)(mailgun|mg)(.{0,20})?['"][0-9a-z]{32}['"]""")],
    "slack_webhook": [
        re.compile(
            r"""https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"""
        )
    ],
    "stripe": [re.compile(r"""(?i)stripe(.{0,20})?['"][s|k]k_live_[0-9a-zA-Z]{24}""")],
    "square": [
        re.compile(r"""sq0atp-[0-9A-Za-z\-_]{22}"""),
        re.compile(r"""sq0atp-[0-9A-Za-z\-_]{43}"""),
    ],
    "twilio": [re.compile(r"""(?i)twilio(.{0,20})?['"][0-9a-f]{32}['"]""")],
    "dynatrace": [
        re.compile(r"""dt0[a-zA-Z]{1}[0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}""")
    ],
    "url": [
        re.compile(r"""(http(s)?|s3)://"""),
        re.compile(
            r"""[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}["'\\s]"""
        ),
        re.compile(
            r"(ftp|jdbc:mysql)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]"
        ),
    ],
    "authorization": [
        re.compile(
            r"(authorization)\\s*:\\s*(bearer|token|basic)\\s+[0-9a-z\\.\\-_]{6,}"
        ),
        re.compile(r"eyJ[A-Za-z0-9_/+-]*\.[A-Za-z0-9._/+-]*"),
    ],
    "email": [
        re.compile(r"(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+")
    ],
    "ip": [
        re.compile(
            r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        )
    ],
}


def is_base64(s):
    try:
        return s.endswith("==") or base64.b64encode(base64.b64decode(s)) == s
    except Exception:
        return False


def decode_base64(s):
    s = s.replace("\n", "")
    if is_base64(s):
        decoded = base64.b64decode(s)
        try:
            return decoded.decode()
        except Exception:
            return str(decoded)
    return s


def is_camel_case(s):
    s = re.sub(r"[*._#%&!\"]", "", s)
    for x in string.digits:
        if x in s:
            return False
    for x in string.punctuation:
        if x in s:
            return False
    return s != s.lower() and s != s.upper() and "_" not in s


def calculate_entropy(data):
    if not data or len(data) < 8:
        return 0
    for text in strings_allowlist:
        if text in data:
            return 0
    entropy = 0.0
    # Remove protocol prefixes which tend to increase false positives
    data = re.sub(r"(file|s3|http(s)?|email|ftp)://", "", data)
    digit_found = False
    punctuation_found = False
    ascii_found = False
    for x in charset:
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            if not ascii_found and x in string.ascii_letters:
                ascii_found = True
            if not digit_found and x in string.digits:
                digit_found = True
            if not punctuation_found and x in string.punctuation:
                punctuation_found = True
            entropy += -p_x * math.log(p_x, 256)
    if is_camel_case(data) or data.lower() == data or data.upper() == data:
        return min(0.2, round(entropy, 2))
    if ascii_found and (digit_found or punctuation_found):
        if not punctuation_found:
            return min(0.38, round(entropy, 2))
        return round(entropy, 2)
    else:
        return min(0.4, round(entropy, 2))


def check_secret(data):
    for text in strings_allowlist:
        if text in data:
            return None
    for category, rlist in secrets_regex.items():
        for regex in rlist:
            for match in regex.findall(data):
                return category
    return None


def is_binary_string(content):
    """
    Method to check if the given content is a binary string
    """
    textchars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
    return bool(content.translate(None, textchars))


def is_ignored_file(file_name):
    """
    Method to find if the given file can be ignored
    :param file_name: File to compare
    :return: Boolean True if file can be ignored. False otherwise
    """
    if not file_name:
        return False
    file_name = file_name.lower()
    extn = "".join(Path(file_name).suffixes)
    if extn in ignore_files or file_name in ignore_files:
        return True
    for ie in ignore_files:
        if file_name.endswith(ie):
            return True
    return False


def is_exe(src):
    """Detect if the source is a binary file

    :param src: Source path

    :return True if binary file. False otherwise.
    """
    if os.path.isfile(src):
        try:
            return is_binary_string(open(src, "rb").read(1024))
        except Exception:
            return False
    return False


def filter_ignored_dirs(dirs):
    """
    Method to filter directory list to remove ignored directories
    :param dirs: Directories to ignore
    :return: Filtered directory list
    """
    [
        dirs.remove(d)
        for d in list(dirs)
        if d.lower() in ignore_directories or d.startswith(".")
    ]
    return dirs


def find_exe_files(src):
    """
    Method to find files with given extenstion
    """
    result = []
    for root, dirs, files in os.walk(src):
        filter_ignored_dirs(dirs)
        for file in files:
            if is_ignored_file(file):
                continue
            fullPath = os.path.join(root, file)
            if is_exe(fullPath):
                result.append(fullPath)
    return result
