import base64
import binascii
import math
import os
import re
import shutil
import string
import zipfile
from importlib.metadata import distribution
from pathlib import Path

import lief
from defusedxml.ElementTree import fromstring
from rich import box
from rich.table import Table

from blint.logger import console, LOG

CHARSET = string.digits + string.ascii_letters + r"""!&@"""

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
    ".nupkg",
]

strings_allowlist = {
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
}

# Method names containing common verbs that could be fuzzed
fuzzable_names = [
    "create", "delete", "update", "insert", "upsert", "post",
    "put", "get", "index", "encrypt", "decrypt", "load", "import", "export",
    "encode", "decode", "obfuscate", "store", "fuzz", "route", "search", "find",
    "open", "send", "receive", "approve", "reject", "password", "lock", "find",
    "allocate", "peer", "block", "socket", "database", "remote", "api", "build",
    "transact", "engage", "quote", "unicode", "escape", "invoke", "execute",
    "process", "shell", "env", "valid", "saniti", "check", "audit", "follow",
    "link",
]
fuzzable_names += [
    "expect", "add", "report", "compare", "base", "close",
    "offer", "price", "approve", "increase", "become", "propose", "decline",
    "raise", "estimate", "call", "design", "acquire", "gain", "reach",
    "announce", "fill", "became", "include", "decid", "disclose", "agree",
    "fail", "complete", "raise", "trade", "continue", "include", "believe",
    "receive", "schedule", "indicate", "provide", "help", "need", "cause",
    "drop", "show", "order", "chang", "launch", "reduce", "plan", "want",
    "follow", "trade", "improve", "issu", "involve", "reject", "increase",
    "turn", "barr", "earn", "consent", "total", "acquire", "require", "prefer",
    "produce", "introduce", "consider", "suspend", "prove", "open", "close",
    "boost", "list", "prepare", "allow", "approve", "wrote", "reduce",
    "advance", "describe", "produce", "operate", "surge", "jump", "provide",
    "mature", "stop", "work", "introduce", "relate", "improve", "seem", "force",
    "leave", "believe", "develop", "decline", "expire", "invest", "settle",
    "change", "contribute", "elaborate", "refuse", "quote", "pass", "threaten",
    "cause", "violate", "soar", "eliminate", "create", "replace", "argue",
    "elect", "complete", "issue", "register", "pursue", "combine", "start",
    "cover", "eliminate", "plunge", "contain", "manag", "suggest", "appear",
    "discover", "oppose", "form", "limit", "force", "disgorge", "attribut",
    "studi", "resign", "settl", "retire", "move", "anticipat", "decide",
    "prompt", "maintain", "rang", "focus", "climb", "adjust", "award", "carri",
    "identif", "confirm", "match", "conclude", "sign", "adopt", "accept",
    "expand", "exercise", "finish", "finance", "charge", "realize", "remain",
    "express", "replace", "deliver", "dump", "import", "assume", "capture",
    "join", "releas", "lower", "exce", "determin", "locat", "appli", "complain",
    "trigger", "enter", "intend", "purchas", "blam", "learn", "renew", "view",
    "speculat", "choose", "respond", "encourage", "dismiss", "realiz", "serve",
    "associat", "slipp", "spark", "negotiate", "pleas", "divid", "financ",
    "execute", "discuss", "hir", "reflect", "determine", "market", "warn",
    "qualifi", "explain", "impose", "recognize", "indicate", "point", "collect",
    "benefit", "attach", "compete", "incurr", "remove", "share", "request",
    "permit", "remove", "revive", "predict", "couple", "play", "commit",
    "revive", "kill", "present", "deserve", "convict", "agree", "accommodate",
    "surrender", "restore", "restructur", "fear", "represent", "fund",
    "involve", "redeem", "resolve", "obtain", "employ", "promote", "impose",
    "insist", "contact", "print", "advertise", "damage", "exercis", "auction",
    "disappoint", "subordinat", "secure", "integrat", "perform", "stepp",
    "regulat", "trail", "occurr", "expell", "amount", "back", "regard",
    "conclude", "dominat", "push", "rumor", "respect", "specifi", "support",
    "abandon", "figure", "extend", "tender", "unveil", "expose", "industrializ",
    "regulate", "contract", "lift", "welcom", "squeez", "prolong", "record",
    "announce", "assert", "inch", "manufacture", "describe", "calculate",
    "favor", "train", "institut", "concern", "accelerat", "solve", "store",
    "assembl", "link", "advertis", "kick", "scrambl", "skyrocket", "target",
    "crippl", "stress", "manufactur", "provoke", "handle", "poll", "endors",
    "balk", "compensate", "terminate", "operate", "admit", "attract", "feature",
    "devote", "triple", "concentrat", "plead", "inspir", "defend", "treat",
    "violat", "enforce", "surfac", "concentrate", "suffer", "advis",
    "interview", "gauge", "measur", "hamper", "nominat", "assure", "merge",
    "achieve", "retain", "chair", "relegat", "mount", "Ask", "compil",
    "Guarante", "position", "lock", "roll", "drift", "Estimat", "persuade",
    "survive", "Found", "chastis", "handl", "press", "sweeten", "allocat",
    "criticiz", "place", "prais", "install", "weigh", "perceiv", "remark",
    "moderat", "stat", "rush", "surpris", "collaps", "licens", "disagree",
    "publiciz", "pressure", "drive", "omitt", "assum", "switch", "define",
    "sound", "invent", "absorb", "found", "observ", "desir", "sustain",
    "welcome", "load", "engag", "drove", "pegg", "compromise", "enact",
    "negotiate", "result", "prove", "examine", "connect", "subscribe", "organi",
    "diminish", "purchase", "answer", "orient", "control", "Post", "succeed",
    "rewrite", "nominate", "discharge", "entrust", "range", "attempt",
    "recover", "maximize", "engage", "obligat", "label", "refuse", "denounce",
    "seize", "halt", "transform", "contribute", "tolerate", "cool", "overcome",
    "caution", "claim", "discontinu", "select", "participate", "bolster",
    "devise", "doubt", "write", "exchange", "narrow", "strike", "diagnos",
    "classif", "outlaw", "ventilat", "slide", "track", "lengthen", "ensnarl",
    "oversee", "renovat", "accumulat", "underscore", "guarante", "shore",
    "evaluat", "clutter", "refile", "expedit", "disput", "refund", "scrapp",
    "complicate", "exist", "Regard", "halve", "store", "adapt", "achiev",
    "resume", "assist", "incorporat", "capp", "stake", "outpac", "burn",
    "clobber", "alarm", "fatten", "amend", "book", "watch", "number", "whistle",
    "perpetuate", "root", "publish", "abide", "ration", "host", "assign",
    "designat", "survey", "espouse", "strapp", "twinn", "authoriz", "paint",
    "accru", "swapp", "obsess", "Film", "jostle", "populat", "curl", "dream",
    "resonate", "glamorize", "collaborat", "enabl", "chopp", "celebrate",
    "scatter", "prosecute", "unleash", "Compare", "superimpos", "nurtur",
    "shake", "interrogat", "clean", "knitt", "assemble", "voice", "monopolize",
    "spott", "Confront", "underline", "prosecut", "enhanc", "depend", "inflat",
    "educat", "fad", "stabb", "resolv", "usher", "struggl", "distinguish",
    "prepare", "copi", "broke", "car", "crowd", "decri", "overus", "enrag",
    "expung", "crank", "touch", "replicat", "devis", "replicate", "discontinue",
    "recommend", "embroil", "defuse", "judg", "polariz", "discourage",
    "regenerate", "Rekindl", "averag", "protect", "prohibit", "initiat", "mail",
    "quipp", "advocate", "appoint", "exhibit", "empower", "manipulate",
    "specialize", "summon", "apologize", "emerge", "phase", "fabricate",
    "speculate", "buoy", "convinc", "erode", "trac", "recede", "flood", "bill",
    "alienat", "portray", "recycle", "service", "Develop", "confuse",
    "materialize", "convert", "equipp", "depress", "enclos", "single", "zoom",
    "command", "exhaust", "yield", "talk", "excit", "overpric", "expir",
    "postpon", "reschedul", "evaporat", "rebuff", "review", "clamp", "interest",
    "license", "patent", "stirr", "devot", "escalat", "clarifi", "cross",
    "penetrate", "guid", "milk", "generate", "double", "compet", "borrow",
    "computerize", "analyze", "cultivat", "tailor", "delete", "experience",
    "troubl", "institute", "reopen", "knock", "synchronize", "aggravat",
    "anger", "annoy", "attend", "evoke", "scrape", "state", "memorize", "muffl",
    "stare", "advance", "fill", "sack", "entitl", "dress", "decorat", "unsettl",
    "breathe", "tank", "escap", "declare", "measure", "infring", "establish",
    "lack", "spoke", "afflict", "harp", "seduce", "remind", "reprove",
    "deteriorat", "codifi", "pull", "acknowledge", "hop", "arriv", "discard",
    "click", "visit", "disapprove", "defin", "disciplin", "Reach", "rectifi",
    "screw", "block", "emigrate", "imagine", "tighten", "reap", "ascribe",
    "tout", "acced", "entice", "pick", "impress", "entic", "befuddl", "possess",
    "skipp", "graduat", "engineer", "inherit", "diversifi", "provok",
    "reallocate", "stripp", "reallocat", "broaden", "instruct", "draft",
    "waive", "bounce", "repair", "propose", "alter", "correct", "promis",
    "impli", "emphasiz", "predispose", "compos", "quote", "robb", "bother",
    "chose", "participat", "Choose", "depriv", "override", "impede", "impair",
    "dubb", "propagandize", "clipp", "transcribe", "happen", "disseminate",
    "preclude", "mention", "examine", "disagre", "prescribe", "assure", "react",
    "advocat", "convince", "exud", "Annualiz", "clash", "evolv", "enjoy",
    "recruit", "intimidate", "Provid", "predicat", "constru", "emasculate",
    "ensure", "wast", "disapprov", "invite", "ratifi", "characteriz", "excise",
    "sav", "mortgag", "reclaim", "parch", "profit", "curtail", "strengthen",
    "cushion", "materializ", "flirt", "fold", "brighten", "restor", "headlin",
    "hand", "beleaguer", "disclose", "approach", "screen", "miss", "preapprov",
    "test-drive", "retrac", "account", "vest", "heat", "exacerbat", "telephone",
    "wedd", "wait", "sneak", "head", "curb", "battle", "entrench", "facilitate",
    "stack", "constitute", "despise", "frighten", "manage", "juggle", "automat",
    "dislike", "spook", "orchestrat", "mint", "chase", "practic", "arise",
    "evolve", "implement", "decrease", "sacrifice", "Eliminate", "please",
    "advise", "grapple", "appropriat", "stifle", "notice", "document",
    "migrate", "color", "Fund", "Concern", "spurn", "overvalu", "recoup",
    "hunt", "promise", "breath", "enable", "combine", "insur", "look",
    "redistribute", "field", "concede", "endorse", "justifi", "structur",
    "downgrad", "generat", "arrang", "overstat", "circulat", "midsiz",
    "eclipse", "stretch", "debate", "assess", "revers", "chill", "insert",
    "outnumber", "surge", "direct", "stimulat", "tempt", "overdone", "waive",
    "notch", "search", "calculat", "tackle", "spackle", "dispos", "stay",
    "revis", "conduct", "rank", "blurr", "compare", "topp", "outdistanc",
    "relaunch", "repric", "guarantee", "hail", "despis", "subsidize", "appease",
    "co-found", "coordinate", "heighten", "nullifi", "puzzl", "challenge",
    "notifi", "clear", "delist", "explore", "emerg", "singl", "sagg", "grant",
    "confus", "complicat", "Continu", "ignor", "secede", "accrue", "term",
    "stemm", "magnifi", "reimburs", "arrive", "firm", "falter", "sense",
    "distribut", "experienc", "customiz", "deriv", "avert", "slat",
    "realestate", "reorganiz", "plagu", "bounc", "reaffirm", "demobilize",
    "brush", "sabotage", "assassinat", "avenge", "pledg", "defeat", "rigg",
    "subpoena", "plant", "explod", "centraliz", "fizzl", "restructure",
    "mitigate", "reserv", "batter", "induce", "investigate", "estimate",
    "question", "trimm", "detail", "travel", "plugg", "fashion", "arrest",
    "Absorb", "finaliz", "lease", "dash", "sputter", "harvest", "gyrate",
    "scrounge", "alleviate", "slow", "deplete", "relieve", "compress", "delay",
    "influence", "plummet", "exceed", "coat", "scuttle", "share",
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
            r"""amzn.mws.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"""
        ),
        re.compile(r"da2-[a-z0-9]{26}"),
        re.compile(r"s3.amazonaws.com"),
        re.compile(r"ec2-[0-9a-z.-_]+.compute(-1)?.amazonaws.com"),
        re.compile(r"[0-9a-z.-_]+.elb.[0-9a-z.-_]+.amazonaws.com"),
        re.compile(r"[0-9a-z.-_]+.rds.amazonaws\\.com"),
        re.compile(r"[0-9a-z.-_]+.cache.amazonaws.com"),
        re.compile(
            r"[0-9a-z.-_]+.s3-website[0-9a-z.-_]+.amazonaws.com"
        ),
        re.compile(
            r"[0-9a-z]+.execute-api.[0-9a-z.\-_]+.amazonaws.com"
        ),
    ],
    "github": [
        re.compile(
            r"""(?i)github.{0,3}(token|api|key).{0,10}?([0-9a-zA-Z]{35,40})"""
        )
    ],
    "slack": [re.compile(r"""xox[baprs]-([0-9a-zA-Z]{10,48})?""")],
    "EC": [re.compile(r"""-----BEGIN EC PRIVATE KEY-----""")],
    "DSA": [re.compile(r"""-----BEGIN DSA PRIVATE KEY-----""")],
    "OPENSSH": [re.compile(r"""-----BEGIN OPENSSH PRIVATE KEY-----""")],
    "RSA": [re.compile(r"""-----BEGIN RSA PRIVATE KEY-----""")],
    "PGP": [re.compile(r"""-----BEGIN PGP PRIVATE KEY-----""")],
    "google": [
        re.compile(r"""AIza[0-9A-Za-z\-_]{35}"""),
        re.compile(
            r"""[sS][eE][cC][rR][eE][tT].*['"][0-9a-zA-Z]{32,45}['"]"""
        ),
        re.compile(
            r"""[sS][eE][cC][rR][eE][tT].*['"][0-9a-zA-Z]{32,45}['"]"""
        ),
        re.compile(
            r"""[0-9]+-[0-9A-Za-z_]{32}.apps.googleusercontent.com"""
        ),
    ],
    "heroku": [
        re.compile(
            r"""(?i)heroku(.{0,20})?['"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]"""
        )
    ],
    "mailchimp": [
        re.compile(
            r"""(?i)(mailchimp|mc)(.{0,20})?['"][0-9a-f]{32}-us[0-9]{1,2}['"]"""
        )
    ],
    "mailgun": [
        re.compile(r"""(?i)(mailgun|mg)(.{0,20})?['"][0-9a-z]{32}['"]""")
    ],
    "slack_webhook": [
        re.compile(
            r"https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"
        )
    ],
    "stripe": [
        re.compile(r"""(?i)stripe(.{0,20})?['"][s|k]k_live_[0-9a-zA-Z]{24}""")
    ],
    "square": [
        re.compile(r"""sq0atp-[0-9A-Za-z\-_]{22}"""),
        re.compile(r"""sq0atp-[0-9A-Za-z\-_]{43}"""),
    ],
    "twilio": [re.compile(r"""(?i)twilio(.{0,20})?['"][0-9a-f]{32}['"]""")],
    "dynatrace": [
        re.compile(r"""dt0[a-zA-Z][0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}""")
    ],
    "url": [
        re.compile(r"""(http(s)?|s3)://"""),
        re.compile(
            r"""[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["'\s]"""
        ),
        re.compile(
            r"(ftp|jdbc:mysql)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]"
        ),
    ],
    "authorization": [
        re.compile(
            r"(authorization)\s*:\s*(bearer|token|basic)\s+[0-9a-z.\-_]{6,}"
        ),
        re.compile(r"eyJ[A-Za-z0-9_/+-]*\.[A-Za-z0-9._/+-]*"),
    ],
    "email": [
        re.compile(
            r"(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+.[a-zA-Z0-9.-]+"
        )
    ],
    "ip": [
        re.compile(
            r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]).){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
        )
    ],
}


def is_base64(s):
    """
    Checks if the given string is a valid Base64 encoded string.

    Args:
        s (str or bytes): The string to be checked.

    Returns:
        bool: True if the string is a valid Base64 encoded string.
    """
    try:
        decoded = base64.b64decode(s)
        return s.endswith("==") or base64.b64encode(decoded) == s.encode()
    except (binascii.Error, TypeError, UnicodeError) as e:
        LOG.debug(f"Caught {type(e)}: {e} while checking if {s} is base64")
        return False


def decode_base64(s):
    """
    This function decodes a Base64 encoded string. It first removes any newline
    characters from the input string. Then, it checks if the string is a valid
    Base64 encoded string using the `is_base64` function. If it is valid, the
    string is decoded using the Base64 decoding algorithm. If the decoded string
    can be successfully decoded as UTF-8, the decoded string is returned.
    Otherwise, the decoded string is returned as a byte string. If the input
    string is not a valid Base64 encoded string, it is returned as is.

    Args:
        s (str or bytes): The Base64 encoded string to be decoded.

    Returns:
      - str or bytes: Decoded string, either a UTF-8 string or a byte string.
    """
    s = s.replace("\n", "")
    if is_base64(s):
        decoded = base64.b64decode(s)
        try:
            return decoded.decode()
        except (binascii.Error, UnicodeError):
            return str(decoded)
    return s


def is_camel_case(s):
    """
    Checks if the given string follows the camel case naming convention.

    Args:
        s (str): The string to be checked.

    Returns:
        bool: True if the string follows the camel case naming convention.
    """
    s = re.sub(r"[*._#%&!\"]", "", s)
    for x in string.digits:
        if x in s:
            return False
    for x in string.punctuation:
        if x in s:
            return False
    return s != s.lower() and s != s.upper() and "_" not in s


def calculate_entropy(data):
    """
    This function calculates the entropy of the given data to measure its
    randomness or predictability. It first performs checks to handle special
    cases, such as empty data or data with a length less than 8. Then, it
    removes certain protocol prefixes from the data to reduce false positives.
    Next, it calculates the entropy based on the character frequencies in the
    data using the Shannon entropy formula. The entropy value represents the
    amount of uncertainty or randomness in the data. Finally, it applies
    additional conditions to adjust the entropy value based on the data's
    characteristics.

    Args:
        data: The data for which entropy needs to be calculated.

    Returns:
        float: The calculated entropy value.
    """
    if not data or len(data) < 8:
        return 0

    if any(text in data for text in strings_allowlist):
        return 0

    entropy = 0.0

    # Remove protocol prefixes which tend to increase false positives
    data = re.sub(r"(file|s3|http(s)?|email|ftp)://", "", data)

    if not data:
        return entropy

    char_count = {}
    for char in data:
        char_count[char] = char_count.get(char, 0) + 1

    total_chars = len(data)
    ascii_found = any(char in string.ascii_letters for char in char_count)
    digit_found = any(char in string.digits for char in char_count)
    punctuation_found = any(char in string.punctuation for char in char_count)

    for count in char_count.values():
        p_x = count / total_chars
        entropy += -p_x * math.log(p_x, 256)

    if is_camel_case(data) or data.lower() == data or data.upper() == data:
        return min(0.2, round(entropy, 2))

    if not ascii_found or (not digit_found and not punctuation_found):
        return min(0.4, round(entropy, 2))

    return round(entropy, 2) if punctuation_found else min(0.38,
                                                           round(entropy, 2))


def check_secret(data):
    """
    This function checks if the given data contains any secrets. It first checks
    if any strings from the allowlist are present in the data. If so, it returns
    an empty string to indicate no secrets found. Then, it iterates over a set
    of regular expressions categorized by secrets and checks if any of the
    regular expressions match the data. If a match is found, it returns the
    corresponding category. If no secrets are found, it returns an empty string.

    Args:
      - data: The data to be checked for secrets.

    Returns:
        str: The category of the secret if found, otherwise an empty string.
    """
    if any(text in data for text in strings_allowlist):
        return ""

    for category, rlist in secrets_regex.items():
        for regex in rlist:
            if regex.search(data):
                return category

    return ""


def is_binary_string(content):
    """
    Method to check if the given content is a binary string
    """
    # text_chars = bytearray(
    #     {7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
    # return bool(
    #     content.translate(bytes.maketrans(b"", text_chars)))
    textchars = bytearray(
        {7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F}
    )
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
    return any(file_name.endswith(ie) for ie in ignore_files)


def is_exe(src):
    """
    Detect if the source is a binary file

    Args:
        src: Source path

    Returns:
         bool: True if binary file. False otherwise.
    """
    if os.path.isfile(src):
        try:
            with open(src, "rb") as f:
                data = f.read(1024)
            return is_binary_string(data)
        except (TypeError, OverflowError, ValueError, OSError) as e:
            LOG.debug(f"Caught {type(e)} while reading file: {src}")
            return False
    return False


def filter_ignored_dirs(dirs):
    """
    Method to filter directory list to remove ignored directories

    Args:
        dirs: Directories

    Returns:
        list: Filtered list of directories
    """
    return [
        dirs.remove(d)
        for d in list(dirs)
        if d.lower() in ignore_directories or d.startswith(".")
    ]


def find_exe_files(src):
    """
    Method to find files with given extension

    Args:
        src (str): Source path

    Returns:
        list: List of filtered files
    """
    result = []
    for root, dirs, files in os.walk(src):
        filter_ignored_dirs(dirs)
        for file in files:
            if is_ignored_file(file):
                continue
            full_path = os.path.join(root, file)
            if is_exe(full_path):
                result.append(full_path)
    return result


def find_android_files(path):
    """
    Method to find android app files

    :param path: Project directory
    :return: List of android files
    """
    app_extns = [".apk", ".aab"]
    return find_files(path, app_extns)


def find_files(path, extns):
    """
    Method to find files matching an extension
    """
    result = []
    if os.path.isfile(path):
        result.extend(path for ext in extns if path.endswith(ext))
    else:
        for root, dirs, files in os.walk(path):
            filter_ignored_dirs(dirs)
            for file in files:
                result.extend(
                    os.path.join(root, file)
                    for ext in extns if file.endswith(ext)
                )
    return result


def bom_strip(manifest):
    """
    Function to delete UTF-8 BOM character in "string"

    Args:
        manifest (str): Executable manifest

    Returns:
        str: Manifest without BOM character
    """
    utf8_bom = b"\xef\xbb\xbf"
    return manifest[3:] if manifest[:3] == utf8_bom else manifest


def parse_pe_manifest(manifest):
    """
    Method to parse xml pe manifest

    Args:
        manifest (str): Executable manifest

    Returns:
        dict: Parsed manifest with flattened keys and values
    """
    try:
        attribs_dict = {}
        root = fromstring(bom_strip(manifest))
        for child in root:
            for ele in child.iter():
                attribs_dict[ele.tag.rpartition("}")[-1]] = ele.attrib
        return attribs_dict
    except (TypeError, AttributeError, IndexError) as e:
        LOG.debug(f"Caught {type(e)}: {e} while parsing PE manifest.")
        return {}


def is_fuzzable_name(name_str):
    """
    This function checks if a given name string is fuzzable.
    """
    return any(n.lower() in name_str for n in fuzzable_names) if name_str else False


def print_findings_table(findings, files):
    """
    Prints the findings in a formatted table.

    This function takes a list of findings and a list of files, and prints the
    findings in a table format. The table includes columns for ID, Binary (if
    multiple files), Title, and Severity.

    Args:
        findings (list[dict]): A list of dictionaries representing the findings
        files (list[str]): A list of files.
    """
    table = Table(
        title="BLint Findings", box=box.DOUBLE_EDGE,
        header_style="bold magenta", show_lines=True,
    )
    table.add_column("ID")
    if len(files) > 1:
        table.add_column("Binary")
    table.add_column("Title")
    table.add_column("Severity")
    for f in findings:
        severity = f.get("severity").upper()
        severity_fmt = (
            f'{"[bright_red]" if severity in ("CRITICAL", "HIGH") else ""}'
            f'{severity}')
        if len(files) > 1:
            table.add_row(
                f.get("id"), f.get("exe_name"), f.get("title"), severity_fmt, )
        else:
            table.add_row(f.get("id"), f.get("title"), severity_fmt, )
    console.print(table)


def gen_file_list(src):
    """Generates a list of files from the given source.

    This function generates a list of executable files from a source directory
    or identifies a file.

    Args:
        src (str): A source file/directory

    Returns:
        list: A list of files.
    """
    files = []
    for s in src:
        if os.path.isdir(s):
            files += find_exe_files(s)
        else:
            if is_ignored_file(s):
                continue
            full_path = os.path.abspath(s)
            if is_exe(full_path):
                files.append(full_path)
    return files


def unzip_unsafe(zf, to_dir):
    """Method to unzip the file in an unsafe manne"""
    with zipfile.ZipFile(zf, "r") as zip_ref:
        zip_ref.extractall(to_dir)


def check_command(cmd):
    """
    Method to check if command is available
    :return True if command is available in PATH. False otherwise
    """
    cpath = shutil.which(cmd, mode=os.F_OK | os.X_OK)
    return cpath is not None


def get_version():
    """
    Returns the version of depscan
    """
    return distribution("blint").version


def cleanup_dict_lief_errors(old_dict):
    """
    Removes lief_errors from a dictionary recursively.

    Args:
        old_dict (dict): The dictionary to remove lief_errors from.

    Returns:
        dict: A new dictionary with lief_errors removed.

    """
    new_dict = {}
    for key, value in old_dict.items():
        if isinstance(value, lief.lief_errors):
            continue
        if isinstance(value, dict):
            entry = cleanup_dict_lief_errors(value)
        elif isinstance(value, list):
            entry = cleanup_list_lief_errors(value)
        else:
            entry = value
        new_dict[key] = entry
    return new_dict


def cleanup_list_lief_errors(d):
    """
    Cleans up a list by removing lief errors recursively.

    :param d: The list to be cleaned up.

    :return: The new list
    """
    new_lst = []
    for dl in d:
        if isinstance(dl, lief.lief_errors):
            continue
        if isinstance(dl, dict):
            entry = cleanup_dict_lief_errors(dl)
        elif isinstance(dl, list):
            entry = cleanup_list_lief_errors(dl)
        else:
            entry = dl
        new_lst.append(entry)
    return new_lst
