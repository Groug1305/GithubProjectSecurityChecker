from src.utility import *


WEAK_HASHES = ("md4", "md5", "sha", "sha1")
WEAK_CRYPT_HASHES = ("METHOD_CRYPT", "METHOD_MD5", "METHOD_BLOWFISH")


def hashlib_func(context, func):
    keywords = call_keywords(context)

    if func in WEAK_HASHES:
        if keywords.get("usedforsecurity", "True") == "True":
            report = {
                'severity': 'high',
                'confidence': 'high',
                'cwe': 'https://cwe.mitre.org/data/definitions/327.html',
                'text': f"Use of weak {func.upper()} hash for security. Consider usedforsecurity=False"
            }
            return report
    elif func == "new":
        args = call_args(context)
        name = args[0] if args else keywords.get("name", None)
        if isinstance(name, str) and name.lower() in WEAK_HASHES:
            if keywords.get("usedforsecurity", "True") == "True":
                report = {
                    'severity': 'high',
                    'confidence': 'high',
                    'cwe': 'https://cwe.mitre.org/data/definitions/327.html',
                    'text': f"Use of weak {func.upper()} hash for security. Consider usedforsecurity=False"
                }
                return report


def _crypt_crypt(context, func):
    args = call_args(context)
    keywords = call_keywords(context)

    if func == "crypt":
        name = args[1] if len(args) > 1 else keywords.get("salt", None)
        if isinstance(name, str) and name in WEAK_CRYPT_HASHES:
            report = {
                'severity': 'medium',
                'confidence': 'high',
                'cwe': 'https://cwe.mitre.org/data/definitions/327.html',
                'text': f"Use of insecure crypt.{name.upper()} hash function."
            }
            return report
    elif func == "mksalt":
        name = args[0] if args else keywords.get("method", None)
        if isinstance(name, str) and name in WEAK_CRYPT_HASHES:
            report = {
                'severity': 'medium',
                'confidence': 'high',
                'cwe': 'https://cwe.mitre.org/data/definitions/327.html',
                'text': f"Use of insecure crypt.{name.upper()} hash function."
            }
            return report


def hashlibcheck(context):
    if isinstance(context['qualname'], str):
        qualname_list = context['qualname'].split(".")
        func = qualname_list[-1]

        if "hashlib" in qualname_list:
            return hashlib_func(context, func)

        elif "crypt" in qualname_list and func in ("crypt", "mksalt"):
            return _crypt_crypt(context, func)