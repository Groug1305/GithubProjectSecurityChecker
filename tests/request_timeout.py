from src.utility import *


def timeoutcheck(context):
    HTTP_VERBS = {"get", "options", "head", "post", "put", "patch", "delete"}
    HTTPX_ATTRS = {"request", "stream", "Client", "AsyncClient"} | HTTP_VERBS
    qualname = context['qualname'].split(".")[0]

    if qualname == "requests" and context['name'] in HTTP_VERBS:
        if check_call_arg_value(context, "timeout") is None:
            report = {
                'severity': 'medium',
                'confidence': 'low',
                'cwe': 'https://cwe.mitre.org/data/definitions/400.html',
                'text': f"Call to {qualname} without timeout"
            }
            return report
        
    if (qualname == "requests" and context['name'] in HTTP_VERBS or qualname == "httpx" and context['name'] in HTTPX_ATTRS):
        if check_call_arg_value(context, "timeout", "None"):
            report = {
                'severity': 'medium',
                'confidence': 'low',
                'cwe': 'https://cwe.mitre.org/data/definitions/400.html',
                'text': f"Call to {qualname} with timeout set to None"
            }
            return report