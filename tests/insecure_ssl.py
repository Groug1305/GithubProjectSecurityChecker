from src.utility import *


bad_versions = [
                "PROTOCOL_SSLv2",
                "SSLv2_METHOD",
                "SSLv23_METHOD",
                "PROTOCOL_SSLv3",
                "PROTOCOL_TLSv1",
                "SSLv3_METHOD",
                "TLSv1_METHOD",
                "PROTOCOL_TLSv1_1",
                "TLSv1_1_METHOD",
                ]


def ssl_with_bad_version(context):
    bad_ssl_versions = bad_versions
    if context['qualname'] == "ssl.wrap_socket":
        if check_call_arg_value(context, "ssl_version", bad_ssl_versions):
            report = {
                'severity': 'high',
                'confidence': 'high',
                'cwe': 'https://cwe.mitre.org/data/definitions/327.html',
                'text': "ssl.wrap_socket call with insecure SSL/TLS protocol version identified, security issue."
            }
            return report
        elif check_call_arg_value(context, "ssl_version") is None:
            report = {
                'severity': 'low',
                'confidence': 'medium',
                'cwe': 'https://cwe.mitre.org/data/definitions/327.html',
                'text': "ssl.wrap_socket call with no SSL/TLS protocol version specified, the default SSLv23 could be insecure, possible security issue."
            }
            return report
        
    elif context['qualname'] == "pyOpenSSL.SSL.Context":
        if check_call_arg_value(context, "method", bad_ssl_versions):
            report = {
                'severity': 'high',
                'confidence': 'high',
                'cwe': 'https://cwe.mitre.org/data/definitions/327.html',
                'text': "SSL.Context call with insecure SSL/TLS protocol version identified, security issue."
            }
            return report
        
    elif context['qualname'] != "ssl.wrap_socket" and context['qualname'] != "pyOpenSSL.SSL.Context":
        if check_call_arg_value(context, "method", bad_ssl_versions) or check_call_arg_value(context, "ssl_version", bad_ssl_versions):
            report = {
                'severity': 'medium',
                'confidence': 'medium',
                'cwe': 'https://cwe.mitre.org/data/definitions/327.html',
                'text': "Function call with insecure SSL/TLS protocol identified, possible security issue."
            }
            return report
        

def sslcheck(context):
    if isinstance(context['qualname'], str):
        return ssl_with_bad_version(context)