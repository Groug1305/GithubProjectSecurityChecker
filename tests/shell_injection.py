from src.utility import *
import re


full_path_match = re.compile(r"^(?:[A-Za-z](?=\:)|[\\\/\.])")


config = {
    "subprocess": [
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.run",
    ],
    "shell": [
        "os.system",
        "os.popen",
        "os.popen2",
        "os.popen3",
        "os.popen4",
        "popen2.popen2",
        "popen2.popen3",
        "popen2.popen4",
        "popen2.Popen3",
        "popen2.Popen4",
        "commands.getoutput",
        "commands.getstatusoutput",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    ],
    "no_shell": [
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
        "os.startfile",
    ]
}


def has_shell(context):
    keywords = context['node'].keywords
    result = False
    if "shell" in call_keywords(context):
        for key in keywords:
            if key.arg == "shell":
                val = key.value
                if isinstance(val, ast.Num):
                    result = bool(val.n)
                elif isinstance(val, ast.List):
                    result = bool(val.elts)
                elif isinstance(val, ast.Dict):
                    result = bool(val.keys)
                elif isinstance(val, ast.Name) and val.id in ["False", "None"]:
                    result = False
                elif isinstance(val, ast.NameConstant):
                    result = val.value
                else:
                    result = True
    return result


def shellcheck(context):
    if context['qualname'] in config["subprocess"]:
        if has_shell(context):
            if len(call_args(context)) > 0:
                no_formatting = isinstance(context['node'].args[0], ast.Str)
                if no_formatting: 
                    report = {
                        'severity': 'low',
                        'confidence': 'high',
                        'cwe': 'https://cwe.mitre.org/data/definitions/78.html',
                        'text': "subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell"
                    }
                    return report
                else:
                    report = {
                        'severity': 'high',
                        'confidence': 'high',
                        'cwe': 'https://cwe.mitre.org/data/definitions/78.html',
                        'text': "subprocess call with shell=True identified, security issue."
                    }
                    return report
        else:
            report = {
                'severity': 'low',
                'confidence': 'high',
                'cwe': 'https://cwe.mitre.org/data/definitions/78.html',
                'text': "subprocess call - check for execution of untrusted input."
            }
            return report
    
    elif context['qualname'] not in config["subprocess"]:
        if has_shell(context):
            report = {
                'severity': 'medium',
                'confidence': 'low',
                'cwe': 'https://cwe.mitre.org/data/definitions/78.html',
                'text': "Function call with shell=True parameter identified, possible security issue."
            }
            return report

    elif context['qualname'] in config["shell"]:
        if len(call_args(context)) > 0:
            no_formatting = isinstance(context['node'].args[0], ast.Str)
            if no_formatting: 
                    report = {
                        'severity': 'low',
                        'confidence': 'high',
                        'cwe': 'https://cwe.mitre.org/data/definitions/78.html',
                        'text': "Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell"
                    }
                    return report
            else:
                report = {
                    'severity': 'high',
                    'confidence': 'high',
                    'cwe': 'https://cwe.mitre.org/data/definitions/78.html',
                    'text': "Starting a process with a shell, possible injection detected, security issue."
                }
                return report
            
    elif context['qualname'] in config["no_shell"]:
        report = {
            'severity': 'low',
            'confidence': 'medium',
            'cwe': 'https://cwe.mitre.org/data/definitions/78.html',
            'text': "Starting a process without a shell."
        }
        return report
    
    elif len(call_args(context)):
        if context['qualname'] in config["subprocess"] or context['qualname'] in config["shell"] or context['qualname'] in config["no_shell"]:
            node = context['node'].args[0]
            if isinstance(node, ast.List) and node.elts:
                node = node.elts[0]

            if isinstance(node, ast.Str) and not full_path_match.match(node.s):
                report = {
                    'severity': 'low',
                    'confidence': 'high',
                    'cwe': 'https://cwe.mitre.org/data/definitions/78.html',
                    'text': "Starting a process with a partial executable path"
                }
                return report