from src.utility import *
import re


RE_WORDS = "(pas+wo?r?d|pass(phrase)?|pwd|token|secrete?)"
RE_CANDIDATES = re.compile(
    "(^{0}$|_{0}_|^{0}_|_{0}$)".format(RE_WORDS), re.IGNORECASE
)


def report(value):
    report = {
        'severity': 'low',
        'confidence': 'medium',
        'cwe': 'https://cwe.mitre.org/data/definitions/259.html',
        'text': f"Possible hardcoded password: '{value}'"
    }
    return report


def passwordcheck_str(context):
    node = context['node']
    if isinstance(node.parent, ast.Assign):
        # looks for "candidate='some_string'"
        for targ in node.parent.targets:
            if isinstance(targ, ast.Name) and RE_CANDIDATES.search(targ.id):
                return report(node.s)
            elif isinstance(targ, ast.Attribute) and RE_CANDIDATES.search(targ.attr):
                return report(node.s)

    elif isinstance(node.parent, ast.Subscript) and RE_CANDIDATES.search(node.s):
        # Py39+: looks for "dict[candidate]='some_string'"
        # subscript -> index -> string
        assign = node.parent.parent
        if isinstance(assign, ast.Assign) and isinstance(assign.value, ast.Str):
            return report(assign.value.s)

    elif isinstance(node.parent, ast.Index) and RE_CANDIDATES.search(node.s):
        # looks for "dict[candidate]='some_string'"
        # assign -> subscript -> index -> string
        assign = node.parent.parent.parent
        if isinstance(assign, ast.Assign) and isinstance(
            assign.value, ast.Str
        ):
            return report(assign.value.s)

    elif isinstance(node.parent, ast.Compare):
        # looks for "candidate == 'some_string'"
        comp = node.parent
        if isinstance(comp.left, ast.Name):
            if RE_CANDIDATES.search(comp.left.id):
                if isinstance(comp.comparators[0], ast.Str):
                    return report(comp.comparators[0].s)
        elif isinstance(comp.left, ast.Attribute):
            if RE_CANDIDATES.search(comp.left.attr):
                if isinstance(comp.comparators[0], ast.Str):
                    return report(comp.comparators[0].s)
                

def passwordcheck_call(context):
    for keyword in context['node'].keywords:
        if isinstance(keyword.value, ast.Str) and RE_CANDIDATES.search(keyword.arg):
            return report(keyword.value.s)