from src.utility import *
import re


SIMPLE_SQL_RE = re.compile(
    r"(select\s.*from\s|"
    r"delete\s+from\s|"
    r"insert\s+into\s.*values\s|"
    r"update\s.*set\s)",
    re.IGNORECASE | re.DOTALL,
)


def check_string(data):
    return SIMPLE_SQL_RE.search(data) is not None


def evaluate_ast(node):
    wrapper = None
    statement = ""
    str_replace = False

    if isinstance(node.parent, ast.BinOp):
        out = concat_string(node, node.parent)
        wrapper = out[0].parent
        statement = out[1]

    elif isinstance(node.parent, ast.Attribute) and node.parent.attr in ("format", "replace"):
        statement = node.s
        # Hierarchy for "".format() is Wrapper -> Call -> Attribute -> Str
        wrapper = node.parent.parent.parent
        if node.parent.attr == "replace":
            str_replace = True

    elif hasattr(ast, "JoinedStr") and isinstance(node.parent, ast.JoinedStr):
        substrings = [
            child
            for child in node.parent.values
            if isinstance(child, ast.Str)
        ]
        # JoinedStr consists of list of Constant and FormattedValue
        # instances. Let's perform one test for the whole string
        # and abandon all parts except the first one to raise one
        # failed test instead of many for the same SQL statement.
        if substrings and node == substrings[0]:
            statement = "".join([str(child.s) for child in substrings])
            wrapper = node.parent.parent

    if isinstance(wrapper, ast.Call):  # wrapped in "execute" call?
        names = ["execute", "executemany"]
        name = get_called_name(wrapper)
        return (name in names, statement, str_replace)
    else:
        return (False, statement, str_replace)


def sqlcheck(context):
    execute_call, statement, str_replace = evaluate_ast(context['node'])
    if check_string(statement):
        if execute_call and not str_replace:
            confidence = 'medium'
        else: confidence = 'low'

        report = {
                'severity': 'medium',
                'confidence': confidence,
                'cwe': 'https://cwe.mitre.org/data/definitions/89.html',
                'text': "Possible SQL injection vector through string-based query construction."
            }
        return report