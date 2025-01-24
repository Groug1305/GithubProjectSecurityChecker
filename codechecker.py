import ast
from src.utility import *
from tests import *


def reportsys(report):
    if report != None:
        reportlist.append(report)


def visit_Call(node):
        context["call"] = node
        qualname = get_call_name(node, import_aliases)
        name = qualname.split(".")[-1]

        context["qualname"] = qualname
        context["name"] = name

        reportsys(insecure_crypto.hashlibcheck(context))

        reportsys(insecure_ssl.sslcheck(context))

        reportsys(shell_injection.shellcheck(context))

        reportsys(hardcoded_passwords.passwordcheck_call(context))

        reportsys(request_timeout.timeoutcheck(context))
        


def visit_Import(node):
        for nodename in node.names:
            if nodename.asname:
                import_aliases[nodename.asname] = nodename.name
            imports.add(nodename.name)
            context["module"] = nodename.name


def visit_ImportFrom(node):
        module = node.module
        if module is None:
            return visit_Import(node)

        for nodename in node.names:
            if nodename.asname:
                import_aliases[nodename.asname] = module + "." + nodename.name
            else:
                import_aliases[nodename.name] = module + "." + nodename.name
            imports.add(module + "." + nodename.name)
            context["module"] = module
            context["name"] = nodename.name


def visit_Constant(node):
    if isinstance(node.value, str):
        visit_Str(node)
    elif isinstance(node.value, bytes):
        visit_Bytes(node)


def visit_Str(node):
    context["str"] = node.s
    if not isinstance(node.parent, ast.Expr):
        reportsys(sql_injection.sqlcheck(context))

    reportsys(hardcoded_passwords.passwordcheck_str(context))


def visit_Bytes(node):
    return


def visit(node):
    name = node.__class__.__name__
    if name == "Call":
        visit_Call(node)
    if name == "Import":
        visit_Import(node)
    if name == "ImportFrom":
        visit_ImportFrom(node)
    if name == "Constant":
        visit_Constant(node)


def genvisit(dataparse, depth):
    for _, value in ast.iter_fields(dataparse):
        if isinstance(value, list):
            max_idx = len(value) - 1
            for idx, item in enumerate(value):
                if isinstance(item, ast.AST):
                    item.parent = dataparse
                    #print(f"Depth: {depth}, Item: {ast.dump(item)}")
                    
                    depth += 1
                    context["node"] = item
                    visit(item)
                    genvisit(item, depth)
                    depth -= 1

        elif isinstance(value, ast.AST):
            value.parent = dataparse
            #print(f"Depth: {depth}, Value: {ast.dump(value)}")
            depth += 1
            context["node"] = value
            visit(value)
            genvisit(value, depth)
            depth -= 1


imports = set()
import_aliases = {}
context = dict()
reportlist = []


def parse(data):
    dataparse = ast.parse(data)

    genvisit(dataparse, 0)

    return reportlist