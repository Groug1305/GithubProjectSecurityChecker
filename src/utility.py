import ast


def get_attr_qual_name(node, aliases):
    if isinstance(node, ast.Name):
        if node.id in aliases:
            return aliases[node.id]
        return node.id
    elif isinstance(node, ast.Attribute):
        name = f"{get_attr_qual_name(node.value, aliases)}.{node.attr}"
        if name in aliases:
            return aliases[name]
        return name
    else:
        return ""


def get_call_name(node, aliases):
    if isinstance(node.func, ast.Name):
        if deep_get_attr(node, "func.id") in aliases:
            return aliases[deep_get_attr(node, "func.id")]
        return deep_get_attr(node, "func.id")
    elif isinstance(node.func, ast.Attribute):
        return get_attr_qual_name(node.func, aliases)
    else:
        return ""


def deep_get_attr(obj, attr):
    for key in attr.split("."):
        obj = getattr(obj, key)
    return obj


def call_keywords(context):
        if "call" in context and hasattr(
            context["call"], "keywords"
        ):
            return_dict = {}
            for li in context["call"].keywords:
                if hasattr(li.value, "attr"):
                    return_dict[li.arg] = li.value.attr
                else:
                    return_dict[li.arg] = get_literal_value(li.value)
            return return_dict
        else:
            return None
        

def call_args(context):
        args = []
        if "call" in context and hasattr(context["call"], "args"):
            for arg in context["call"].args:
                if hasattr(arg, "attr"):
                    args.append(arg.attr)
                else:
                    args.append(get_literal_value(arg))
        return args
        

def get_literal_value(literal):
        if isinstance(literal, ast.Num):
            literal_value = literal.n

        elif isinstance(literal, ast.Str):
            literal_value = literal.s

        elif isinstance(literal, ast.List):
            return_list = list()
            for li in literal.elts:
                return_list.append(get_literal_value(li))
            literal_value = return_list

        elif isinstance(literal, ast.Tuple):
            return_tuple = tuple()
            for ti in literal.elts:
                return_tuple += (get_literal_value(ti),)
            literal_value = return_tuple

        elif isinstance(literal, ast.Set):
            return_set = set()
            for si in literal.elts:
                return_set.add(get_literal_value(si))
            literal_value = return_set

        elif isinstance(literal, ast.Dict):
            literal_value = dict(zip(literal.keys, literal.values))

        elif isinstance(literal, ast.Ellipsis):
            # what do we want to do with this?
            literal_value = None

        elif isinstance(literal, ast.Name):
            literal_value = literal.id

        elif isinstance(literal, ast.NameConstant):
            literal_value = str(literal.value)

        elif isinstance(literal, ast.Bytes):
            literal_value = literal.s

        else:
            literal_value = None

        return literal_value


def call_args(context):
        args = []
        if "call" in context and hasattr(context["call"], "args"):
            for arg in context["call"].args:
                if hasattr(arg, "attr"):
                    args.append(arg.attr)
                else:
                    args.append(get_literal_value(arg))
        return args


def get_call_arg_value(context, argument_name):
        kwd_values = call_keywords(context)
        if kwd_values is not None and argument_name in kwd_values:
            return kwd_values[argument_name]


def check_call_arg_value(context, argument_name, argument_values=None):
    arg_value = get_call_arg_value(context, argument_name)
    if arg_value is not None:
        if not isinstance(argument_values, list):
            argument_values = list((argument_values,))
        for val in argument_values:
            if arg_value == val:
                return True
        return False
    else:
        return None
    

def concat_string(node, stop=None):

    def _get(node, bits, stop=None):
        if node != stop:
            bits.append(
                _get(node.left, bits, stop)
                if isinstance(node.left, ast.BinOp)
                else node.left
            )
            bits.append(
                _get(node.right, bits, stop)
                if isinstance(node.right, ast.BinOp)
                else node.right
            )

    bits = [node]
    while isinstance(node.parent, ast.BinOp):
        node = node.parent
    if isinstance(node, ast.BinOp):
        _get(node, bits, stop)
    return (node, " ".join([x.s for x in bits if isinstance(x, ast.Str)]))


def get_called_name(node):
    func = node.func
    try:
        return func.attr if isinstance(func, ast.Attribute) else func.id
    except AttributeError:
        return ""


def get_code(data, linenum):

    count = 0
    realcount = 0
    code = ''

    linelist = data.iter_lines(decode_unicode=True)

    for line in linelist:
        print(f"{count}\t{line}")
        if realcount == (linenum - 1) and linenum > 0:
            code += f"{count+1}\t{line}\n"
        if realcount == linenum:
            code += f"{count+1}\t{line}\n"
        if realcount == (linenum + 1):
            code += f"{count+1}\t{line}\n"

        if line and line[0] != '#':
            realcount += 1
        count += 1

    return code
