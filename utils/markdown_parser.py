import re
import ast
import textwrap
from typing import Dict, Tuple, List


def parse_llm_code_blocks(llm_response: str) -> Tuple[Dict[str, str], Dict[str, str], List[str]]:
    """
    Extracts Python code blocks from an LLM response and parses out
    route assignments, function definitions, and import statements.

    Returns:
        tuple: (new_routes_dict, new_functions_dict, new_imports_list)
    """
    new_routes = {}
    new_functions = {}
    new_imports = []

    # Extract all code blocks.
    code_blocks = re.findall(
        r"^\s*```(?:python)?\s*\n(.*?)\n\s*```", llm_response, re.DOTALL | re.IGNORECASE | re.MULTILINE
    )

    route_pattern = re.compile(r'routes\[[\'"]([^\'"]+)[\'"]\]\s*=\s*([a-zA-Z0-9_]+)')
    import_pattern = re.compile(r"^\s*(import\s+.+|from\s+.+\s+import\s+.+)", re.MULTILINE)

    for block in code_blocks:
        clean_block = textwrap.dedent(block).strip()

        # Attempt AST parsing for precise extraction
        try:
            tree = ast.parse(clean_block)
            lines = clean_block.splitlines()
            for node in tree.body:
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    start_line = node.lineno - 1
                    end_line = getattr(node, "end_lineno", node.lineno)
                    import_source = "\n".join(lines[start_line:end_line]).strip()
                    new_imports.append(import_source)
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id == "routes":
                            if isinstance(node.value, ast.Dict):
                                for key, value in zip(node.value.keys, node.value.values):
                                    k = getattr(key, "s", getattr(key, "value", None))
                                    v = getattr(value, "s", getattr(value, "value", None))
                                    if k is not None and v is not None:
                                        new_routes[k] = v
                elif isinstance(node, ast.FunctionDef):
                    func_name = node.name
                    start_line = node.lineno - 1
                    if hasattr(node, "end_lineno"):
                        end_line = node.end_lineno
                        func_source = "\n".join(lines[start_line:end_line])
                    else:
                        func_source = "\n".join(lines[start_line:])
                    new_functions[func_name] = func_source

            # Also catch individual route assignments like routes['x'] = 'y' using regex
            for line in clean_block.split("\n"):
                route_match = route_pattern.search(line)
                if route_match:
                    new_routes[route_match.group(1)] = route_match.group(2)

            continue
        except SyntaxError:
            pass

        # --- Regex Fallback ---

        # 1. Route Assignments
        for line in clean_block.split("\n"):
            route_match = route_pattern.search(line)
            if route_match:
                trigger = route_match.group(1)
                func_name = route_match.group(2)
                new_routes[trigger] = func_name

        # 2. Function Definitions
        segments = re.split(r"(?m)^(?=def\s+[a-zA-Z0-9_]+\s*\()", clean_block)

        if segments:
            header_segment = segments[0]
            # 3. Import Statements from header
            import_matches = import_pattern.findall(header_segment)
            for imp in import_matches:
                new_imports.append(imp.strip())

            # Remaining segments are the functions
            for seg in segments[1:]:
                def_match = re.search(r"def\s+([a-zA-Z0-9_]+)\s*\(", seg)
                if def_match:
                    func_name = def_match.group(1)
                    new_functions[func_name] = seg.strip()

                    inner_imports = import_pattern.findall(seg)
                    for imp in inner_imports:
                        new_imports.append(imp.strip())

    return new_routes, new_functions, list(set(new_imports))
