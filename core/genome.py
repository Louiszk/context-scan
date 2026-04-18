import re
import math
import ast
import textwrap
from typing import Dict, List, Any, Optional

class GenomeNode:
    def __init__(self, node_id: str, parent: Optional['GenomeNode'] = None, 
                 local_routes: dict = None, local_functions: dict = None, local_imports: list = None):
        """
        Initializes a node in the evolutionary tree. 
        It only stores the diffs (local_routes, local_functions, local_imports) from its parent.
        """
        self.node_id = node_id
        self.parent = parent
        
        self.local_routes = local_routes or {}
        self.local_functions = local_functions or {}
        self.local_imports = local_imports or []
        
        self.trace_log = []
        
        # Build the execution namespace
        if self.parent:
            self.namespace = self.parent.namespace.copy()
        else:
            self.namespace = {}
            
        self._compile_local_functions()

    def __getstate__(self):
        state = self.__dict__.copy()
        if 'namespace' in state:
            del state['namespace']
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        # Re-build the namespace upon unpickling
        if self.parent:
            self.namespace = self.parent.namespace.copy()
        else:
            self.namespace = {}
        self._compile_local_functions()

    def _compile_local_functions(self):
        """Compiles locally mutated/added functions and imports into the namespace."""
        # 1. Resolve Imports
        for import_stmt in self.local_imports:
            try:
                exec(import_stmt, self.namespace)
            except Exception as e:
                self.trace_log.append({
                    "type": "compilation_error",
                    "trigger": "import",
                    "error": f"Import failed: {import_stmt} -> {str(e)}",
                    "code": import_stmt
                })
                return

        # 2. Compile Functions
        for func_name, func_code in self.local_functions.items():
            try:
                # exec compiles the string and assigns the function to self.namespace[func_name]
                exec(func_code, self.namespace)
            except Exception as e:
                self.trace_log.append({
                    "type": "compilation_error",
                    "function": func_name,
                    "error": str(e),
                    "code": func_code
                })

    def get_route(self, trigger: str) -> str:
        """Recursively resolves a route mapping."""
        if trigger in self.local_routes:
            return self.local_routes[trigger]
        if self.parent:
            return self.parent.get_route(trigger)
        return None

    def get_full_context(self) -> dict:
        """
        Flattens the entire tree up to the root to generate a complete 
        view of routes, functions, and imports. Used to generate the LLM prompt context.
        """
        if self.parent:
            context = self.parent.get_full_context()
        else:
            context = {"routes": {}, "functions": {}, "imports": set()}
            
        # Overwrite parent context with local mutations
        context["routes"].update(self.local_routes)
        context["functions"].update(self.local_functions)
        context["imports"].update(self.local_imports)
        return context

    def clear_traces(self):
        self.trace_log = []

    def evaluate_window(self, window: dict, all_triggers: set) -> bool:
        """Routes the window to the appropriate expert function."""
        text_slice = window.get("text_slice", "")
        triggers = window.get("triggers", [])

        for trigger in triggers:
            trigger_category = trigger.get("category", "")
            func_name = self.get_route(trigger_category)
            
            if func_name and func_name in self.namespace:
                expert_func = self.namespace[func_name]
                try:
                    # Expert functions now receive (text, local_triggers, all_triggers)
                    result = expert_func(text_slice, triggers, all_triggers)
                    self.trace_log.append({
                        "type": "execution",
                        "trigger": trigger,
                        "function": func_name,
                        "text_slice": text_slice,
                        "result": bool(result),
                        "all_triggers": list(all_triggers)
                    })
                    if result:
                        return True
                except Exception as e:
                    self.trace_log.append({
                        "type": "runtime_error",
                        "trigger": trigger,
                        "function": func_name,
                        "text_slice": text_slice,
                        "error": str(e)
                    })
                    
        return False

    def process_document(self, radar_result: dict) -> bool:
        """Processes all windows using the global trigger context."""
        windows = radar_result.get("windows", [])
        all_triggers = radar_result.get("all_triggers", set())
        
        for window in windows:
            if self.evaluate_window(window, all_triggers):
                return True
        return False

    def to_python_source(self) -> str:
        """
        Converts the local routes, functions, and imports of this GenomeNode into a 
        Python source string.
        """
        source_parts = []
        
        if self.local_imports:
            source_parts.append("# --- Imports ---")
            for imp in sorted(self.local_imports):
                source_parts.append(imp)
            source_parts.append("")

        if self.local_routes:
            source_parts.append("# --- Routes ---")
            source_parts.append("routes = {")
            for trigger, func_name in sorted(self.local_routes.items()):
                source_parts.append(f"    '{trigger}': '{func_name}',")
            source_parts.append("}\n")
            
        if self.local_functions:
            source_parts.append("# --- Expert Functions ---")
            for func_name, func_code in sorted(self.local_functions.items()):
                source_parts.append(func_code.strip() + "\n")
                
        return "\n".join(source_parts)

    @classmethod
    def from_python_source(cls, source_code: str, node_id: str, parent: Optional['GenomeNode'] = None) -> 'GenomeNode':
        """
        Parses a Python source string to create a GenomeNode.
        Expects a 'routes' dictionary, function definitions, and optional imports.
        """
        local_routes = {}
        local_functions = {}
        local_imports = []
        
        tree = ast.parse(source_code)
        
        # Split source into lines for extracting function source
        lines = source_code.splitlines()
        
        for node in tree.body:
            # Look for imports
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                start_line = node.lineno - 1
                end_line = getattr(node, 'end_lineno', node.lineno)
                import_source = "\n".join(lines[start_line:end_line]).strip()
                local_imports.append(import_source)

            # Look for routes = { ... }
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == 'routes':
                        if isinstance(node.value, ast.Dict):
                            for key, value in zip(node.value.keys, node.value.values):
                                if isinstance(key, (ast.Str, ast.Constant)) and isinstance(value, (ast.Str, ast.Constant)):
                                    # Handle both older ast.Str and newer ast.Constant
                                    k = key.s if hasattr(key, 's') else key.value
                                    v = value.s if hasattr(value, 's') else value.value
                                    local_routes[k] = v
            
            # Look for function definitions
            elif isinstance(node, ast.FunctionDef):
                func_name = node.name
                # Extract original source code for the function
                start_line = node.lineno - 1
                if hasattr(node, 'end_lineno'):
                    end_line = node.end_lineno
                    func_source = "\n".join(lines[start_line:end_line])
                else:
                    func_source = "\n".join(lines[start_line:])

                local_functions[func_name] = func_source

        return cls(node_id=node_id, parent=parent, 
                   local_routes=local_routes, local_functions=local_functions, local_imports=local_imports)
