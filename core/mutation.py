import os

from openai import OpenAI

from core.config import settings
from core.genome import GenomeNode
from data.raw_filters import FILTER_DESCRIPTIONS
from utils.markdown_parser import parse_llm_code_blocks


class LLMMutator:
    def __init__(self, api_key: str | None = None, model: str | None = None):
        """
        Initializes the OpenAI client.
        If api_key is not provided, it attempts to load from the OPENAI_API_KEY env variable.
        """
        self.client = OpenAI(api_key=api_key or os.environ.get("OPENAI_API_KEY"))
        self.model = model or settings.llm_model

    def _build_context_string(self, genome: GenomeNode) -> str:
        """
        Flattens the GenomeNode's ancestry into a single, readable Python
        source string to feed to the LLM.
        """
        context = genome.get_full_context()
        # Create a temporary flat node for representation
        flat_node = GenomeNode(
            node_id="FLAT_VIEW",
            local_routes=context["routes"],
            local_functions=context["functions"],
            local_imports=list(context["imports"]),
        )
        return flat_node.to_python_source()

    def _build_prompt(
        self,
        context_str: str,
        target_traces: list[dict],
        compilation_error: dict | None = None,
        directive: str | None = None,
    ) -> tuple[str, str]:
        system_prompt = (
            "You are an expert cybersecurity AI architect optimizing a Python-based prompt injection firewall. "
            "Your task is to fix failing classification functions based on execution trace logs. "
            "You may add new helper functions, rewrite existing expert functions, or remap routes. "
            "Expert functions should be specialized and not try to be a 'jack of all trades'; if a function becomes too complex, split it into multiple smaller, more focused expert functions and update the routing table accordingly.\n\n"
            "**FILTER DEFINITIONS:**\n"
            "The first layer is a massive hyperscan radar which triggers categories based on keywords in 60+ languages. Avoid writing your own english-only regexes.\n"
            "Instead, your Expert functions should primarily rely on these categories for *language-agnostic* detection:\n"
            + "\n".join([f"- {k}: {v}" for k, v in FILTER_DESCRIPTIONS.items()])
            + "\n\n"
            "**EXPERT SIGNATURE:**\n"
            "Expert functions must follow this signature: `def expert_name(text, triggers, all_triggers):`\n"
            "- `text`: The local text slice around the hit.\n"
            "- `triggers`: List of detailed trigger dictionaries in this window, sorted by position. Each dict contains:\n"
            "  `{'category': str, 'rel_start': int, 'rel_end': int}`\n"
            "  Note: `rel_start` and `rel_end` are character indices relative to the provided `text` slice (0 is the start of the window).\n"
            "- `all_triggers`: Set of ALL unique category names that triggered anywhere in the entire document.\n\n"
            "**RULES:**\n"
            "- Wrap your updates in markdown code blocks (```).\n"
            "- **IMPORTANT: You MUST include all necessary Python standard library imports (e.g., `import re`, `import math`) at the top of your code block.** "
            "Only standard library modules are allowed. Do not use multi-line imports.\n"
            "- To add a new function, just use a new name for that function and write it in a markdown code block.\n"
            "- To update an existing function, reuse the same name and it will be overwritten.\n"
            "- Route updates must be formatted in a separate markdown block as `routes['trigger'] = function_name`.\n"
            "- Every code structure besides imports, route assignments, and functions will be ignored!\n"
            "- You only have a single turn. You must provide ALL your changes sequentially as markdown blocks in your response."
        )

        failures_desc = []
        for i, trace in enumerate(target_traces[: settings.max_failures_in_prompt]):
            func_name = trace.get("function", "UNKNOWN")
            raw_trigger = trace.get("trigger", "UNKNOWN")
            trigger = raw_trigger.get("category", raw_trigger) if isinstance(raw_trigger, dict) else raw_trigger
            text_slice = trace.get("text_slice", "")

            if trace.get("type") == "runtime_error":
                error_msg = trace.get("error", "")
                failures_desc.append(
                    f"FAILURE {i + 1}: Function `{func_name}` (trigger: '{trigger}') crashed: {error_msg}\nInput: \"{text_slice}\""
                )
            else:
                result = trace.get("result")
                expected = not result
                failures_desc.append(
                    f"FAILURE {i + 1}: Function `{func_name}` (trigger: '{trigger}') returned {result}, but expected {expected}.\nInput: \"{text_slice}\""
                )

        issue_desc = "\n\n".join(failures_desc)

        compilation_feedback = ""
        if compilation_error:
            compilation_feedback = (
                f"\n\n**CRITICAL: YOUR PREVIOUS ATTEMPT HAD A COMPILATION ERROR!**\n"
                f"Error: {compilation_error.get('error')}\n"
                f"Offending Code:\n```python\n{compilation_error.get('code')}\n```\n"
                "Please fix this error (e.g., add missing imports or fix syntax) in your next response."
            )

        directive_desc = ""
        if directive:
            directive_desc = f"\n**SPECIAL DIRECTIVE:**\n{directive}\n"

        user_prompt = f"""
        Here is the current state of the firewall:

        ```python
        {context_str}
        ```

        **THE FAILURES:**
        {issue_desc}
        {compilation_feedback}

        **YOUR TASK:**
        Rewrite the failing function(s) so they handle these inputs correctly.
        Ensure you include all required imports at the top of your code block.
        If necessary, you can also update other functions, write new functions, or update the routing table.
        {directive_desc}
        """
        return system_prompt, user_prompt

    def mutate_individual(
        self,
        genome: GenomeNode,
        target_traces: list[dict],
        new_node_id: str,
        compilation_error: dict | None = None,
        directive: str | None = None,
    ) -> GenomeNode | None:
        """
        Takes a list of failing traces, queries OpenAI to patch the failures, and returns
        a new child GenomeNode containing the diffs.
        """
        context_str = self._build_context_string(genome)
        system_prompt, user_prompt = self._build_prompt(context_str, target_traces, compilation_error, directive)

        try:
            # OpenAI SDK v2.26.0 Responses API
            response = self.client.responses.create(model=self.model, instructions=system_prompt, input=user_prompt)

            llm_output = response.output_text

            # Use our custom parser to extract the diffs
            new_routes, new_functions, new_imports = parse_llm_code_blocks(llm_output)

            # If the LLM failed to output any usable code, return None
            if not new_routes and not new_functions and not new_imports:
                print(f"[{new_node_id}] LLM output contained no valid code blocks.")
                return None

            # Spawn the child node
            child_node = GenomeNode(
                node_id=new_node_id,
                parent=genome,
                local_routes=new_routes,
                local_functions=new_functions,
                local_imports=new_imports,
            )

            return child_node

        except Exception as e:
            print(f"[{new_node_id}] OpenAI API Call Failed: {e}")
            return None
