import unittest
from utils.markdown_parser import parse_llm_code_blocks


class TestMarkdownParser(unittest.TestCase):
    def test_basic_parsing(self):
        llm_response = """
        Here is the fix:
        ```python
        import json
        routes["ignoring"] = my_expert
        ```
        ```python
        def my_expert(text, triggers):
            return "ignore" in text.lower()
        ```
        """
        routes, funcs, imports = parse_llm_code_blocks(llm_response)
        self.assertEqual(routes, {"ignoring": "my_expert"})
        self.assertIn("my_expert", funcs)
        self.assertIn("def my_expert", funcs["my_expert"])
        self.assertEqual(imports, ["import json"])

    def test_indented_blocks(self):
        # LLMs often indent the whole markdown block if they are responding in a list or blockquote
        llm_response = """
        1. Fix the expert:
            ```python
            def my_expert(text, triggers):
                return "ignore" in text.lower()
            ```
            ```python
            routes["ignoring"] = my_expert
            ```
        """
        routes, funcs, imports = parse_llm_code_blocks(llm_response)
        self.assertEqual(routes, {"ignoring": "my_expert"})
        self.assertIn("my_expert", funcs)
        # Verify it's dedented (first line should start with 'def')
        self.assertTrue(funcs["my_expert"].startswith("def my_expert"))

    def test_multiple_functions_in_one_block(self):
        llm_response = """
        ```python
        def helper(text):
            return text.strip()

        def main_expert(text, triggers):
            return helper(text) == "stop"
        ```
        """
        routes, funcs, imports = parse_llm_code_blocks(llm_response)
        self.assertIn("helper", funcs)
        self.assertIn("main_expert", funcs)

        # Verify that each function name maps to its correct definition
        self.assertIn("def helper", funcs["helper"])
        self.assertIn("return text.strip()", funcs["helper"])
        self.assertIn("def main_expert", funcs["main_expert"])
        self.assertIn('return helper(text) == "stop"', funcs["main_expert"])

        # They should NOT be equal anymore because we extract them surgically
        self.assertNotEqual(funcs["helper"], funcs["main_expert"])

    def test_multiple_routes_in_one_block(self):
        llm_response = """
        ```python
        routes["r1"] = f1
        routes["r2"] = f2
        ```
        """
        routes, funcs, imports = parse_llm_code_blocks(llm_response)
        self.assertEqual(routes, {"r1": "f1", "r2": "f2"})


if __name__ == "__main__":
    unittest.main()
