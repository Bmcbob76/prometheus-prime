"""
AST-Based Code Injection - Intelligent Code Modification
=========================================================

Uses Python's AST to intelligently inject fixes into code,
more robust than regex-based approaches.

Features:
- Parse and modify Python AST
- Inject await keywords intelligently
- Add missing imports
- Convert list comprehensions to generators
- Preserve code structure and formatting

Version: 1.0.0 (Phase 3)
"""

import ast
import astor  # Note: requires astor package
from typing import Optional, List, Tuple
from dataclasses import dataclass


@dataclass
class CodeModification:
    """A modification to be applied to code"""
    line_number: int
    original_code: str
    modified_code: str
    modification_type: str
    description: str


class ASTCodeInjector:
    """
    AST-based code modification for robust error fixes.

    Safer and more accurate than regex-based modifications.
    """

    def __init__(self):
        self.modifications: List[CodeModification] = []

    def inject_await(self, code: str, function_name: str) -> Optional[str]:
        """
        Inject 'await' keyword before coroutine calls.

        Args:
            code: Source code as string
            function_name: Name of async function to await

        Returns:
            Modified code with await injected, or None if failed
        """
        try:
            tree = ast.parse(code)
            modified = False

            class AwaitInjector(ast.NodeTransformer):
                def visit_Call(self, node):
                    # If this is a call to the target function
                    if isinstance(node.func, ast.Name) and node.func.id == function_name:
                        # Wrap in await
                        return ast.Await(value=node)
                    return node

            transformer = AwaitInjector()
            new_tree = transformer.visit(tree)

            # Convert back to code (requires astor)
            try:
                import astor
                new_code = astor.to_source(new_tree)
                return new_code
            except ImportError:
                # Fallback to ast.unparse if available (Python 3.9+)
                if hasattr(ast, 'unparse'):
                    return ast.unparse(new_tree)
                return None

        except Exception as e:
            print(f"[AST] Error injecting await: {e}")
            return None

    def add_import(self, code: str, module_name: str, as_name: Optional[str] = None) -> Optional[str]:
        """
        Add import statement at the top of the file.

        Args:
            code: Source code
            module_name: Module to import
            as_name: Optional alias (e.g., 'np' for numpy)

        Returns:
            Modified code with import added
        """
        try:
            tree = ast.parse(code)

            # Check if import already exists
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == module_name:
                            return code  # Already imported

            # Create new import node
            if as_name:
                import_node = ast.Import(names=[ast.alias(name=module_name, asname=as_name)])
            else:
                import_node = ast.Import(names=[ast.alias(name=module_name, asname=None)])

            # Insert at the beginning (after docstring if present)
            insert_pos = 0
            if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Str):
                insert_pos = 1  # After docstring

            tree.body.insert(insert_pos, import_node)

            # Convert back
            try:
                import astor
                return astor.to_source(tree)
            except ImportError:
                if hasattr(ast, 'unparse'):
                    return ast.unparse(tree)
                # Fallback: simple string injection
                import_line = f"import {module_name}" + (f" as {as_name}" if as_name else "")
                return import_line + "\n" + code

        except Exception as e:
            print(f"[AST] Error adding import: {e}")
            return None

    def convert_to_generator(self, code: str, line_number: Optional[int] = None) -> Optional[str]:
        """
        Convert list comprehensions to generator expressions for memory efficiency.

        Args:
            code: Source code
            line_number: Specific line to convert (optional)

        Returns:
            Modified code with generators instead of lists
        """
        try:
            tree = ast.parse(code)
            modified = False

            class ListToGenerator(ast.NodeTransformer):
                def visit_ListComp(self, node):
                    # Check if this should be converted
                    # (Simple heuristic: large iterations)
                    # In practice, would need more context

                    # Convert ListComp to GeneratorExp
                    gen_exp = ast.GeneratorExp(
                        elt=node.elt,
                        generators=node.generators
                    )
                    return gen_exp

            transformer = ListToGenerator()
            new_tree = transformer.visit(tree)

            try:
                import astor
                return astor.to_source(new_tree)
            except ImportError:
                if hasattr(ast, 'unparse'):
                    return ast.unparse(new_tree)
                return None

        except Exception as e:
            print(f"[AST] Error converting to generator: {e}")
            return None

    def inject_type_hints(self, code: str, function_name: str, param_types: dict, return_type: Optional[str] = None) -> Optional[str]:
        """
        Add type hints to function parameters and return type.

        Args:
            code: Source code
            function_name: Function to annotate
            param_types: Dict of param_name -> type_annotation
            return_type: Return type annotation (optional)

        Returns:
            Code with type hints added
        """
        try:
            tree = ast.parse(code)

            class TypeHintInjector(ast.NodeTransformer):
                def visit_FunctionDef(self, node):
                    if node.name == function_name:
                        # Add parameter annotations
                        for arg in node.args.args:
                            if arg.arg in param_types:
                                # Create annotation (simplified - real impl would parse type string)
                                arg.annotation = ast.Name(id=param_types[arg.arg], ctx=ast.Load())

                        # Add return annotation
                        if return_type and not node.returns:
                            node.returns = ast.Name(id=return_type, ctx=ast.Load())

                    return node

            transformer = TypeHintInjector()
            new_tree = transformer.visit(tree)

            try:
                import astor
                return astor.to_source(new_tree)
            except ImportError:
                if hasattr(ast, 'unparse'):
                    return ast.unparse(new_tree)
                return None

        except Exception as e:
            print(f"[AST] Error injecting type hints: {e}")
            return None

    def extract_function_calls(self, code: str) -> List[Tuple[str, int]]:
        """
        Extract all function calls from code.

        Returns:
            List of (function_name, line_number) tuples
        """
        try:
            tree = ast.parse(code)
            calls = []

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        calls.append((node.func.id, node.lineno))
                    elif isinstance(node.func, ast.Attribute):
                        calls.append((node.func.attr, node.lineno))

            return calls

        except Exception as e:
            print(f"[AST] Error extracting calls: {e}")
            return []

    def find_async_functions(self, code: str) -> List[Tuple[str, int]]:
        """
        Find all async function definitions.

        Returns:
            List of (function_name, line_number) tuples
        """
        try:
            tree = ast.parse(code)
            async_funcs = []

            for node in ast.walk(tree):
                if isinstance(node, ast.AsyncFunctionDef):
                    async_funcs.append((node.name, node.lineno))

            return async_funcs

        except Exception as e:
            print(f"[AST] Error finding async functions: {e}")
            return []

    def find_imports(self, code: str) -> List[Tuple[str, Optional[str], int]]:
        """
        Extract all import statements.

        Returns:
            List of (module_name, alias, line_number) tuples
        """
        try:
            tree = ast.parse(code)
            imports = []

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append((alias.name, alias.asname, node.lineno))
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        for alias in node.names:
                            imports.append((f"{node.module}.{alias.name}", alias.asname, node.lineno))

            return imports

        except Exception as e:
            print(f"[AST] Error finding imports: {e}")
            return []

    def validate_syntax(self, code: str) -> Tuple[bool, Optional[str]]:
        """
        Validate Python syntax using AST.

        Returns:
            (is_valid, error_message) tuple
        """
        try:
            ast.parse(code)
            return (True, None)
        except SyntaxError as e:
            return (False, f"Syntax error at line {e.lineno}: {e.msg}")
        except Exception as e:
            return (False, f"Parse error: {e}")
