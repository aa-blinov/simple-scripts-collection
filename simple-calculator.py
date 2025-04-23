"""Restricted eval Calculator."""

import argparse


def calculate(expression: str) -> float | None:
    """Evaluate a mathematical expression with restricted eval."""
    try:
        return eval(
            expression, {"__builtins__": None}, {}
        )  # Restrict the eval environment to only allow safe operations
    except Exception as exc:
        print(f"Error: {exc}")
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculator with restricted eval.")
    parser.add_argument(
        "expression", help="Mathematical expression to evaluate (e.g., '2 + 3 * 4')."
    )
    args = parser.parse_args()

    result = calculate(args.expression)
    if result is not None:
        print(f"Result: {result}")
