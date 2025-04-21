"""Simple file search utility with tree-like output, filtering by extension."""

import os
import argparse
from typing import List, Optional


def find_files(
    directory: str,
    name: str | None = None,
    allowed_extensions: List[str] |None = None,
) -> List[str]:
    """Search for files in the specified directory and its subdirectories, optionally filtering by name and allowed extensions."""
    found_files: List[str] = []
    for root, _, files in os.walk(directory):
        for filename in files:
            full_path = os.path.join(root, filename)
            if name:
                if name.lower() not in filename.lower():
                    continue
            if allowed_extensions:
                file_extension = (
                    filename.lower().split(".")[-1] if "." in filename else ""
                )
                if file_extension not in [ext.lower() for ext in allowed_extensions]:
                    continue
            found_files.append(full_path)
    return found_files


def print_tree(
    directory: str,
    found_files: List[str],
    allowed_extensions: List[str] | None = None,
    indent: str = "",
) -> None:
    """Prints the directory structure as a tree, highlighting found files that match the allowed extensions."""
    items = sorted(os.listdir(directory))
    num_items = len(items)
    for index, item in enumerate(items):
        path = os.path.join(directory, item)
        is_last = index == num_items - 1
        prefix = "└── " if is_last else "├── "
        marker = ""
        if os.path.isfile(path):
            file_extension = item.lower().split(".")[-1] if "." in item else ""
            if allowed_extensions and file_extension in [
                ext.lower() for ext in allowed_extensions
            ]:
                marker = "📄 "
            elif allowed_extensions:
                continue  # Skip files with disallowed extensions
            else:
                marker = "📄 "
        elif os.path.isdir(path):
            marker = "📁 "
        else:
            marker = "❓ "

        print(indent + prefix + marker + item)
        if os.path.isdir(path):
            new_indent = indent + ("    " if is_last else "│   ")
            print_tree(path, found_files, allowed_extensions, new_indent)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Search for files in the specified directory and display the results in a tree-like structure, optionally filtering by name and allowed extensions."
    )
    parser.add_argument("directory", help="The directory to search in")
    parser.add_argument(
        "-n",
        "--name",
        help="A substring to search for in the filename (case-insensitive)",
    )
    parser.add_argument(
        "-e",
        "--extensions",
        nargs="+",
        help="List of allowed file extensions (e.g., 'txt jpg')",
    )

    args = parser.parse_args()

    search_directory: str = args.directory
    search_name: Optional[str] = args.name
    search_extensions: Optional[List[str]] = args.extensions

    if not os.path.isdir(search_directory):
        print(f"Error: Directory '{search_directory}' not found.")
    else:
        results: List[str] = find_files(
            search_directory, name=search_name, allowed_extensions=search_extensions
        )
        print(f"Searching for files in '{search_directory}'")
        if search_name:
            print(f"  with name containing: '{search_name}'")
        if search_extensions:
            print(f"  with allowed extensions: {', '.join(search_extensions)}")

        print("\nDirectory Structure:")
        print(f"📁 {os.path.basename(search_directory)}")
        print_tree(search_directory, results, search_extensions)

        if not results:
            print("\nNo files matching the criteria were found.")
