import os
import argparse
import string
import re
import sys
from typing import Dict, List, Optional, Tuple


def is_binary_file(file_path: str) -> bool:
    """
    Determines if a file is binary using multiple checks.
    More reliable than just checking for null bytes.
    """
    try:
        # Check file extension first
        binary_extensions = {
            # Common document formats
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".ppt",
            ".pptx",
            # Image formats
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".bmp",
            ".tiff",
            ".tif",
            ".webp",
            ".svg",
            ".ico",
            # Audio/Video formats
            ".mp3",
            ".mp4",
            ".wav",
            ".flac",
            ".ogg",
            ".avi",
            ".mkv",
            ".mov",
            ".wmv",
            ".flv",
            # Archive and compressed formats
            ".zip",
            ".tar",
            ".gz",
            ".rar",
            ".7z",
            ".bz2",
            ".xz",
            ".cab",
            # Executable and binary formats
            ".exe",
            ".dll",
            ".so",
            ".dylib",
            ".bin",
            ".dat",
            ".pyc",
            ".pyd",
            ".pyo",
            # Database and data formats
            ".db",
            ".sqlite",
            ".mdb",
            ".accdb",
            ".dbf",
            ".sav",
            ".pkl",
            # Font formats
            ".ttf",
            ".otf",
            ".woff",
            ".woff2",
            ".eot",
            # System and disk image formats
            ".iso",
            ".img",
            ".dmg",
            ".vhd",
            ".vmdk",
            # Other binary formats
            ".jar",
            ".class",
            ".o",
            ".obj",
            ".lib",
            ".a",
            ".deb",
            ".rpm",
        }
        _, ext = os.path.splitext(file_path.lower())
        if ext in binary_extensions:
            return True

        # Read a chunk and look for binary indicators
        with open(file_path, "rb") as f:
            chunk = f.read(8192)  # Read a larger chunk

        # Check for null bytes (common in binary files)
        if b"\x00" in chunk:
            return True

        # Check the ratio of text characters to binary characters in the file
        # Count the number of "text" characters:
        # - ASCII characters with codes 32-127 (letters, digits, punctuation)
        # - Control characters: tab (9), newline (10), carriage return (13)
        text_chars = len([b for b in chunk if 32 <= b <= 127 or b in (9, 10, 13)])

        # Calculate the proportion of text characters to total bytes
        # If less than 70% of characters are text characters, consider the file binary
        if len(chunk) > 0 and float(text_chars) / float(len(chunk)) < 0.7:
            return True

        return False
    except Exception:
        return True  # Be safe and assume binary if there's an error


def try_encodings(file_path: str) -> Tuple[str, str]:
    """
    Try different encodings to read the file.
    Returns a tuple of (content, encoding_used)
    """
    # Common encodings to try in order of likelihood
    encodings = ["utf-8", "latin-1", "cp1252", "iso-8859-1", "ascii"]

    for encoding in encodings:
        try:
            with open(file_path, "r", encoding=encoding) as f:
                content = f.read()
            return content, encoding
        except UnicodeDecodeError:
            continue

    # If all encodings fail, use latin-1 as a fallback which can read any byte stream
    try:
        with open(file_path, "r", encoding="latin-1", errors="replace") as f:
            content = f.read()
        return content, "latin-1 (fallback)"
    except Exception as e:
        return "", f"Error: {e}"


def count_word_frequency(file_paths: list[str]) -> dict[str, int]:
    """Counts the frequency of words in one or more text files or directories."""
    word_counts: Dict[str, int] = {}
    processed_files = 0
    skipped_files = 0
    encoding_stats: Dict[str, int] = {}
    processed_file_paths = []  # Track processed files to display later

    # Print files being processed if there are 20 or fewer
    if len(file_paths) <= 20:
        print(f"\nProcessing {len(file_paths)} files:")
    else:
        print(f"\nProcessing {len(file_paths)} files... (too many to list)")

    for path in file_paths:
        if os.path.isfile(path):
            if is_binary_file(path):
                print(
                    f"Warning: File '{path}' appears to be binary and will be skipped."
                )
                skipped_files += 1
                continue
            files_to_process = [path]
        elif os.path.isdir(path):
            files_to_process = []
            for f in os.listdir(path):
                full_path = os.path.join(path, f)
                if os.path.isfile(full_path) and not is_binary_file(full_path):
                    files_to_process.append(full_path)

            if not files_to_process:
                print(f"Warning: Directory '{path}' contains no supported text files.")
                continue
        else:
            print(
                f"Warning: Path '{path}' is neither a file nor a directory and will be skipped."
            )
            continue

        for file_path in files_to_process:
            try:
                # If we're displaying files (<=20), show processing status
                if len(file_paths) <= 20:
                    print(f"  - Processing: {file_path}")

                text, encoding = try_encodings(file_path)
                if not text:
                    print(
                        f"Error: Could not read file '{file_path}' with any supported encoding."
                    )
                    skipped_files += 1
                    continue

                # Track which encoding was used
                encoding_stats[encoding] = encoding_stats.get(encoding, 0) + 1
                processed_files += 1
                processed_file_paths.append(file_path)  # Add to processed files list

            except FileNotFoundError as exc:
                print(f"Error: File not found at '{file_path}': {exc}")
                skipped_files += 1
                continue
            except IOError as exc:
                print(
                    f"Error: An error occurred while reading file '{file_path}': {exc}"
                )
                skipped_files += 1
                continue

            # Remove punctuation and convert to lowercase for consistent counting
            text = text.translate(str.maketrans("", "", string.punctuation)).lower()

            # Split the text into words using a robust regular expression
            # This matches Unicode word characters to support multiple languages
            words = re.findall(r"\b\w+\b", text, re.UNICODE)

            for word in words:
                word_counts[word] = word_counts.get(word, 0) + 1  # Increment the count

    print(f"\nProcessed {processed_files} files. Skipped {skipped_files} files.")

    # Display the actual processed files if there were 20 or fewer
    if 0 < len(processed_file_paths) <= 20:
        print("\nSuccessfully processed files:")
        for i, file_path in enumerate(processed_file_paths, 1):
            print(f"  {i}. {file_path}")

    # Print encoding statistics
    if encoding_stats:
        print("\nFile encodings detected:")
        for encoding, count in encoding_stats.items():
            print(f"  - {encoding}: {count} files")

    return word_counts


def print_word_frequency(
    word_counts: Dict[str, int], top_n: Optional[int] = 10
) -> None:
    """Prints the word frequencies, sorted in descending order of frequency."""
    if not word_counts:
        print("No words were found in the processed files.")
        return

    # Sort the words by frequency in descending order
    sorted_words = sorted(word_counts.items(), key=lambda item: (-item[1], item[0]))

    total_words = sum(word_counts.values())
    unique_words = len(word_counts)

    print(f"\nTotal words: {total_words}")
    print(f"Unique words: {unique_words}")

    if top_n:
        print(f"\nTop {min(top_n, len(sorted_words))} most frequent words:")
        for i, (word, count) in enumerate(sorted_words[:top_n], 1):
            percentage = (count / total_words) * 100
            print(f"{i}. {word}: {count} ({percentage:.2f}%)")
    else:
        print("\nAll words and their frequencies:")
        for i, (word, count) in enumerate(sorted_words, 1):
            percentage = (count / total_words) * 100
            print(f"{i}. {word}: {count} ({percentage:.2f}%)")


def validate_paths(file_paths: List[str]) -> Tuple[List[str], bool]:
    """Validates if the provided paths exist and are accessible."""
    valid_paths = []
    has_errors = False

    for path in file_paths:
        if not os.path.exists(path):
            print(f"Error: Path '{path}' does not exist.")
            has_errors = True
        elif not os.access(path, os.R_OK):
            print(f"Error: No read permission for '{path}'.")
            has_errors = True
        else:
            valid_paths.append(path)

    return valid_paths, has_errors


def main() -> None:
    """Main function to parse command line arguments and execute the word frequency counter."""
    parser = argparse.ArgumentParser(
        description="Counts the frequency of words in text files and directories.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-d",
        "--directory",
        type=str,
        help="Path to a directory containing text files to process.",
    )
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        help="Path to a single text file to process.",
    )
    parser.add_argument(
        "-n",
        "--top_n",
        type=int,
        metavar="N",
        default=10,
        help="An optional integer specifying the number of top-N most frequent words to display (default: 10).",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Display all words instead of just the top N.",
    )
    parser.add_argument(
        "--recursive", action="store_true", help="Process directories recursively."
    )
    parser.add_argument(
        "--exclude",
        type=str,
        nargs="+",
        help="File extensions to exclude (e.g., --exclude .log .tmp)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Display all processed files regardless of how many there are.",
    )

    args = parser.parse_args()

    if args.directory and args.file:
        print(
            "Error: Both --directory and --file cannot be specified. Use one or the other.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not args.directory and not args.file:
        print("Error: Either --directory or --file must be specified.", file=sys.stderr)
        sys.exit(1)

    # Convert exclude extensions to a set for O(1) lookup
    exclude_extensions = set()
    if args.exclude:
        exclude_extensions = {
            ext.lower() if ext.startswith(".") else f".{ext.lower()}"
            for ext in args.exclude
        }

    file_paths: List[str] = []
    if args.directory:
        if not os.path.isdir(args.directory):
            print("Error: --directory path is not a valid directory", file=sys.stderr)
            sys.exit(1)

        if args.recursive:
            # Walk through directory recursively
            for root, _, files in os.walk(args.directory):
                for f in files:
                    file_path = os.path.join(root, f)
                    _, ext = os.path.splitext(file_path.lower())
                    if ext not in exclude_extensions:
                        file_paths.append(file_path)
        else:
            # Just get files from the top directory
            for f in os.listdir(args.directory):
                file_path = os.path.join(args.directory, f)
                if os.path.isfile(file_path):
                    _, ext = os.path.splitext(file_path.lower())
                    if ext not in exclude_extensions:
                        file_paths.append(file_path)
    elif args.file:
        if not os.path.isfile(args.file):
            print("Error: --file path is not a valid file", file=sys.stderr)
            sys.exit(1)
        file_paths = [args.file]

    # Validate paths before processing
    valid_paths, has_errors = validate_paths(file_paths)
    if has_errors and not valid_paths:
        print("Error: No valid paths to process.", file=sys.stderr)
        sys.exit(1)

    print("Starting word frequency analysis...")
    word_counts = count_word_frequency(valid_paths)

    if args.all:
        print_word_frequency(word_counts, None)  # Show all words
    else:
        print_word_frequency(word_counts, args.top_n)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)
