"""Secure Random Password Generator."""

import string
import secrets
import argparse


def generate_password(length: int = 12) -> str:
    """Generate a secure random password with guaranteed inclusion of different character types."""
    if length < 8:
        raise ValueError(
            "Password length must be at least 8 characters to include all required character types."
        )

    uppercase_letters = string.ascii_uppercase
    lowercase_letters = string.ascii_lowercase
    digits = string.digits
    punctuation = "!@#$%^&*()-_=+[]{}|;:,.<>?/"  # Exclude ambiguous characters like space or quotes

    all_characters = uppercase_letters + lowercase_letters + digits + punctuation
    password = []
    password += [secrets.choice(all_characters) for _ in range(length)]

    secrets.SystemRandom().shuffle(password)

    return "".join(password)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a secure random password.")
    parser.add_argument(
        "-l",
        "--length",
        type=int,
        default=16,
        help="Length of the password (default: 16). Must be at least 8.",
    )
    args = parser.parse_args()

    try:
        password = generate_password(args.length)
        print(f"Generated password:\n{password}")
    except ValueError as exc:
        print(f"Error: {exc}")
