# SPDX-License-Identifier: Apache-2.0
# Copyright 2025-2026 The Phantex Authors

"""
Phantex — Password Validation Utilities.

Enforces password complexity requirements:
- Minimum 12 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 digit
- At least 1 special character

These rules prevent weak passwords while not being so restrictive
that users resort to writing them down.
"""

import re

# Minimum password length (C3 spec requirement)
MIN_PASSWORD_LENGTH = 12

# Common passwords to reject (top-20 most common + security-product specific)
COMMON_PASSWORDS = frozenset(
    {
        "password1234",
        "123456789012",
        "qwerty123456",
        "admin1234567",
        "changeme1234",
        "letmein12345",
        "welcome12345",
        "password1234!",
        "Password1234",
        "Password123!",
        "Passw0rd1234",
        "Phantex12345",
        "phantex12345",
    }
)

class PasswordValidationError(ValueError):
    """Raised when a password doesn't meet complexity requirements."""

    def __init__(self, violations: list[str]):
        self.violations = violations
        super().__init__(f"Password validation failed: {'; '.join(violations)}")

def validate_password_strength(password: str) -> list[str]:
    """
    Validate password complexity. Returns a list of violations (empty = valid).

    Rules:
    1. Minimum 12 characters
    2. At least 1 uppercase letter (A-Z)
    3. At least 1 lowercase letter (a-z)
    4. At least 1 digit (0-9)
    5. At least 1 special character (!@#$%^&*... etc)
    6. Not in common passwords list
    """
    violations: list[str] = []

    if len(password) < MIN_PASSWORD_LENGTH:
        violations.append(f"Must be at least {MIN_PASSWORD_LENGTH} characters (got {len(password)})")

    if not re.search(r"[A-Z]", password):
        violations.append("Must contain at least 1 uppercase letter")

    if not re.search(r"[a-z]", password):
        violations.append("Must contain at least 1 lowercase letter")

    if not re.search(r"\d", password):
        violations.append("Must contain at least 1 digit")

    if not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:'\",.<>?/`~\\]", password):
        violations.append("Must contain at least 1 special character")

    if password.lower() in COMMON_PASSWORDS:
        violations.append("This password is too common")

    return violations

def assert_password_strength(password: str) -> None:
    """Validate password and raise PasswordValidationError if invalid."""
    violations = validate_password_strength(password)
    if violations:
        raise PasswordValidationError(violations)
