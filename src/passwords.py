"""
Password configuration for multi-location storage.

This module provides flexible password management supporting:
- Same password for all storage locations
- Different passwords for each location
- Prefix + suffix pattern (common prefix with unique suffixes)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from src.exceptions import ConfigurationError

if TYPE_CHECKING:
    pass

__all__ = ["PasswordMode", "PasswordConfig", "StoragePasswords"]


class PasswordMode(Enum):
    """Password configuration mode."""

    SINGLE = "single"  # Same password for all
    SEPARATE = "separate"  # Different password for each location
    PREFIX_SUFFIX = "prefix_suffix"  # Common prefix + unique suffixes


@dataclass
class StoragePasswords:
    """
    Container for storage location passwords.

    Attributes:
        local: Password for local storage encryption.
        aws_account1: Password for AWS account 1 credential encryption.
        aws_account2: Password for AWS account 2 credential encryption.
    """

    local: str
    aws_account1: str
    aws_account2: str

    def __post_init__(self) -> None:
        """Validate passwords meet minimum requirements."""
        min_length = 12
        for name, pwd in [
            ("local", self.local),
            ("aws_account1", self.aws_account1),
            ("aws_account2", self.aws_account2),
        ]:
            if len(pwd) < min_length:
                raise ConfigurationError(
                    f"Password for '{name}' must be at least {min_length} characters"
                )

    def get_for_location(self, location: str) -> str:
        """Get password for a specific storage location."""
        mapping = {
            "local": self.local,
            "aws_account1": self.aws_account1,
            "aws_account2": self.aws_account2,
            "cloud_account1": self.aws_account1,
            "cloud_account2": self.aws_account2,
        }
        if location not in mapping:
            raise ConfigurationError(f"Unknown storage location: {location}")
        return mapping[location]


class PasswordConfig:
    """
    Flexible password configuration for multi-location storage.

    Supports three modes:
    1. SINGLE: Same password for all storage locations
    2. SEPARATE: Different password for each location
    3. PREFIX_SUFFIX: Common prefix with unique suffixes per location

    Example (single password):
        >>> config = PasswordConfig.single("my-secure-password-12chars")
        >>> passwords = config.get_passwords()

    Example (separate passwords):
        >>> config = PasswordConfig.separate(
        ...     local="local-password-12",
        ...     aws_account1="aws1-password-12",
        ...     aws_account2="aws2-password-12",
        ... )

    Example (prefix + suffix):
        >>> config = PasswordConfig.prefix_suffix(
        ...     prefix="common-prefix-",
        ...     local_suffix="local-123",
        ...     aws1_suffix="aws1-456",
        ...     aws2_suffix="aws2-789",
        ... )
    """

    def __init__(
        self,
        mode: PasswordMode,
        passwords: StoragePasswords,
    ) -> None:
        """
        Initialize password configuration.

        Use factory methods (single, separate, prefix_suffix) instead.
        """
        self.mode = mode
        self._passwords = passwords

    @classmethod
    def single(cls, password: str) -> PasswordConfig:
        """
        Create configuration with same password for all locations.

        Args:
            password: Password to use for all storage locations (min 12 chars).

        Returns:
            PasswordConfig with single password mode.
        """
        passwords = StoragePasswords(
            local=password,
            aws_account1=password,
            aws_account2=password,
        )
        return cls(PasswordMode.SINGLE, passwords)

    @classmethod
    def separate(
        cls,
        local: str,
        aws_account1: str,
        aws_account2: str,
    ) -> PasswordConfig:
        """
        Create configuration with different password for each location.

        Args:
            local: Password for local storage (min 12 chars).
            aws_account1: Password for AWS account 1 (min 12 chars).
            aws_account2: Password for AWS account 2 (min 12 chars).

        Returns:
            PasswordConfig with separate passwords mode.
        """
        passwords = StoragePasswords(
            local=local,
            aws_account1=aws_account1,
            aws_account2=aws_account2,
        )
        return cls(PasswordMode.SEPARATE, passwords)

    @classmethod
    def prefix_suffix(
        cls,
        prefix: str,
        local_suffix: str,
        aws1_suffix: str,
        aws2_suffix: str,
    ) -> PasswordConfig:
        """
        Create configuration with common prefix and unique suffixes.

        The final password is: prefix + suffix for each location.
        Useful for memorable yet unique passwords per location.

        Args:
            prefix: Common prefix for all passwords.
            local_suffix: Suffix for local storage password.
            aws1_suffix: Suffix for AWS account 1 password.
            aws2_suffix: Suffix for AWS account 2 password.

        Returns:
            PasswordConfig with prefix+suffix mode.
        """
        passwords = StoragePasswords(
            local=prefix + local_suffix,
            aws_account1=prefix + aws1_suffix,
            aws_account2=prefix + aws2_suffix,
        )
        return cls(PasswordMode.PREFIX_SUFFIX, passwords)

    def get_passwords(self) -> StoragePasswords:
        """Get the resolved passwords for all storage locations."""
        return self._passwords

    def get_password(self, location: str) -> str:
        """Get password for a specific storage location."""
        return self._passwords.get_for_location(location)
