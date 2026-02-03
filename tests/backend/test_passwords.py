"""
Tests for password configuration module.
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.passwords import PasswordConfig, PasswordMode, StoragePasswords
from src.exceptions import ConfigurationError


class TestStoragePasswords:
    """Tests for StoragePasswords dataclass."""

    def test_valid_passwords(self):
        """Test creating StoragePasswords with valid passwords."""
        passwords = StoragePasswords(
            local="local-password-12",
            aws_account1="aws1-password-12",
            aws_account2="aws2-password-12",
        )
        assert passwords.local == "local-password-12"
        assert passwords.aws_account1 == "aws1-password-12"
        assert passwords.aws_account2 == "aws2-password-12"

    def test_password_too_short_local(self):
        """Test that short local password raises error."""
        with pytest.raises(ConfigurationError) as exc_info:
            StoragePasswords(
                local="short",
                aws_account1="aws1-password-12",
                aws_account2="aws2-password-12",
            )
        assert "local" in str(exc_info.value).lower()
        assert "12 characters" in str(exc_info.value)

    def test_password_too_short_aws1(self):
        """Test that short AWS-1 password raises error."""
        with pytest.raises(ConfigurationError) as exc_info:
            StoragePasswords(
                local="local-password-12",
                aws_account1="short",
                aws_account2="aws2-password-12",
            )
        assert "aws_account1" in str(exc_info.value).lower()

    def test_password_too_short_aws2(self):
        """Test that short AWS-2 password raises error."""
        with pytest.raises(ConfigurationError) as exc_info:
            StoragePasswords(
                local="local-password-12",
                aws_account1="aws1-password-12",
                aws_account2="short",
            )
        assert "aws_account2" in str(exc_info.value).lower()

    def test_get_for_location_valid(self):
        """Test getting password by location name."""
        passwords = StoragePasswords(
            local="local-password-12",
            aws_account1="aws1-password-12",
            aws_account2="aws2-password-12",
        )
        assert passwords.get_for_location("local") == "local-password-12"
        assert passwords.get_for_location("aws_account1") == "aws1-password-12"
        assert passwords.get_for_location("aws_account2") == "aws2-password-12"
        # Aliases
        assert passwords.get_for_location("cloud_account1") == "aws1-password-12"
        assert passwords.get_for_location("cloud_account2") == "aws2-password-12"

    def test_get_for_location_invalid(self):
        """Test that invalid location raises error."""
        passwords = StoragePasswords(
            local="local-password-12",
            aws_account1="aws1-password-12",
            aws_account2="aws2-password-12",
        )
        with pytest.raises(ConfigurationError) as exc_info:
            passwords.get_for_location("unknown")
        assert "Unknown storage location" in str(exc_info.value)


class TestPasswordConfig:
    """Tests for PasswordConfig factory class."""

    def test_single_mode(self):
        """Test single password mode."""
        config = PasswordConfig.single("my-secure-password-12")
        assert config.mode == PasswordMode.SINGLE

        passwords = config.get_passwords()
        assert passwords.local == "my-secure-password-12"
        assert passwords.aws_account1 == "my-secure-password-12"
        assert passwords.aws_account2 == "my-secure-password-12"

    def test_separate_mode(self):
        """Test separate passwords mode."""
        config = PasswordConfig.separate(
            local="local-password-12",
            aws_account1="aws1-password-12",
            aws_account2="aws2-password-12",
        )
        assert config.mode == PasswordMode.SEPARATE

        passwords = config.get_passwords()
        assert passwords.local == "local-password-12"
        assert passwords.aws_account1 == "aws1-password-12"
        assert passwords.aws_account2 == "aws2-password-12"

    def test_prefix_suffix_mode(self):
        """Test prefix+suffix password mode."""
        config = PasswordConfig.prefix_suffix(
            prefix="company-2024-",
            local_suffix="local-123",
            aws1_suffix="aws1-4567",
            aws2_suffix="aws2-8901",
        )
        assert config.mode == PasswordMode.PREFIX_SUFFIX

        passwords = config.get_passwords()
        assert passwords.local == "company-2024-local-123"
        assert passwords.aws_account1 == "company-2024-aws1-4567"
        assert passwords.aws_account2 == "company-2024-aws2-8901"

    def test_get_password_method(self):
        """Test getting password for specific location."""
        config = PasswordConfig.separate(
            local="local-password-12",
            aws_account1="aws1-password-12",
            aws_account2="aws2-password-12",
        )
        assert config.get_password("local") == "local-password-12"
        assert config.get_password("aws_account1") == "aws1-password-12"
        assert config.get_password("aws_account2") == "aws2-password-12"

    def test_single_mode_short_password(self):
        """Test that single mode rejects short passwords."""
        with pytest.raises(ConfigurationError):
            PasswordConfig.single("short")

    def test_separate_mode_short_password(self):
        """Test that separate mode rejects short passwords."""
        with pytest.raises(ConfigurationError):
            PasswordConfig.separate(
                local="short",
                aws_account1="aws1-password-12",
                aws_account2="aws2-password-12",
            )

    def test_prefix_suffix_minimum_length(self):
        """Test that prefix+suffix must meet minimum length."""
        # This should work - combined is >= 12
        config = PasswordConfig.prefix_suffix(
            prefix="prefix-",
            local_suffix="local",
            aws1_suffix="aws12",
            aws2_suffix="aws34",
        )
        passwords = config.get_passwords()
        assert len(passwords.local) == 12

    def test_prefix_suffix_too_short(self):
        """Test that prefix+suffix rejects too short combinations."""
        with pytest.raises(ConfigurationError):
            PasswordConfig.prefix_suffix(
                prefix="x",
                local_suffix="y",
                aws1_suffix="z",
                aws2_suffix="w",
            )
