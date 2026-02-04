"""
Tests for encrypted credential storage module.
"""

import json
import pytest
import sys
import tempfile
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.credentials import (
    AWSCredentials,
    CredentialStore,
    EncryptedCredentials,
    InMemoryCredentialProvider,
)
from src.exceptions import ConfigurationError, DecryptionError


class TestAWSCredentials:
    """Tests for AWSCredentials dataclass."""

    def test_basic_credentials(self):
        """Test creating basic credentials."""
        creds = AWSCredentials(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
        assert creds.access_key_id == "AKIAIOSFODNN7EXAMPLE"
        assert creds.secret_access_key == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert creds.session_token is None
        assert creds.region is None

    def test_credentials_with_session_token(self):
        """Test credentials with session token."""
        creds = AWSCredentials(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token="FwoGZXIvYXdzEBY...",
            region="us-east-1",
        )
        assert creds.session_token == "FwoGZXIvYXdzEBY..."
        assert creds.region == "us-east-1"

    def test_to_dict(self):
        """Test conversion to dictionary."""
        creds = AWSCredentials(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region="us-west-2",
        )
        data = creds.to_dict()
        assert data["access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
        assert data["secret_access_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert data["region"] == "us-west-2"
        assert "session_token" not in data

    def test_from_dict(self):
        """Test creation from dictionary."""
        data = {
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "session_token": "token123",
            "region": "eu-west-1",
        }
        creds = AWSCredentials.from_dict(data)
        assert creds.access_key_id == "AKIAIOSFODNN7EXAMPLE"
        assert creds.session_token == "token123"
        assert creds.region == "eu-west-1"

    def test_to_boto3_config(self):
        """Test conversion to boto3 config."""
        creds = AWSCredentials(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token="token123",
        )
        config = creds.to_boto3_config()
        assert config["aws_access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
        assert config["aws_secret_access_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert config["aws_session_token"] == "token123"


class TestCredentialStore:
    """Tests for CredentialStore class."""

    @pytest.fixture
    def temp_store(self, tmp_path):
        """Create a temporary credential store."""
        return CredentialStore(tmp_path / "credentials")

    @pytest.fixture
    def sample_credentials(self):
        """Sample AWS credentials for testing."""
        return AWSCredentials(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region="us-east-1",
        )

    def test_store_creates_directory(self, tmp_path):
        """Test that credential store creates the storage directory."""
        store_path = tmp_path / "new" / "credentials"
        store = CredentialStore(store_path)
        assert store_path.exists()

    def test_store_and_load_credentials(self, temp_store, sample_credentials):
        """Test storing and loading credentials."""
        password = "my-secure-password-12"

        # Store
        path = temp_store.store_credentials(
            "account1",
            sample_credentials,
            password,
        )
        assert path.exists()

        # Load
        loaded = temp_store.load_credentials("account1", password)
        assert loaded.access_key_id == sample_credentials.access_key_id
        assert loaded.secret_access_key == sample_credentials.secret_access_key
        assert loaded.region == sample_credentials.region

    def test_store_with_metadata(self, temp_store, sample_credentials):
        """Test storing credentials with metadata."""
        password = "my-secure-password-12"
        metadata = {"environment": "production", "created_by": "test"}

        path = temp_store.store_credentials(
            "account1",
            sample_credentials,
            password,
            metadata=metadata,
        )

        # Read raw file to verify metadata is stored
        data = json.loads(path.read_text())
        assert data["metadata"]["environment"] == "production"
        assert data["metadata"]["created_by"] == "test"

    def test_wrong_password_raises_error(self, temp_store, sample_credentials):
        """Test that wrong password raises DecryptionError."""
        temp_store.store_credentials(
            "account1",
            sample_credentials,
            "correct-password-12",
        )

        with pytest.raises(DecryptionError):
            temp_store.load_credentials("account1", "wrong-password-123")

    def test_nonexistent_account_raises_error(self, temp_store):
        """Test that loading nonexistent account raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            temp_store.load_credentials("nonexistent", "any-password-12")
        assert "not found" in str(exc_info.value)

    def test_password_too_short(self, temp_store, sample_credentials):
        """Test that short password raises ConfigurationError."""
        with pytest.raises(ConfigurationError) as exc_info:
            temp_store.store_credentials("account1", sample_credentials, "short")
        assert "12 characters" in str(exc_info.value)

    def test_has_credentials(self, temp_store, sample_credentials):
        """Test checking if credentials exist."""
        assert not temp_store.has_credentials("account1")

        temp_store.store_credentials(
            "account1",
            sample_credentials,
            "my-secure-password-12",
        )

        assert temp_store.has_credentials("account1")
        assert not temp_store.has_credentials("account2")

    def test_delete_credentials(self, temp_store, sample_credentials):
        """Test deleting credentials."""
        password = "my-secure-password-12"
        temp_store.store_credentials("account1", sample_credentials, password)

        assert temp_store.has_credentials("account1")
        result = temp_store.delete_credentials("account1", secure=True)
        assert result is True
        assert not temp_store.has_credentials("account1")

    def test_delete_nonexistent_credentials(self, temp_store):
        """Test deleting nonexistent credentials returns False."""
        result = temp_store.delete_credentials("nonexistent")
        assert result is False

    def test_list_accounts(self, temp_store, sample_credentials):
        """Test listing stored account IDs."""
        password = "my-secure-password-12"

        # Initially empty
        assert temp_store.list_accounts() == []

        # Add some accounts
        temp_store.store_credentials("account1", sample_credentials, password)
        temp_store.store_credentials("account2", sample_credentials, password)
        temp_store.store_credentials("backup", sample_credentials, password)

        accounts = temp_store.list_accounts()
        assert len(accounts) == 3
        assert "account1" in accounts
        assert "account2" in accounts
        assert "backup" in accounts

    def test_account_id_sanitization(self, temp_store, sample_credentials):
        """Test that account IDs with special chars are sanitized."""
        password = "my-secure-password-12"

        # Store with special characters
        temp_store.store_credentials(
            "account/with/slashes",
            sample_credentials,
            password,
        )

        # Should be able to load it back
        loaded = temp_store.load_credentials("account/with/slashes", password)
        assert loaded.access_key_id == sample_credentials.access_key_id


class TestInMemoryCredentialProvider:
    """Tests for InMemoryCredentialProvider class."""

    @pytest.fixture
    def provider(self):
        """Create a provider instance."""
        return InMemoryCredentialProvider()

    @pytest.fixture
    def sample_credentials(self):
        """Sample AWS credentials for testing."""
        return AWSCredentials(
            access_key_id="AKIAIOSFODNN7EXAMPLE",
            secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_token="token123",
            region="us-west-2",
        )

    def test_encrypt_decrypt_roundtrip(self, provider, sample_credentials):
        """Test encrypting and decrypting credentials."""
        password = "my-secure-password"

        encrypted = provider.encrypt_credentials(sample_credentials, password)
        assert isinstance(encrypted, EncryptedCredentials)
        assert encrypted.account_id == "default"

        decrypted = provider.decrypt_credentials(encrypted, password)
        assert decrypted.access_key_id == sample_credentials.access_key_id
        assert decrypted.secret_access_key == sample_credentials.secret_access_key
        assert decrypted.session_token == sample_credentials.session_token
        assert decrypted.region == sample_credentials.region

    def test_wrong_password_fails(self, provider, sample_credentials):
        """Test that wrong password fails to decrypt."""
        encrypted = provider.encrypt_credentials(
            sample_credentials,
            "correct-password",
        )

        with pytest.raises(Exception):  # ChaCha20 will raise InvalidTag
            provider.decrypt_credentials(encrypted, "wrong-password")

    def test_base64_serialization(self, provider, sample_credentials):
        """Test serializing to and from base64."""
        password = "my-secure-password"

        encrypted = provider.encrypt_credentials(sample_credentials, password)
        base64_str = provider.to_base64(encrypted)

        # Should be a string
        assert isinstance(base64_str, str)

        # Should be able to deserialize
        restored = provider.from_base64(base64_str)
        assert restored.account_id == encrypted.account_id
        assert restored.salt == encrypted.salt
        assert restored.nonce == encrypted.nonce
        assert restored.ciphertext == encrypted.ciphertext

        # And decrypt
        decrypted = provider.decrypt_credentials(restored, password)
        assert decrypted.access_key_id == sample_credentials.access_key_id

    def test_custom_account_id(self, provider, sample_credentials):
        """Test using custom account ID."""
        encrypted = provider.encrypt_credentials(
            sample_credentials,
            "my-secure-password",
            account_id="production-aws",
        )
        assert encrypted.account_id == "production-aws"


class TestEncryptedCredentials:
    """Tests for EncryptedCredentials dataclass."""

    def test_to_dict_from_dict_roundtrip(self):
        """Test serialization roundtrip."""
        original = EncryptedCredentials(
            account_id="test-account",
            salt=b"1234567890123456",
            nonce=b"123456789012",
            ciphertext=b"encrypted-data",
            metadata={"key": "value"},
        )

        data = original.to_dict()
        restored = EncryptedCredentials.from_dict(data)

        assert restored.account_id == original.account_id
        assert restored.salt == original.salt
        assert restored.nonce == original.nonce
        assert restored.ciphertext == original.ciphertext
        assert restored.metadata == original.metadata

    def test_to_dict_includes_version(self):
        """Test that serialized dict includes version."""
        encrypted = EncryptedCredentials(
            account_id="test",
            salt=b"x" * 16,
            nonce=b"y" * 12,
            ciphertext=b"z" * 32,
        )
        data = encrypted.to_dict()
        assert data["version"] == "1.0"
