"""
Encrypted credential storage for AWS credentials.

This module provides secure storage and retrieval of AWS credentials,
encrypted with user-provided passwords using ChaCha20-Poly1305.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.exceptions import ConfigurationError, DecryptionError

if TYPE_CHECKING:
    from typing import Any

__all__ = ["AWSCredentials", "CredentialStore", "EncryptedCredentials"]

logger = logging.getLogger(__name__)


@dataclass
class AWSCredentials:
    """
    AWS credentials container.

    Attributes:
        access_key_id: AWS access key ID.
        secret_access_key: AWS secret access key.
        session_token: Optional session token for temporary credentials.
        region: AWS region (optional, for convenience).
    """

    access_key_id: str
    secret_access_key: str
    session_token: str | None = None
    region: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = {
            "access_key_id": self.access_key_id,
            "secret_access_key": self.secret_access_key,
        }
        if self.session_token:
            data["session_token"] = self.session_token
        if self.region:
            data["region"] = self.region
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AWSCredentials:
        """Create from dictionary."""
        return cls(
            access_key_id=data["access_key_id"],
            secret_access_key=data["secret_access_key"],
            session_token=data.get("session_token"),
            region=data.get("region"),
        )

    def to_boto3_config(self) -> dict[str, str]:
        """Convert to boto3 client configuration."""
        config: dict[str, str] = {
            "aws_access_key_id": self.access_key_id,
            "aws_secret_access_key": self.secret_access_key,
        }
        if self.session_token:
            config["aws_session_token"] = self.session_token
        return config


@dataclass
class EncryptedCredentials:
    """
    Encrypted credentials container.

    Attributes:
        account_id: Identifier for the AWS account.
        salt: Salt used for key derivation.
        nonce: Nonce used for encryption.
        ciphertext: Encrypted credential data.
        metadata: Optional metadata (stored unencrypted).
    """

    account_id: str
    salt: bytes
    nonce: bytes
    ciphertext: bytes
    metadata: dict[str, str] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "version": "1.0",
            "account_id": self.account_id,
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
            "metadata": self.metadata or {},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EncryptedCredentials:
        """Create from dictionary."""
        return cls(
            account_id=data["account_id"],
            salt=base64.b64decode(data["salt"]),
            nonce=base64.b64decode(data["nonce"]),
            ciphertext=base64.b64decode(data["ciphertext"]),
            metadata=data.get("metadata"),
        )


class CredentialStore:
    """
    Secure storage for encrypted AWS credentials.

    Encrypts AWS credentials with user-provided passwords using
    ChaCha20-Poly1305 and stores them in a local file. This allows
    storing AWS credentials securely without relying on AWS profiles
    or environment variables.

    Security Features:
        - PBKDF2-HMAC-SHA256 key derivation (600,000 iterations)
        - ChaCha20-Poly1305 authenticated encryption
        - Unique salt per credential set
        - Restrictive file permissions (0o600)

    Example:
        >>> store = CredentialStore('/secure/credentials')
        >>> store.store_credentials(
        ...     'account1',
        ...     AWSCredentials('AKIA...', 'secret...'),
        ...     'encryption-password',
        ... )
        >>> creds = store.load_credentials('account1', 'encryption-password')
    """

    # Security parameters
    PBKDF2_ITERATIONS: int = 600_000
    SALT_SIZE: int = 32
    NONCE_SIZE: int = 12
    KEY_SIZE: int = 32

    def __init__(self, storage_path: str | Path) -> None:
        """
        Initialize credential store.

        Args:
            storage_path: Directory path for storing encrypted credentials.
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

        try:
            os.chmod(self.storage_path, 0o700)
        except OSError as e:
            logger.warning(f"Could not set permissions on {self.storage_path}: {e}")

        logger.info(f"Initialized credential store: {self.storage_path}")

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )
        return kdf.derive(password.encode("utf-8"))

    def _encrypt(self, data: bytes, password: str) -> tuple[bytes, bytes, bytes]:
        """Encrypt data with ChaCha20-Poly1305."""
        salt = secrets.token_bytes(self.SALT_SIZE)
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        key = self._derive_key(password, salt)
        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(nonce, data, None)
        return salt, nonce, ciphertext

    def _decrypt(
        self, salt: bytes, nonce: bytes, ciphertext: bytes, password: str
    ) -> bytes:
        """Decrypt data with ChaCha20-Poly1305."""
        key = self._derive_key(password, salt)
        cipher = ChaCha20Poly1305(key)
        return cipher.decrypt(nonce, ciphertext, None)

    def _get_credential_path(self, account_id: str) -> Path:
        """Get path for credential file."""
        # Sanitize account_id for use as filename
        safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in account_id)
        return self.storage_path / f"{safe_id}.credentials.enc"

    def store_credentials(
        self,
        account_id: str,
        credentials: AWSCredentials,
        password: str,
        metadata: dict[str, str] | None = None,
    ) -> Path:
        """
        Store encrypted AWS credentials.

        Args:
            account_id: Identifier for this set of credentials.
            credentials: AWS credentials to encrypt and store.
            password: Password for encryption (min 12 characters).
            metadata: Optional metadata to store (unencrypted).

        Returns:
            Path to the stored credential file.

        Raises:
            ConfigurationError: If password is too short.
        """
        if len(password) < 12:
            raise ConfigurationError("Credential password must be at least 12 characters")

        # Serialize credentials
        cred_data = json.dumps(credentials.to_dict()).encode("utf-8")

        # Encrypt
        salt, nonce, ciphertext = self._encrypt(cred_data, password)

        # Create encrypted credentials object
        encrypted = EncryptedCredentials(
            account_id=account_id,
            salt=salt,
            nonce=nonce,
            ciphertext=ciphertext,
            metadata=metadata,
        )

        # Write to file
        cred_path = self._get_credential_path(account_id)
        cred_path.write_text(json.dumps(encrypted.to_dict(), indent=2), encoding="utf-8")

        try:
            os.chmod(cred_path, 0o600)
        except OSError as e:
            logger.warning(f"Could not set permissions on {cred_path}: {e}")

        logger.info(f"Stored encrypted credentials for {account_id}")
        return cred_path

    def load_credentials(self, account_id: str, password: str) -> AWSCredentials:
        """
        Load and decrypt AWS credentials.

        Args:
            account_id: Identifier for the credentials to load.
            password: Password for decryption.

        Returns:
            Decrypted AWS credentials.

        Raises:
            ConfigurationError: If credentials file not found.
            DecryptionError: If decryption fails (wrong password).
        """
        cred_path = self._get_credential_path(account_id)

        if not cred_path.exists():
            raise ConfigurationError(f"Credentials not found for account: {account_id}")

        try:
            data = json.loads(cred_path.read_text(encoding="utf-8"))
            encrypted = EncryptedCredentials.from_dict(data)

            # Decrypt
            decrypted = self._decrypt(
                encrypted.salt,
                encrypted.nonce,
                encrypted.ciphertext,
                password,
            )

            cred_data = json.loads(decrypted.decode("utf-8"))
            credentials = AWSCredentials.from_dict(cred_data)

            logger.info(f"Loaded credentials for {account_id}")
            return credentials

        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid credential file format: {e}") from e
        except Exception as e:
            if "tag" in str(e).lower() or "authentication" in str(e).lower():
                raise DecryptionError(
                    shard_index=-1,
                    message=f"Failed to decrypt credentials for {account_id}: wrong password",
                ) from e
            raise

    def has_credentials(self, account_id: str) -> bool:
        """Check if credentials exist for an account."""
        return self._get_credential_path(account_id).exists()

    def delete_credentials(self, account_id: str, secure: bool = True) -> bool:
        """
        Delete stored credentials.

        Args:
            account_id: Identifier for the credentials to delete.
            secure: If True, overwrite with random data before deletion.

        Returns:
            True if deleted, False if not found.
        """
        cred_path = self._get_credential_path(account_id)

        if not cred_path.exists():
            return False

        if secure:
            # Overwrite with random data
            file_size = cred_path.stat().st_size
            cred_path.write_bytes(secrets.token_bytes(file_size))

        cred_path.unlink()
        logger.info(f"Deleted credentials for {account_id}")
        return True

    def list_accounts(self) -> list[str]:
        """List all stored account IDs."""
        accounts = []
        for path in self.storage_path.glob("*.credentials.enc"):
            account_id = path.stem.replace(".credentials", "")
            accounts.append(account_id)
        return sorted(accounts)


class InMemoryCredentialProvider:
    """
    Provides AWS credentials from encrypted in-memory storage.

    This allows passing encrypted credentials directly without
    storing them on disk. Useful for containerized environments.

    Example:
        >>> provider = InMemoryCredentialProvider()
        >>> encrypted = provider.encrypt_credentials(credentials, password)
        >>> # Later...
        >>> creds = provider.decrypt_credentials(encrypted, password)
    """

    PBKDF2_ITERATIONS: int = 600_000
    SALT_SIZE: int = 32
    NONCE_SIZE: int = 12
    KEY_SIZE: int = 32

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )
        return kdf.derive(password.encode("utf-8"))

    def encrypt_credentials(
        self,
        credentials: AWSCredentials,
        password: str,
        account_id: str = "default",
    ) -> EncryptedCredentials:
        """
        Encrypt credentials for in-memory storage.

        Args:
            credentials: AWS credentials to encrypt.
            password: Encryption password.
            account_id: Identifier for these credentials.

        Returns:
            Encrypted credentials object.
        """
        cred_data = json.dumps(credentials.to_dict()).encode("utf-8")

        salt = secrets.token_bytes(self.SALT_SIZE)
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        key = self._derive_key(password, salt)
        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(nonce, cred_data, None)

        return EncryptedCredentials(
            account_id=account_id,
            salt=salt,
            nonce=nonce,
            ciphertext=ciphertext,
        )

    def decrypt_credentials(
        self,
        encrypted: EncryptedCredentials,
        password: str,
    ) -> AWSCredentials:
        """
        Decrypt credentials from encrypted container.

        Args:
            encrypted: Encrypted credentials object.
            password: Decryption password.

        Returns:
            Decrypted AWS credentials.
        """
        key = self._derive_key(password, encrypted.salt)
        cipher = ChaCha20Poly1305(key)
        decrypted = cipher.decrypt(encrypted.nonce, encrypted.ciphertext, None)
        cred_data = json.loads(decrypted.decode("utf-8"))
        return AWSCredentials.from_dict(cred_data)

    def to_base64(self, encrypted: EncryptedCredentials) -> str:
        """Serialize encrypted credentials to base64 string."""
        return base64.b64encode(
            json.dumps(encrypted.to_dict()).encode("utf-8")
        ).decode("ascii")

    def from_base64(self, data: str) -> EncryptedCredentials:
        """Deserialize encrypted credentials from base64 string."""
        decoded = json.loads(base64.b64decode(data).decode("utf-8"))
        return EncryptedCredentials.from_dict(decoded)
