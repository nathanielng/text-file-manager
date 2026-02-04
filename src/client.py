"""
Multi-backend Secure Sharding Client.

This module provides a client that supports multiple storage modes:
- LOCAL: 100% local storage
- CLOUD: 100% cloud storage (across 2 AWS accounts)
- HYBRID: 50% local, 50% cloud (requires local + one AWS account to recover)

The hybrid mode is designed such that:
- Data cannot be accessed if only one storage mode is compromised
- Data can still be recovered even if one storage mode is completely lost

Supports per-location passwords:
- Local shards encrypted with local password
- AWS-1 shards encrypted with AWS-1 password (also encrypts credentials)
- AWS-2 shards encrypted with AWS-2 password (also encrypts credentials)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sslib import shamir

from src.backends import LocalStorageBackend, S3StorageBackend, StorageBackend, StorageType
from src.credentials import AWSCredentials, CredentialStore
from src.exceptions import (
    ConfigurationError,
    DecryptionError,
    InsufficientShardsError,
    IntegrityError,
    PasswordTooShortError,
    StorageError,
    ThresholdError,
)
from src.passwords import PasswordConfig, StoragePasswords

if TYPE_CHECKING:
    from typing import Any

__all__ = [
    "StorageMode",
    "ShardDistribution",
    "ShardResult",
    "DeletionResult",
    "SecureShardingClient",
]

logger = logging.getLogger(__name__)


class StorageMode(Enum):
    """
    Storage mode for shard distribution.

    Attributes:
        LOCAL: Store all shards locally (single machine, multiple directories).
        CLOUD: Store all shards in cloud (distributed across 2 AWS accounts).
        HYBRID: Store shards across local and cloud (requires multi-location access).
    """

    LOCAL = "local"
    CLOUD = "cloud"
    HYBRID = "hybrid"


@dataclass
class ShardDistribution:
    """
    Configuration for how shards are distributed across backends.

    For HYBRID mode, this determines how many shards go to each storage type
    and ensures the threshold requires access to multiple storage types.

    Attributes:
        total_shards: Total number of shards to create.
        threshold: Minimum shards required to reconstruct data.
        local_shards: Number of shards stored locally.
        cloud_account1_shards: Number of shards in first AWS account.
        cloud_account2_shards: Number of shards in second AWS account.
    """

    total_shards: int
    threshold: int
    local_shards: int = 0
    cloud_account1_shards: int = 0
    cloud_account2_shards: int = 0

    def __post_init__(self) -> None:
        """Validate the distribution configuration."""
        total = self.local_shards + self.cloud_account1_shards + self.cloud_account2_shards
        if total != self.total_shards:
            raise ConfigurationError(
                f"Shard distribution mismatch: {total} != {self.total_shards}"
            )
        if self.threshold > self.total_shards:
            raise ThresholdError(self.threshold, self.total_shards)

    @classmethod
    def for_local_mode(cls, num_directories: int, threshold: int = 3) -> ShardDistribution:
        """Create distribution for 100% local storage."""
        return cls(
            total_shards=num_directories,
            threshold=threshold,
            local_shards=num_directories,
            cloud_account1_shards=0,
            cloud_account2_shards=0,
        )

    @classmethod
    def for_cloud_mode(
        cls, threshold: int = 3, account1_shards: int = 3, account2_shards: int = 2
    ) -> ShardDistribution:
        """
        Create distribution for 100% cloud storage across 2 AWS accounts.

        Default: 5 shards total (3 in account1, 2 in account2), threshold of 3.
        """
        return cls(
            total_shards=account1_shards + account2_shards,
            threshold=threshold,
            local_shards=0,
            cloud_account1_shards=account1_shards,
            cloud_account2_shards=account2_shards,
        )

    @classmethod
    def for_hybrid_mode(
        cls,
        local_shards: int = 2,
        account1_shards: int = 2,
        account2_shards: int = 2,
    ) -> ShardDistribution:
        """
        Create distribution for hybrid local + cloud storage.

        The threshold is set such that:
        - Local alone cannot reconstruct (local_shards < threshold)
        - Single AWS account alone cannot reconstruct
        - Local + any one AWS account CAN reconstruct
        - Any two AWS accounts CAN reconstruct (if local is lost)

        Default: 6 shards (2 local, 2 AWS-1, 2 AWS-2), threshold of 4.
        This means you need shards from at least 2 different storage types.
        """
        total = local_shards + account1_shards + account2_shards

        # Threshold should be:
        # - Greater than any single source (no single source can recover)
        # - Less than or equal to sum of any two sources (recovery possible)
        max_single = max(local_shards, account1_shards, account2_shards)
        min_pair = min(
            local_shards + account1_shards,
            local_shards + account2_shards,
            account1_shards + account2_shards,
        )

        # Threshold must be > max_single and <= min_pair
        threshold = max_single + 1
        if threshold > min_pair:
            raise ConfigurationError(
                f"Cannot create valid hybrid distribution: threshold {threshold} "
                f"would exceed minimum pair sum {min_pair}. "
                f"Increase shard counts for better distribution."
            )

        return cls(
            total_shards=total,
            threshold=threshold,
            local_shards=local_shards,
            cloud_account1_shards=account1_shards,
            cloud_account2_shards=account2_shards,
        )


@dataclass
class ShardResult:
    """Result of a shard storage operation."""

    key: str
    threshold: int
    total_shares: int
    data_hash: str
    storage_mode: StorageMode
    distribution: ShardDistribution
    stored_shards: list[dict[str, Any]] = field(default_factory=list)
    success: bool = True

    def __post_init__(self) -> None:
        """Validate the result after initialization."""
        if self.success and len(self.stored_shards) < self.threshold:
            self.success = False


@dataclass
class DeletionResult:
    """Result of a shard deletion operation."""

    key: str
    deleted: list[dict[str, Any]] = field(default_factory=list)
    failed: list[dict[str, Any]] = field(default_factory=list)
    success: bool = True

    def __post_init__(self) -> None:
        """Validate the result after initialization."""
        self.success = len(self.failed) == 0


class SecureShardingClient:
    """
    Multi-backend secure sharding client with per-location passwords.

    Supports three storage modes:
    - LOCAL: All shards stored locally in multiple directories
    - CLOUD: All shards stored in AWS S3 across 2 accounts
    - HYBRID: Shards distributed between local and cloud storage

    Password Configuration:
    - Each storage location (local, AWS-1, AWS-2) can have its own password
    - Local shards are encrypted with the local password
    - AWS credentials are encrypted with their respective passwords
    - AWS shards are encrypted with their respective passwords

    The HYBRID mode ensures:
    1. No single storage type has enough shards to reconstruct data
    2. Data can be recovered with access to any two storage types
    3. Compromise of one storage type doesn't expose data
    4. Loss of one storage type doesn't prevent recovery

    Security Parameters:
        - PBKDF2 iterations: 600,000 (OWASP 2023)
        - Encryption: ChaCha20-Poly1305 (AEAD)
        - Key size: 256 bits
        - Salt/Nonce: Unique per shard

    Example:
        >>> # Hybrid mode with separate passwords
        >>> passwords = PasswordConfig.separate(
        ...     local="local-password-12",
        ...     aws_account1="aws1-password-12",
        ...     aws_account2="aws2-password-12",
        ... )
        >>> client = SecureShardingClient.create_hybrid(
        ...     local_directories=['/secure/drive1', '/secure/drive2'],
        ...     aws_account1_config={'bucket': 'shards-1', 'region': 'us-east-1'},
        ...     aws_account2_config={'bucket': 'shards-2', 'region': 'us-west-2'},
        ...     aws_account1_credentials=AWSCredentials('AKIA...', 'secret...'),
        ...     aws_account2_credentials=AWSCredentials('AKIA...', 'secret...'),
        ...     passwords=passwords,
        ...     credential_store_path='/secure/credentials',
        ... )
    """

    # Security parameters (OWASP 2023 recommendations)
    PBKDF2_ITERATIONS: int = 600_000
    SALT_SIZE: int = 32  # 256 bits
    NONCE_SIZE: int = 12  # 96 bits for ChaCha20Poly1305
    KEY_SIZE: int = 32  # 256 bits
    MIN_PASSWORD_LENGTH: int = 12
    SHARD_FORMAT_VERSION: str = "2.1"

    def __init__(
        self,
        backends: list[StorageBackend],
        storage_mode: StorageMode,
        distribution: ShardDistribution,
        passwords: StoragePasswords | None = None,
        backend_password_map: dict[int, str] | None = None,
    ) -> None:
        """
        Initialize the sharding client with storage backends.

        Use the factory methods (create_local, create_cloud, create_hybrid)
        for easier configuration.

        Args:
            backends: List of storage backends (local and/or S3).
            storage_mode: The storage mode being used.
            distribution: How shards should be distributed across backends.
            passwords: Password configuration for each storage location.
            backend_password_map: Mapping of backend index to password.
        """
        self.backends = backends
        self.storage_mode = storage_mode
        self.distribution = distribution
        self._passwords = passwords
        self._backend_password_map = backend_password_map or {}

        # Organize backends by type
        self.local_backends = [b for b in backends if b.storage_type == StorageType.LOCAL]
        self.s3_backends = [b for b in backends if b.storage_type == StorageType.AWS_S3]

        logger.info(
            f"Initialized SecureShardingClient: mode={storage_mode.value}, "
            f"backends={len(backends)}, threshold={distribution.threshold}"
        )

    def _get_password_for_backend(self, backend_index: int, default_password: str) -> str:
        """Get the appropriate password for a backend index."""
        if backend_index in self._backend_password_map:
            return self._backend_password_map[backend_index]
        return default_password

    @classmethod
    def create_local(
        cls,
        directories: list[str],
        threshold: int = 3,
        password: str | None = None,
    ) -> SecureShardingClient:
        """
        Create a client for 100% local storage.

        Args:
            directories: List of local directory paths for shard storage.
            threshold: Minimum shards needed to reconstruct data.
            password: Optional password for local encryption (can also be
                      provided at store/retrieve time).

        Returns:
            Configured SecureShardingClient for local storage.
        """
        if len(directories) < threshold:
            raise ConfigurationError(
                f"Need at least {threshold} directories for threshold {threshold}"
            )

        backends: list[StorageBackend] = [LocalStorageBackend(d) for d in directories]
        distribution = ShardDistribution.for_local_mode(len(directories), threshold)

        # Build password map if password provided
        backend_password_map: dict[int, str] = {}
        if password:
            for i in range(len(backends)):
                backend_password_map[i] = password

        return cls(
            backends,
            StorageMode.LOCAL,
            distribution,
            backend_password_map=backend_password_map,
        )

    @classmethod
    def create_cloud(
        cls,
        aws_account1_config: dict[str, Any],
        aws_account2_config: dict[str, Any],
        threshold: int = 3,
        account1_shards: int = 3,
        account2_shards: int = 2,
        aws_account1_credentials: AWSCredentials | None = None,
        aws_account2_credentials: AWSCredentials | None = None,
        passwords: PasswordConfig | None = None,
        credential_store_path: str | Path | None = None,
    ) -> SecureShardingClient:
        """
        Create a client for 100% cloud storage across 2 AWS accounts.

        Args:
            aws_account1_config: Config for first AWS account S3 backend.
                Required keys: bucket, region.
                Optional keys: profile_name, role_arn, prefix.
            aws_account2_config: Config for second AWS account S3 backend.
            threshold: Minimum shards needed to reconstruct data.
            account1_shards: Number of shards in first account.
            account2_shards: Number of shards in second account.
            aws_account1_credentials: AWS credentials for account 1.
            aws_account2_credentials: AWS credentials for account 2.
            passwords: Password configuration for each account.
            credential_store_path: Path to store encrypted credentials.

        Returns:
            Configured SecureShardingClient for cloud storage.
        """
        backends: list[StorageBackend] = []
        backend_password_map: dict[int, str] = {}
        storage_passwords: StoragePasswords | None = None

        # Get passwords if provided
        if passwords:
            storage_passwords = passwords.get_passwords()

        # Store encrypted credentials if provided
        if credential_store_path and storage_passwords:
            cred_store = CredentialStore(credential_store_path)

            if aws_account1_credentials:
                cred_store.store_credentials(
                    "aws_account1",
                    aws_account1_credentials,
                    storage_passwords.aws_account1,
                )
                # Add credentials to config
                aws_account1_config = dict(aws_account1_config)
                boto_config = aws_account1_credentials.to_boto3_config()
                aws_account1_config.update(boto_config)

            if aws_account2_credentials:
                cred_store.store_credentials(
                    "aws_account2",
                    aws_account2_credentials,
                    storage_passwords.aws_account2,
                )
                aws_account2_config = dict(aws_account2_config)
                boto_config = aws_account2_credentials.to_boto3_config()
                aws_account2_config.update(boto_config)

        # Create backends for account 1
        for i in range(account1_shards):
            config = dict(aws_account1_config)
            config.setdefault("prefix", f"shards/replica{i}/")
            config["account_id"] = config.get("account_id", "account1")
            backends.append(S3StorageBackend(**config))
            if storage_passwords:
                backend_password_map[i] = storage_passwords.aws_account1

        # Create backends for account 2
        for i in range(account2_shards):
            config = dict(aws_account2_config)
            config.setdefault("prefix", f"shards/replica{i}/")
            config["account_id"] = config.get("account_id", "account2")
            backends.append(S3StorageBackend(**config))
            if storage_passwords:
                backend_password_map[account1_shards + i] = storage_passwords.aws_account2

        distribution = ShardDistribution.for_cloud_mode(
            threshold, account1_shards, account2_shards
        )

        return cls(
            backends,
            StorageMode.CLOUD,
            distribution,
            passwords=storage_passwords,
            backend_password_map=backend_password_map,
        )

    @classmethod
    def create_hybrid(
        cls,
        local_directories: list[str],
        aws_account1_config: dict[str, Any],
        aws_account2_config: dict[str, Any],
        local_shards: int | None = None,
        account1_shards: int | None = None,
        account2_shards: int | None = None,
        aws_account1_credentials: AWSCredentials | None = None,
        aws_account2_credentials: AWSCredentials | None = None,
        passwords: PasswordConfig | None = None,
        credential_store_path: str | Path | None = None,
    ) -> SecureShardingClient:
        """
        Create a client for hybrid local + cloud storage with per-location passwords.

        This mode ensures:
        - Local alone cannot reconstruct data
        - Single AWS account alone cannot reconstruct data
        - Local + any one AWS account CAN reconstruct data
        - Both AWS accounts together CAN reconstruct data (if local is lost)

        Password Security:
        - Local shards encrypted with local password
        - AWS-1 credentials and shards encrypted with AWS-1 password
        - AWS-2 credentials and shards encrypted with AWS-2 password

        Args:
            local_directories: List of local directory paths.
            aws_account1_config: Config for first AWS account S3 backend.
            aws_account2_config: Config for second AWS account S3 backend.
            local_shards: Number of local shards (default: len(directories)).
            account1_shards: Number of shards in first AWS account (default: 2).
            account2_shards: Number of shards in second AWS account (default: 2).
            aws_account1_credentials: AWS credentials for account 1.
            aws_account2_credentials: AWS credentials for account 2.
            passwords: Password configuration (single, separate, or prefix_suffix).
            credential_store_path: Path to store encrypted AWS credentials.

        Returns:
            Configured SecureShardingClient for hybrid storage.

        Example:
            >>> # Same password for all
            >>> passwords = PasswordConfig.single("my-password-12chars")

            >>> # Different passwords
            >>> passwords = PasswordConfig.separate(
            ...     local="local-pwd-12345",
            ...     aws_account1="aws1-pwd-12345",
            ...     aws_account2="aws2-pwd-12345",
            ... )

            >>> # Prefix + suffix
            >>> passwords = PasswordConfig.prefix_suffix(
            ...     prefix="common-prefix-",
            ...     local_suffix="local-123",
            ...     aws1_suffix="aws1-456",
            ...     aws2_suffix="aws2-789",
            ... )
        """
        local_shards = local_shards or len(local_directories)
        account1_shards = account1_shards or 2
        account2_shards = account2_shards or 2

        if local_shards > len(local_directories):
            raise ConfigurationError(
                f"local_shards ({local_shards}) exceeds available directories "
                f"({len(local_directories)})"
            )

        backends: list[StorageBackend] = []
        backend_password_map: dict[int, str] = {}
        storage_passwords: StoragePasswords | None = None

        # Get passwords if provided
        if passwords:
            storage_passwords = passwords.get_passwords()

        # Store encrypted credentials if provided
        if credential_store_path and storage_passwords:
            cred_store = CredentialStore(credential_store_path)

            if aws_account1_credentials:
                cred_store.store_credentials(
                    "aws_account1",
                    aws_account1_credentials,
                    storage_passwords.aws_account1,
                )
                aws_account1_config = dict(aws_account1_config)
                boto_config = aws_account1_credentials.to_boto3_config()
                aws_account1_config.update(boto_config)

            if aws_account2_credentials:
                cred_store.store_credentials(
                    "aws_account2",
                    aws_account2_credentials,
                    storage_passwords.aws_account2,
                )
                aws_account2_config = dict(aws_account2_config)
                boto_config = aws_account2_credentials.to_boto3_config()
                aws_account2_config.update(boto_config)

        # Create local backends
        backend_idx = 0
        for i in range(local_shards):
            backends.append(LocalStorageBackend(local_directories[i]))
            if storage_passwords:
                backend_password_map[backend_idx] = storage_passwords.local
            backend_idx += 1

        # Create S3 backends for account 1
        for i in range(account1_shards):
            config = dict(aws_account1_config)
            config.setdefault("prefix", f"shards/replica{i}/")
            config["account_id"] = config.get("account_id", "account1")
            backends.append(S3StorageBackend(**config))
            if storage_passwords:
                backend_password_map[backend_idx] = storage_passwords.aws_account1
            backend_idx += 1

        # Create S3 backends for account 2
        for i in range(account2_shards):
            config = dict(aws_account2_config)
            config.setdefault("prefix", f"shards/replica{i}/")
            config["account_id"] = config.get("account_id", "account2")
            backends.append(S3StorageBackend(**config))
            if storage_passwords:
                backend_password_map[backend_idx] = storage_passwords.aws_account2
            backend_idx += 1

        distribution = ShardDistribution.for_hybrid_mode(
            local_shards, account1_shards, account2_shards
        )

        return cls(
            backends,
            StorageMode.HYBRID,
            distribution,
            passwords=storage_passwords,
            backend_password_map=backend_password_map,
        )

    @classmethod
    def load_with_credentials(
        cls,
        credential_store_path: str | Path,
        passwords: PasswordConfig,
        local_directories: list[str] | None = None,
        aws_account1_config: dict[str, Any] | None = None,
        aws_account2_config: dict[str, Any] | None = None,
        storage_mode: StorageMode = StorageMode.HYBRID,
        local_shards: int | None = None,
        account1_shards: int | None = None,
        account2_shards: int | None = None,
    ) -> SecureShardingClient:
        """
        Load a client using previously stored encrypted credentials.

        This is useful for resuming operations where credentials were
        previously stored using create_hybrid or create_cloud.

        Args:
            credential_store_path: Path where encrypted credentials are stored.
            passwords: Passwords for decrypting credentials and shards.
            local_directories: Local directories (for hybrid mode).
            aws_account1_config: Base config for AWS account 1 (bucket, region).
            aws_account2_config: Base config for AWS account 2 (bucket, region).
            storage_mode: Storage mode to use.
            local_shards: Number of local shards.
            account1_shards: Number of AWS account 1 shards.
            account2_shards: Number of AWS account 2 shards.

        Returns:
            Configured SecureShardingClient with loaded credentials.
        """
        storage_passwords = passwords.get_passwords()
        cred_store = CredentialStore(credential_store_path)

        # Load and decrypt AWS credentials
        if cred_store.has_credentials("aws_account1") and aws_account1_config:
            creds1 = cred_store.load_credentials("aws_account1", storage_passwords.aws_account1)
            aws_account1_config = dict(aws_account1_config)
            aws_account1_config.update(creds1.to_boto3_config())

        if cred_store.has_credentials("aws_account2") and aws_account2_config:
            creds2 = cred_store.load_credentials("aws_account2", storage_passwords.aws_account2)
            aws_account2_config = dict(aws_account2_config)
            aws_account2_config.update(creds2.to_boto3_config())

        # Create client based on storage mode
        if storage_mode == StorageMode.LOCAL:
            if not local_directories:
                raise ConfigurationError("local_directories required for LOCAL mode")
            return cls.create_local(
                directories=local_directories,
                threshold=local_shards or 3,
                password=storage_passwords.local,
            )
        elif storage_mode == StorageMode.CLOUD:
            if not aws_account1_config or not aws_account2_config:
                raise ConfigurationError("AWS configs required for CLOUD mode")
            return cls.create_cloud(
                aws_account1_config=aws_account1_config,
                aws_account2_config=aws_account2_config,
                account1_shards=account1_shards or 3,
                account2_shards=account2_shards or 2,
                passwords=passwords,
            )
        else:  # HYBRID
            if not local_directories or not aws_account1_config or not aws_account2_config:
                raise ConfigurationError(
                    "local_directories and AWS configs required for HYBRID mode"
                )
            return cls.create_hybrid(
                local_directories=local_directories,
                aws_account1_config=aws_account1_config,
                aws_account2_config=aws_account2_config,
                local_shards=local_shards,
                account1_shards=account1_shards,
                account2_shards=account2_shards,
                passwords=passwords,
            )

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2-HMAC-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )
        return kdf.derive(password.encode("utf-8"))

    def _encrypt_shard(self, data: bytes, password: str) -> tuple[bytes, bytes, bytes]:
        """Encrypt shard data with ChaCha20-Poly1305."""
        salt = secrets.token_bytes(self.SALT_SIZE)
        nonce = secrets.token_bytes(self.NONCE_SIZE)

        key = self._derive_key(password, salt)
        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(nonce, data, None)

        return salt, nonce, ciphertext

    def _decrypt_shard(
        self, salt: bytes, nonce: bytes, ciphertext: bytes, password: str
    ) -> bytes:
        """Decrypt shard data with ChaCha20-Poly1305."""
        key = self._derive_key(password, salt)
        cipher = ChaCha20Poly1305(key)
        return cipher.decrypt(nonce, ciphertext, None)

    def _compute_integrity_hash(self, data: bytes) -> str:
        """Compute SHA-256 hash for integrity verification."""
        return hashlib.sha256(data).hexdigest()

    def store(
        self,
        key: str,
        data: bytes,
        password: str | PasswordConfig | None = None,
        metadata: dict[str, str] | None = None,
    ) -> ShardResult:
        """
        Split data into encrypted shards and store according to storage mode.

        Each shard is encrypted with its location-specific password if
        per-location passwords were configured, otherwise uses the provided
        password for all shards.

        Args:
            key: Unique identifier for the sharded data.
            data: Raw bytes to shard and store.
            password: Password for encrypting shards. Can be:
                      - str: Single password for all shards
                      - PasswordConfig: Per-location passwords
                      - None: Use passwords from client configuration
            metadata: Optional metadata stored with shards (unencrypted).

        Returns:
            ShardResult with storage details and success status.

        Raises:
            TypeError: If data is not bytes.
            PasswordTooShortError: If password < 12 characters.
            ConfigurationError: If no password provided and none configured.
            InsufficientShardsError: If not enough shards could be stored.
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes")

        # Resolve passwords
        if isinstance(password, PasswordConfig):
            passwords = password.get_passwords()
        elif isinstance(password, str):
            if len(password) < self.MIN_PASSWORD_LENGTH:
                raise PasswordTooShortError(self.MIN_PASSWORD_LENGTH)
            # Use same password for all
            passwords = None
            default_password = password
        elif self._passwords:
            passwords = self._passwords
        else:
            raise ConfigurationError(
                "No password provided. Provide password parameter or configure "
                "passwords when creating the client."
            )

        # Update backend password map if using PasswordConfig
        if passwords:
            default_password = passwords.local  # Fallback
            # Rebuild password map
            self._backend_password_map = {}
            idx = 0
            for _ in range(self.distribution.local_shards):
                self._backend_password_map[idx] = passwords.local
                idx += 1
            for _ in range(self.distribution.cloud_account1_shards):
                self._backend_password_map[idx] = passwords.aws_account1
                idx += 1
            for _ in range(self.distribution.cloud_account2_shards):
                self._backend_password_map[idx] = passwords.aws_account2
                idx += 1

        dist = self.distribution
        logger.info(
            f"Storing '{key}' with {dist.total_shards} shards "
            f"(threshold: {dist.threshold}, mode: {self.storage_mode.value})"
        )

        # Compute integrity hash
        data_hash = self._compute_integrity_hash(data)

        # Split data using Shamir's Secret Sharing
        shares = shamir.to_base64(
            shamir.split_secret(data, dist.threshold, dist.total_shards)
        )

        # Prepare metadata
        shard_metadata = dict(metadata) if metadata else {}
        shard_metadata.update({
            "threshold": str(dist.threshold),
            "total-shares": str(dist.total_shards),
            "original-key": key,
            "data-hash": data_hash,
            "storage-mode": self.storage_mode.value,
            "pbkdf2-iterations": str(self.PBKDF2_ITERATIONS),
            "local-shards": str(dist.local_shards),
            "cloud-account1-shards": str(dist.cloud_account1_shards),
            "cloud-account2-shards": str(dist.cloud_account2_shards),
            "per-location-passwords": str(passwords is not None),
        })

        # Store each shard in its designated backend
        stored_shards: list[dict[str, Any]] = []

        for i, share in enumerate(shares):
            backend = self.backends[i]
            shard_password = self._get_password_for_backend(i, default_password)

            try:
                # Encrypt the shard with location-specific password
                share_bytes = share.encode("utf-8")
                salt, nonce, ciphertext = self._encrypt_shard(share_bytes, shard_password)

                # Create shard file structure
                shard_data = {
                    "version": self.SHARD_FORMAT_VERSION,
                    "salt": base64.b64encode(salt).decode("ascii"),
                    "nonce": base64.b64encode(nonce).decode("ascii"),
                    "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                    "metadata": shard_metadata,
                }

                # Write to backend
                result = backend.write_shard(key, i, json.dumps(shard_data, indent=2))
                result["shard_index"] = i
                result["backend_type"] = backend.storage_type.value
                stored_shards.append(result)

                logger.info(f"Stored shard {i} via {backend.storage_type.value}")

            except Exception as e:
                logger.error(f"Failed to store shard {i}: {e}")
                continue

        if len(stored_shards) < dist.threshold:
            raise InsufficientShardsError(
                available=len(stored_shards),
                required=dist.threshold,
                shard_indices=[s["shard_index"] for s in stored_shards],
            )

        logger.info(
            f"Successfully stored {len(stored_shards)}/{dist.total_shards} shards"
        )

        return ShardResult(
            key=key,
            threshold=dist.threshold,
            total_shares=dist.total_shards,
            data_hash=data_hash,
            storage_mode=self.storage_mode,
            distribution=dist,
            stored_shards=stored_shards,
            success=True,
        )

    def retrieve(
        self,
        key: str,
        password: str | PasswordConfig | None = None,
        verify_integrity: bool = True,
    ) -> bytes:
        """
        Retrieve and reconstruct data from encrypted shards.

        Will attempt to read from all available backends and reconstruct
        once the threshold is reached. Uses location-specific passwords
        for decryption if configured.

        Args:
            key: Original file key used during storage.
            password: Password for decrypting shards. Can be:
                      - str: Single password for all shards
                      - PasswordConfig: Per-location passwords
                      - None: Use passwords from client configuration
            verify_integrity: Whether to verify SHA-256 hash.

        Returns:
            Reconstructed original data as bytes.

        Raises:
            DecryptionError: If decryption fails.
            InsufficientShardsError: If not enough shards available.
            IntegrityError: If integrity verification fails.
            ConfigurationError: If no password provided and none configured.
        """
        # Resolve passwords
        if isinstance(password, PasswordConfig):
            passwords = password.get_passwords()
        elif isinstance(password, str):
            passwords = None
            default_password = password
        elif self._passwords:
            passwords = self._passwords
        else:
            raise ConfigurationError(
                "No password provided. Provide password parameter or configure "
                "passwords when creating the client."
            )

        # Update backend password map if using PasswordConfig
        if passwords:
            default_password = passwords.local  # Fallback
            self._backend_password_map = {}
            idx = 0
            for _ in range(self.distribution.local_shards):
                self._backend_password_map[idx] = passwords.local
                idx += 1
            for _ in range(self.distribution.cloud_account1_shards):
                self._backend_password_map[idx] = passwords.aws_account1
                idx += 1
            for _ in range(self.distribution.cloud_account2_shards):
                self._backend_password_map[idx] = passwords.aws_account2
                idx += 1

        logger.info(f"Retrieving '{key}' (mode: {self.storage_mode.value})")

        shares: list[str] = []
        shard_indices: list[int] = []
        detected_threshold: int | None = None
        expected_hash: str | None = None

        for i, backend in enumerate(self.backends):
            # Stop early if we have enough
            if detected_threshold and len(shares) >= detected_threshold:
                break

            shard_password = self._get_password_for_backend(i, default_password)

            try:
                shard_data_str = backend.read_shard(key, i)
                if shard_data_str is None:
                    logger.debug(f"Shard {i} not found in {backend.storage_type.value}")
                    continue

                shard_data = json.loads(shard_data_str)

                salt = base64.b64decode(shard_data["salt"])
                nonce = base64.b64decode(shard_data["nonce"])
                ciphertext = base64.b64decode(shard_data["ciphertext"])

                # Decrypt with location-specific password
                try:
                    decrypted = self._decrypt_shard(salt, nonce, ciphertext, shard_password)
                    share = decrypted.decode("utf-8")
                    shares.append(share)
                    shard_indices.append(i)
                    logger.info(f"Decrypted shard {i} from {backend.storage_type.value}")
                except Exception as e:
                    logger.error(f"Failed to decrypt shard {i}: {e}")
                    raise DecryptionError(i, "Wrong password or corrupted data") from e

                # Extract metadata
                metadata = shard_data.get("metadata", {})
                if not detected_threshold and "threshold" in metadata:
                    detected_threshold = int(metadata["threshold"])
                if not expected_hash and "data-hash" in metadata:
                    expected_hash = metadata["data-hash"]

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse shard {i}: {e}")
                continue
            except DecryptionError:
                raise
            except StorageError as e:
                logger.error(f"Storage error reading shard {i}: {e}")
                continue
            except Exception as e:
                logger.error(f"Failed to retrieve shard {i}: {e}")
                continue

        # Validate we have enough
        threshold = detected_threshold or self.distribution.threshold

        if len(shares) < threshold:
            raise InsufficientShardsError(
                available=len(shares),
                required=threshold,
                shard_indices=shard_indices,
            )

        logger.info(f"Reconstructing from {len(shares)} shards (indices: {shard_indices})")

        # Reconstruct
        share_tuples = shamir.from_base64(shares[:threshold])
        reconstructed = shamir.recover_secret(share_tuples)

        # Verify integrity
        if verify_integrity and expected_hash:
            actual_hash = self._compute_integrity_hash(reconstructed)
            if actual_hash != expected_hash:
                raise IntegrityError(expected_hash, actual_hash)
            logger.info("Integrity check passed")

        logger.info(f"Successfully reconstructed '{key}' ({len(reconstructed)} bytes)")
        return reconstructed

    def delete(self, key: str, secure: bool = True) -> DeletionResult:
        """
        Delete all shards for a given key from all backends.

        Args:
            key: Original file key to delete.
            secure: If True, securely delete where supported.

        Returns:
            DeletionResult with deletion details.
        """
        logger.info(f"Deleting all shards for '{key}'")

        deleted: list[dict[str, Any]] = []
        failed: list[dict[str, Any]] = []

        for i, backend in enumerate(self.backends):
            try:
                if backend.delete_shard(key, i, secure):
                    deleted.append({
                        "shard_index": i,
                        "backend": backend.storage_type.value,
                        "location": str(backend.location),
                    })
                    logger.info(f"Deleted shard {i} from {backend.storage_type.value}")
            except Exception as e:
                logger.error(f"Failed to delete shard {i}: {e}")
                failed.append({
                    "shard_index": i,
                    "backend": backend.storage_type.value,
                    "error": str(e),
                })

        logger.info(f"Deletion complete: {len(deleted)} deleted, {len(failed)} failed")

        return DeletionResult(key=key, deleted=deleted, failed=failed)

    def list_keys(self) -> list[str]:
        """
        List all stored keys across all backends.

        Returns:
            Sorted list of unique keys.
        """
        keys: set[str] = set()

        for backend in self.backends:
            try:
                for shard_key, _ in backend.list_shards():
                    keys.add(shard_key)
            except Exception as e:
                logger.warning(f"Failed to list shards from {backend.location}: {e}")

        return sorted(keys)

    def get_shard_status(self, key: str) -> dict[str, Any]:
        """
        Get detailed status of all shards for a key.

        Returns:
            Dict with shard availability per backend type.
        """
        status: dict[str, Any] = {
            "key": key,
            "threshold": self.distribution.threshold,
            "total_shards": self.distribution.total_shards,
            "storage_mode": self.storage_mode.value,
            "shards": [],
            "local_available": 0,
            "cloud_account1_available": 0,
            "cloud_account2_available": 0,
            "can_reconstruct": False,
        }

        local_count = 0
        cloud1_count = 0
        cloud2_count = 0

        for i, backend in enumerate(self.backends):
            exists = backend.shard_exists(key, i)
            shard_info = {
                "index": i,
                "backend_type": backend.storage_type.value,
                "location": str(backend.location),
                "exists": exists,
            }
            status["shards"].append(shard_info)

            if exists:
                if backend.storage_type == StorageType.LOCAL:
                    local_count += 1
                elif i < self.distribution.local_shards + self.distribution.cloud_account1_shards:
                    cloud1_count += 1
                else:
                    cloud2_count += 1

        status["local_available"] = local_count
        status["cloud_account1_available"] = cloud1_count
        status["cloud_account2_available"] = cloud2_count

        total_available = local_count + cloud1_count + cloud2_count
        status["can_reconstruct"] = total_available >= self.distribution.threshold

        return status
