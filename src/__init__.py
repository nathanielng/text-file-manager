"""
Text File Manager - Secure file management with encrypted sharding.

This package provides secure storage and retrieval of sensitive data using:
- Shamir's Secret Sharing for data sharding
- ChaCha20-Poly1305 authenticated encryption
- PBKDF2-HMAC-SHA256 for password-based key derivation

Supports three storage modes:
- LOCAL: 100% local storage across multiple directories
- CLOUD: 100% cloud storage across 2 AWS accounts
- HYBRID: 50% local, 50% cloud (requires multi-location access)

Password Configuration Options:
- Single password for all locations
- Separate passwords for each location (local, AWS-1, AWS-2)
- Prefix + suffix pattern (common prefix with unique suffixes)

Example (Local Mode):
    >>> from src import SecureShardingClient
    >>> client = SecureShardingClient.create_local(['/path/shard1', '/path/shard2', '/path/shard3'])
    >>> client.store('my-secret', b'sensitive data', 'strong-password-12')

Example (Hybrid Mode with Per-Location Passwords):
    >>> from src import SecureShardingClient, PasswordConfig, AWSCredentials
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

from src.backends import (
    LocalStorageBackend,
    S3StorageBackend,
    StorageBackend,
    StorageLocation,
    StorageType,
)
from src.client import (
    DeletionResult,
    SecureShardingClient,
    ShardDistribution,
    ShardResult,
    StorageMode,
)
from src.credentials import (
    AWSCredentials,
    CredentialStore,
    EncryptedCredentials,
    InMemoryCredentialProvider,
)
from src.exceptions import (
    ConfigurationError,
    DecryptionError,
    DirectoryError,
    InsufficientShardsError,
    IntegrityError,
    PasswordError,
    PasswordTooShortError,
    ShardManagerError,
    StorageError,
    ThresholdError,
)
from src.passwords import PasswordConfig, PasswordMode, StoragePasswords

# Legacy import for backwards compatibility
from src.shard_manager import SecureLocalShardingClient

__version__ = "0.3.0"
__all__ = [
    # Main client (new multi-backend)
    "SecureShardingClient",
    "StorageMode",
    "ShardDistribution",
    # Legacy client (local-only)
    "SecureLocalShardingClient",
    # Result types
    "ShardResult",
    "DeletionResult",
    # Storage backends
    "StorageBackend",
    "StorageLocation",
    "StorageType",
    "LocalStorageBackend",
    "S3StorageBackend",
    # Password configuration
    "PasswordConfig",
    "PasswordMode",
    "StoragePasswords",
    # AWS credentials
    "AWSCredentials",
    "CredentialStore",
    "EncryptedCredentials",
    "InMemoryCredentialProvider",
    # Exceptions
    "ShardManagerError",
    "PasswordError",
    "PasswordTooShortError",
    "DecryptionError",
    "IntegrityError",
    "InsufficientShardsError",
    "ThresholdError",
    "DirectoryError",
    "StorageError",
    "ConfigurationError",
]
