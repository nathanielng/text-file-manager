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

Example (Local Mode):
    >>> from src import SecureShardingClient
    >>> client = SecureShardingClient.create_local(['/path/shard1', '/path/shard2', '/path/shard3'])
    >>> client.store('my-secret', b'sensitive data', 'strong-password-12')

Example (Hybrid Mode):
    >>> client = SecureShardingClient.create_hybrid(
    ...     local_directories=['/secure/drive1', '/secure/drive2'],
    ...     aws_account1_config={'bucket': 'shards-1', 'region': 'us-east-1'},
    ...     aws_account2_config={'bucket': 'shards-2', 'region': 'us-west-2'},
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

# Legacy import for backwards compatibility
from src.shard_manager import SecureLocalShardingClient

__version__ = "0.2.0"
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
