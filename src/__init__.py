"""
Text File Manager - Secure file management with encrypted sharding.

This package provides secure storage and retrieval of sensitive data using:
- Shamir's Secret Sharing for data sharding
- ChaCha20-Poly1305 authenticated encryption
- PBKDF2-HMAC-SHA256 for password-based key derivation

Example:
    >>> from src import SecureLocalShardingClient
    >>> client = SecureLocalShardingClient(['/path/to/shard1', '/path/to/shard2'])
    >>> client.store_sharded('my-secret', b'sensitive data', 'strong-password-12')
"""

from src.exceptions import (
    DecryptionError,
    DirectoryError,
    InsufficientShardsError,
    IntegrityError,
    PasswordError,
    PasswordTooShortError,
    ShardManagerError,
    ThresholdError,
)
from src.shard_manager import DeletionResult, SecureLocalShardingClient, ShardResult

__version__ = "0.1.0"
__all__ = [
    # Main client
    "SecureLocalShardingClient",
    # Result types
    "ShardResult",
    "DeletionResult",
    # Exceptions
    "ShardManagerError",
    "PasswordError",
    "PasswordTooShortError",
    "DecryptionError",
    "IntegrityError",
    "InsufficientShardsError",
    "ThresholdError",
    "DirectoryError",
]
