"""
Custom exceptions for the Text File Manager.

This module defines specific exception types for better error handling
and clearer error messages when working with encrypted sharded data.
"""

from __future__ import annotations


class ShardManagerError(Exception):
    """Base exception for all shard manager errors."""

    pass


class PasswordError(ShardManagerError):
    """Raised when password validation fails."""

    def __init__(self, message: str = "Password validation failed") -> None:
        super().__init__(message)


class PasswordTooShortError(PasswordError):
    """Raised when password does not meet minimum length requirements."""

    def __init__(self, min_length: int = 12) -> None:
        super().__init__(f"Password must be at least {min_length} characters long")
        self.min_length = min_length


class DecryptionError(ShardManagerError):
    """Raised when shard decryption fails."""

    def __init__(
        self, shard_index: int, message: str = "Failed to decrypt shard"
    ) -> None:
        super().__init__(f"{message} (shard {shard_index})")
        self.shard_index = shard_index


class IntegrityError(ShardManagerError):
    """Raised when data integrity verification fails."""

    def __init__(self, expected_hash: str, actual_hash: str) -> None:
        super().__init__(
            f"Integrity check failed. Expected: {expected_hash}, got: {actual_hash}"
        )
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash


class InsufficientShardsError(ShardManagerError):
    """Raised when not enough shards are available for reconstruction."""

    def __init__(
        self, available: int, required: int, shard_indices: list[int] | None = None
    ) -> None:
        indices_msg = f" (available indices: {shard_indices})" if shard_indices else ""
        super().__init__(
            f"Insufficient shards: {available}/{required} available{indices_msg}"
        )
        self.available = available
        self.required = required
        self.shard_indices = shard_indices or []


class ThresholdError(ShardManagerError):
    """Raised when threshold configuration is invalid."""

    def __init__(self, threshold: int, total_shares: int) -> None:
        super().__init__(
            f"Invalid threshold: {threshold} cannot exceed total shares: {total_shares}"
        )
        self.threshold = threshold
        self.total_shares = total_shares


class DirectoryError(ShardManagerError):
    """Raised when there are issues with shard directories."""

    def __init__(self, message: str, directory: str | None = None) -> None:
        full_message = f"{message}: {directory}" if directory else message
        super().__init__(full_message)
        self.directory = directory


class StorageError(ShardManagerError):
    """Raised when a storage backend operation fails."""

    def __init__(
        self,
        message: str,
        backend: str | None = None,
        location: str | None = None,
    ) -> None:
        parts = [message]
        if backend:
            parts.append(f"backend={backend}")
        if location:
            parts.append(f"location={location}")
        super().__init__(" ".join(parts))
        self.backend = backend
        self.location = location


class ConfigurationError(ShardManagerError):
    """Raised when storage mode configuration is invalid."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
