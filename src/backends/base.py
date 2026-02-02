"""
Abstract base class for storage backends.

This module defines the interface that all storage backends must implement,
enabling pluggable storage for local filesystems, cloud providers, etc.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any


class StorageType(Enum):
    """Type of storage backend."""

    LOCAL = "local"
    AWS_S3 = "aws_s3"


@dataclass
class StorageLocation:
    """
    Represents a storage location with its backend configuration.

    Attributes:
        storage_type: The type of storage backend.
        identifier: Unique identifier for this location (path, bucket name, etc.).
        config: Backend-specific configuration.
        account_id: Optional account identifier (for cloud providers).
    """

    storage_type: StorageType
    identifier: str
    config: dict[str, Any]
    account_id: str | None = None

    def __str__(self) -> str:
        """Return human-readable representation."""
        if self.account_id:
            return f"{self.storage_type.value}:{self.account_id}/{self.identifier}"
        return f"{self.storage_type.value}:{self.identifier}"


class StorageBackend(ABC):
    """
    Abstract base class for storage backends.

    All storage backends must implement these methods to support
    shard storage, retrieval, deletion, and listing operations.
    """

    @property
    @abstractmethod
    def storage_type(self) -> StorageType:
        """Return the type of this storage backend."""
        ...

    @property
    @abstractmethod
    def location(self) -> StorageLocation:
        """Return the storage location configuration."""
        ...

    @abstractmethod
    def write_shard(self, key: str, shard_index: int, data: str) -> dict[str, Any]:
        """
        Write a shard to storage.

        Args:
            key: The original data key.
            shard_index: Index of this shard (0-based).
            data: JSON-encoded shard data.

        Returns:
            Dict containing storage metadata (path, size, etc.).

        Raises:
            StorageError: If write fails.
        """
        ...

    @abstractmethod
    def read_shard(self, key: str, shard_index: int) -> str | None:
        """
        Read a shard from storage.

        Args:
            key: The original data key.
            shard_index: Index of the shard to read.

        Returns:
            JSON-encoded shard data, or None if not found.

        Raises:
            StorageError: If read fails (other than not found).
        """
        ...

    @abstractmethod
    def delete_shard(
        self, key: str, shard_index: int, secure: bool = True
    ) -> bool:
        """
        Delete a shard from storage.

        Args:
            key: The original data key.
            shard_index: Index of the shard to delete.
            secure: If True, securely overwrite before deletion (if supported).

        Returns:
            True if deleted, False if not found.

        Raises:
            StorageError: If deletion fails.
        """
        ...

    @abstractmethod
    def shard_exists(self, key: str, shard_index: int) -> bool:
        """
        Check if a shard exists.

        Args:
            key: The original data key.
            shard_index: Index of the shard.

        Returns:
            True if shard exists, False otherwise.
        """
        ...

    @abstractmethod
    def list_shards(self, key: str | None = None) -> list[tuple[str, int]]:
        """
        List shards in storage.

        Args:
            key: If provided, list only shards for this key.
                 If None, list all shards.

        Returns:
            List of (key, shard_index) tuples.
        """
        ...

    def get_shard_path(self, key: str, shard_index: int) -> str:
        """
        Generate the storage path/key for a shard.

        Args:
            key: The original data key.
            shard_index: Index of the shard.

        Returns:
            Storage-specific path or key for the shard.
        """
        return f"{key}.shard{shard_index}"
