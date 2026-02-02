"""
Local filesystem storage backend.

This module provides a storage backend for storing shards on the local filesystem
with secure file permissions and optional secure deletion.
"""

from __future__ import annotations

import logging
import os
import re
import secrets
from pathlib import Path
from typing import TYPE_CHECKING

from src.backends.base import StorageBackend, StorageLocation, StorageType
from src.exceptions import DirectoryError, StorageError

if TYPE_CHECKING:
    from typing import Any

logger = logging.getLogger(__name__)


class LocalStorageBackend(StorageBackend):
    """
    Storage backend for local filesystem.

    Stores shards as JSON files in a specified directory with
    restrictive permissions (0o600 for files, 0o700 for directories).

    Attributes:
        directory: Path to the storage directory.

    Example:
        >>> backend = LocalStorageBackend('/secure/shards')
        >>> backend.write_shard('my-secret', 0, '{"data": "..."}')
    """

    def __init__(self, directory: str | Path) -> None:
        """
        Initialize local storage backend.

        Args:
            directory: Path to directory for storing shards.
                      Will be created if it doesn't exist.

        Raises:
            DirectoryError: If directory cannot be created or accessed.
        """
        self.directory = Path(directory)
        self._location = StorageLocation(
            storage_type=StorageType.LOCAL,
            identifier=str(self.directory.absolute()),
            config={"path": str(self.directory.absolute())},
        )

        # Create directory with secure permissions
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            os.chmod(self.directory, 0o700)
            logger.info(f"Initialized local storage backend: {self.directory}")
        except PermissionError as e:
            raise DirectoryError(
                "Permission denied creating directory", str(self.directory)
            ) from e
        except OSError as e:
            raise DirectoryError(
                f"Failed to create directory: {e}", str(self.directory)
            ) from e

    @property
    def storage_type(self) -> StorageType:
        """Return LOCAL storage type."""
        return StorageType.LOCAL

    @property
    def location(self) -> StorageLocation:
        """Return the storage location configuration."""
        return self._location

    def _get_shard_path(self, key: str, shard_index: int) -> Path:
        """Get the full path for a shard file."""
        shard_name = self.get_shard_path(key, shard_index)
        return self.directory / shard_name

    def _ensure_parent_directory(self, shard_path: Path) -> None:
        """Ensure parent directories exist with secure permissions."""
        parent = shard_path.parent
        if parent != self.directory and not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(parent, 0o700)
            except OSError as e:
                logger.warning(f"Could not set permissions on {parent}: {e}")

    def write_shard(self, key: str, shard_index: int, data: str) -> dict[str, Any]:
        """
        Write a shard to the local filesystem.

        Args:
            key: The original data key.
            shard_index: Index of this shard.
            data: JSON-encoded shard data.

        Returns:
            Dict with path, size, and storage type.

        Raises:
            StorageError: If write fails.
        """
        shard_path = self._get_shard_path(key, shard_index)

        try:
            self._ensure_parent_directory(shard_path)

            # Write with secure permissions
            shard_path.write_text(data, encoding="utf-8")

            try:
                os.chmod(shard_path, 0o600)
            except OSError as e:
                logger.warning(f"Could not set permissions on {shard_path}: {e}")

            logger.info(f"Wrote shard {shard_index} to {shard_path}")

            return {
                "path": str(shard_path),
                "size": len(data),
                "storage_type": self.storage_type.value,
                "location": str(self._location),
            }

        except Exception as e:
            logger.error(f"Failed to write shard {shard_index}: {e}")
            raise StorageError(
                f"Failed to write shard to local storage: {e}",
                backend=self.storage_type.value,
                location=str(self.directory),
            ) from e

    def read_shard(self, key: str, shard_index: int) -> str | None:
        """
        Read a shard from the local filesystem.

        Args:
            key: The original data key.
            shard_index: Index of the shard.

        Returns:
            JSON-encoded shard data, or None if not found.

        Raises:
            StorageError: If read fails (other than not found).
        """
        shard_path = self._get_shard_path(key, shard_index)

        try:
            if not shard_path.exists():
                logger.debug(f"Shard {shard_index} not found at {shard_path}")
                return None

            data = shard_path.read_text(encoding="utf-8")
            logger.info(f"Read shard {shard_index} from {shard_path}")
            return data

        except FileNotFoundError:
            return None
        except Exception as e:
            logger.error(f"Failed to read shard {shard_index}: {e}")
            raise StorageError(
                f"Failed to read shard from local storage: {e}",
                backend=self.storage_type.value,
                location=str(self.directory),
            ) from e

    def delete_shard(
        self, key: str, shard_index: int, secure: bool = True
    ) -> bool:
        """
        Delete a shard from the local filesystem.

        Args:
            key: The original data key.
            shard_index: Index of the shard.
            secure: If True, overwrite with random data before deletion.

        Returns:
            True if deleted, False if not found.

        Raises:
            StorageError: If deletion fails.
        """
        shard_path = self._get_shard_path(key, shard_index)

        try:
            if not shard_path.exists():
                return False

            if secure:
                # Overwrite with random data before deletion
                file_size = shard_path.stat().st_size
                shard_path.write_bytes(secrets.token_bytes(file_size))

            shard_path.unlink()
            logger.info(f"Deleted shard {shard_index} from {shard_path}")
            return True

        except FileNotFoundError:
            return False
        except Exception as e:
            logger.error(f"Failed to delete shard {shard_index}: {e}")
            raise StorageError(
                f"Failed to delete shard from local storage: {e}",
                backend=self.storage_type.value,
                location=str(self.directory),
            ) from e

    def shard_exists(self, key: str, shard_index: int) -> bool:
        """Check if a shard exists on the local filesystem."""
        return self._get_shard_path(key, shard_index).exists()

    def list_shards(self, key: str | None = None) -> list[tuple[str, int]]:
        """
        List shards in the local storage directory.

        Args:
            key: If provided, list only shards for this key.

        Returns:
            List of (key, shard_index) tuples.
        """
        shards: list[tuple[str, int]] = []
        pattern = re.compile(r"^(.+)\.shard(\d+)$")

        if not self.directory.exists():
            return shards

        for shard_file in self.directory.rglob("*.shard*"):
            relative = str(shard_file.relative_to(self.directory))
            match = pattern.match(relative)

            if match:
                shard_key = match.group(1)
                shard_index = int(match.group(2))

                if key is None or shard_key == key:
                    shards.append((shard_key, shard_index))

        return sorted(shards)
