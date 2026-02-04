"""
Tests for local filesystem storage backend.
"""

import json
import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.backends.local import LocalStorageBackend
from src.backends.base import StorageType
from src.exceptions import DirectoryError, StorageError


class TestLocalStorageBackend:
    """Tests for LocalStorageBackend class."""

    @pytest.fixture
    def temp_backend(self, tmp_path):
        """Create a temporary local storage backend."""
        return LocalStorageBackend(tmp_path / "shards")

    def test_creates_directory(self, tmp_path):
        """Test that backend creates storage directory."""
        storage_dir = tmp_path / "new" / "shards"
        backend = LocalStorageBackend(storage_dir)
        assert storage_dir.exists()
        assert storage_dir.is_dir()

    def test_storage_type(self, temp_backend):
        """Test storage type is LOCAL."""
        assert temp_backend.storage_type == StorageType.LOCAL

    def test_location_property(self, temp_backend):
        """Test location property contains correct info."""
        location = temp_backend.location
        assert location.storage_type == StorageType.LOCAL
        assert "shards" in location.identifier

    def test_write_shard(self, temp_backend):
        """Test writing a shard."""
        shard_data = json.dumps({"version": "2.1", "data": "encrypted-content"})
        result = temp_backend.write_shard("test-key", 0, shard_data)

        assert "path" in result
        assert "size" in result
        assert result["storage_type"] == "local"
        assert result["size"] == len(shard_data)

        # Verify file exists
        shard_path = Path(result["path"])
        assert shard_path.exists()
        assert shard_path.read_text() == shard_data

    def test_read_shard(self, temp_backend):
        """Test reading a shard."""
        shard_data = json.dumps({"version": "2.1", "encrypted": "data123"})
        temp_backend.write_shard("test-key", 0, shard_data)

        read_data = temp_backend.read_shard("test-key", 0)
        assert read_data == shard_data

    def test_read_nonexistent_shard(self, temp_backend):
        """Test reading nonexistent shard returns None."""
        result = temp_backend.read_shard("nonexistent", 0)
        assert result is None

    def test_delete_shard(self, temp_backend):
        """Test deleting a shard."""
        temp_backend.write_shard("test-key", 0, "data")

        result = temp_backend.delete_shard("test-key", 0, secure=False)
        assert result is True

        # Should no longer exist
        assert temp_backend.read_shard("test-key", 0) is None

    def test_delete_shard_secure(self, temp_backend):
        """Test secure deletion overwrites data."""
        shard_data = "sensitive-data" * 100
        result = temp_backend.write_shard("test-key", 0, shard_data)
        shard_path = Path(result["path"])

        # Delete securely
        temp_backend.delete_shard("test-key", 0, secure=True)

        # File should not exist
        assert not shard_path.exists()

    def test_delete_nonexistent_shard(self, temp_backend):
        """Test deleting nonexistent shard returns False."""
        result = temp_backend.delete_shard("nonexistent", 0)
        assert result is False

    def test_shard_exists(self, temp_backend):
        """Test checking if shard exists."""
        assert not temp_backend.shard_exists("test-key", 0)

        temp_backend.write_shard("test-key", 0, "data")

        assert temp_backend.shard_exists("test-key", 0)
        assert not temp_backend.shard_exists("test-key", 1)
        assert not temp_backend.shard_exists("other-key", 0)

    def test_list_shards_empty(self, temp_backend):
        """Test listing shards when empty."""
        shards = temp_backend.list_shards()
        assert shards == []

    def test_list_shards(self, temp_backend):
        """Test listing all shards."""
        temp_backend.write_shard("key1", 0, "data")
        temp_backend.write_shard("key1", 1, "data")
        temp_backend.write_shard("key2", 0, "data")

        shards = temp_backend.list_shards()
        assert len(shards) == 3
        assert ("key1", 0) in shards
        assert ("key1", 1) in shards
        assert ("key2", 0) in shards

    def test_list_shards_by_key(self, temp_backend):
        """Test listing shards for specific key."""
        temp_backend.write_shard("key1", 0, "data")
        temp_backend.write_shard("key1", 1, "data")
        temp_backend.write_shard("key2", 0, "data")

        shards = temp_backend.list_shards(key="key1")
        assert len(shards) == 2
        assert ("key1", 0) in shards
        assert ("key1", 1) in shards

    def test_nested_key_path(self, temp_backend):
        """Test keys with nested paths."""
        temp_backend.write_shard("secrets/api/key1", 0, "data")

        result = temp_backend.read_shard("secrets/api/key1", 0)
        assert result == "data"

        assert temp_backend.shard_exists("secrets/api/key1", 0)

    def test_multiple_shards_same_key(self, temp_backend):
        """Test writing multiple shards for same key."""
        for i in range(5):
            result = temp_backend.write_shard(f"multi-key", i, f"data-{i}")
            assert "path" in result

        # All should exist
        for i in range(5):
            data = temp_backend.read_shard("multi-key", i)
            assert data == f"data-{i}"

    def test_get_shard_path_method(self, temp_backend):
        """Test the shard path generation."""
        path = temp_backend.get_shard_path("my-key", 3)
        assert path == "my-key.shard3"

    def test_write_read_json_data(self, temp_backend):
        """Test writing and reading JSON shard data."""
        shard_content = {
            "version": "2.1",
            "salt": "base64-salt",
            "nonce": "base64-nonce",
            "ciphertext": "base64-ciphertext",
            "metadata": {
                "threshold": "3",
                "total-shares": "5",
            },
        }
        shard_json = json.dumps(shard_content, indent=2)

        temp_backend.write_shard("encrypted-key", 0, shard_json)
        read_json = temp_backend.read_shard("encrypted-key", 0)

        read_content = json.loads(read_json)
        assert read_content == shard_content


class TestLocalStorageBackendEdgeCases:
    """Edge case tests for LocalStorageBackend."""

    def test_special_characters_in_key(self, tmp_path):
        """Test handling keys with special characters."""
        backend = LocalStorageBackend(tmp_path / "shards")

        # These should work
        backend.write_shard("key-with-dashes", 0, "data")
        backend.write_shard("key_with_underscores", 0, "data")
        backend.write_shard("key.with.dots", 0, "data")

        assert backend.shard_exists("key-with-dashes", 0)
        assert backend.shard_exists("key_with_underscores", 0)
        assert backend.shard_exists("key.with.dots", 0)

    def test_unicode_in_data(self, tmp_path):
        """Test handling Unicode in shard data."""
        backend = LocalStorageBackend(tmp_path / "shards")

        unicode_data = json.dumps({"message": "Hello, 世界! 🔐"})
        backend.write_shard("unicode-key", 0, unicode_data)

        read_data = backend.read_shard("unicode-key", 0)
        assert read_data == unicode_data

    def test_large_shard_data(self, tmp_path):
        """Test handling large shard data."""
        backend = LocalStorageBackend(tmp_path / "shards")

        # 1MB of data
        large_data = "x" * (1024 * 1024)
        result = backend.write_shard("large-key", 0, large_data)

        assert result["size"] == len(large_data)
        read_data = backend.read_shard("large-key", 0)
        assert len(read_data) == len(large_data)

    def test_overwrite_existing_shard(self, tmp_path):
        """Test overwriting an existing shard."""
        backend = LocalStorageBackend(tmp_path / "shards")

        backend.write_shard("key", 0, "original-data")
        backend.write_shard("key", 0, "new-data")

        read_data = backend.read_shard("key", 0)
        assert read_data == "new-data"

    def test_empty_data(self, tmp_path):
        """Test handling empty shard data."""
        backend = LocalStorageBackend(tmp_path / "shards")

        backend.write_shard("empty-key", 0, "")
        read_data = backend.read_shard("empty-key", 0)
        assert read_data == ""
