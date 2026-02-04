"""
Tests for the SecureShardingClient.
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.client import (
    SecureShardingClient,
    StorageMode,
    ShardDistribution,
    ShardResult,
    DeletionResult,
)
from src.passwords import PasswordConfig
from src.exceptions import (
    ConfigurationError,
    DecryptionError,
    InsufficientShardsError,
    IntegrityError,
    PasswordTooShortError,
    ThresholdError,
)


class TestShardDistribution:
    """Tests for ShardDistribution dataclass."""

    def test_local_mode_distribution(self):
        """Test creating distribution for local mode."""
        dist = ShardDistribution.for_local_mode(num_directories=5, threshold=3)
        assert dist.total_shards == 5
        assert dist.threshold == 3
        assert dist.local_shards == 5
        assert dist.cloud_account1_shards == 0
        assert dist.cloud_account2_shards == 0

    def test_cloud_mode_distribution(self):
        """Test creating distribution for cloud mode."""
        dist = ShardDistribution.for_cloud_mode(
            threshold=3,
            account1_shards=3,
            account2_shards=2,
        )
        assert dist.total_shards == 5
        assert dist.threshold == 3
        assert dist.local_shards == 0
        assert dist.cloud_account1_shards == 3
        assert dist.cloud_account2_shards == 2

    def test_hybrid_mode_distribution(self):
        """Test creating distribution for hybrid mode."""
        dist = ShardDistribution.for_hybrid_mode(
            local_shards=2,
            account1_shards=2,
            account2_shards=2,
        )
        assert dist.total_shards == 6
        # Threshold should be > max single (2) but <= min pair (4)
        assert dist.threshold == 3
        assert dist.local_shards == 2
        assert dist.cloud_account1_shards == 2
        assert dist.cloud_account2_shards == 2

    def test_hybrid_mode_threshold_calculation(self):
        """Test automatic threshold calculation for hybrid mode."""
        # With 3, 2, 2 shards
        dist = ShardDistribution.for_hybrid_mode(
            local_shards=3,
            account1_shards=2,
            account2_shards=2,
        )
        # max_single = 3, so threshold = 4
        # min_pair = 2+2 = 4, so threshold 4 is valid
        assert dist.threshold == 4

    def test_invalid_hybrid_configuration(self):
        """Test that invalid hybrid config raises error."""
        # With 5, 1, 1 - threshold would be 6 but min_pair is only 2
        with pytest.raises(ConfigurationError):
            ShardDistribution.for_hybrid_mode(
                local_shards=5,
                account1_shards=1,
                account2_shards=1,
            )

    def test_threshold_exceeds_total(self):
        """Test that threshold > total raises ThresholdError."""
        with pytest.raises(ThresholdError):
            ShardDistribution(
                total_shards=3,
                threshold=5,
                local_shards=3,
            )

    def test_shard_count_mismatch(self):
        """Test that mismatched shard counts raise error."""
        with pytest.raises(ConfigurationError):
            ShardDistribution(
                total_shards=5,
                threshold=3,
                local_shards=2,
                cloud_account1_shards=2,
                cloud_account2_shards=0,  # Total is 4, not 5
            )


class TestSecureShardingClientLocal:
    """Tests for SecureShardingClient in local mode."""

    @pytest.fixture
    def local_directories(self, tmp_path):
        """Create temporary directories for local storage."""
        dirs = []
        for i in range(5):
            d = tmp_path / f"shard{i}"
            d.mkdir()
            dirs.append(str(d))
        return dirs

    @pytest.fixture
    def local_client(self, local_directories):
        """Create a local storage client."""
        return SecureShardingClient.create_local(
            directories=local_directories,
            threshold=3,
        )

    def test_create_local_client(self, local_directories):
        """Test creating a local storage client."""
        client = SecureShardingClient.create_local(
            directories=local_directories,
            threshold=3,
        )
        assert client.storage_mode == StorageMode.LOCAL
        assert len(client.backends) == 5
        assert client.distribution.threshold == 3

    def test_create_local_with_password(self, local_directories):
        """Test creating local client with pre-configured password."""
        client = SecureShardingClient.create_local(
            directories=local_directories,
            threshold=2,
            password="my-secure-password-12",
        )
        assert client.storage_mode == StorageMode.LOCAL

    def test_insufficient_directories(self, tmp_path):
        """Test that insufficient directories raises error."""
        dirs = [str(tmp_path / "shard1"), str(tmp_path / "shard2")]
        with pytest.raises(ConfigurationError):
            SecureShardingClient.create_local(
                directories=dirs,
                threshold=5,  # More than directories
            )

    def test_store_data(self, local_client):
        """Test storing data."""
        data = b"my secret data"
        password = "my-secure-password-12"

        result = local_client.store("test-key", data, password)

        assert isinstance(result, ShardResult)
        assert result.key == "test-key"
        assert result.success is True
        assert result.total_shares == 5
        assert result.threshold == 3
        assert len(result.stored_shards) >= 3

    def test_store_and_retrieve(self, local_client):
        """Test storing and retrieving data."""
        original_data = b"my secret data to store"
        password = "my-secure-password-12"

        local_client.store("test-key", original_data, password)
        retrieved_data = local_client.retrieve("test-key", password)

        assert retrieved_data == original_data

    def test_retrieve_with_wrong_password(self, local_client):
        """Test that wrong password raises DecryptionError."""
        local_client.store("test-key", b"data", "correct-password-12")

        with pytest.raises(DecryptionError):
            local_client.retrieve("test-key", "wrong-password-123")

    def test_store_non_bytes_raises_error(self, local_client):
        """Test that storing non-bytes raises TypeError."""
        with pytest.raises(TypeError):
            local_client.store("test-key", "not bytes", "password-12345")

    def test_short_password_raises_error(self, local_client):
        """Test that short password raises PasswordTooShortError."""
        with pytest.raises(PasswordTooShortError) as exc_info:
            local_client.store("test-key", b"data", "short")
        assert exc_info.value.min_length == 12

    def test_store_without_password_raises_error(self, local_client):
        """Test that storing without password raises error."""
        with pytest.raises(ConfigurationError):
            local_client.store("test-key", b"data")

    def test_list_keys(self, local_client):
        """Test listing stored keys."""
        password = "my-secure-password-12"

        local_client.store("key1", b"data1", password)
        local_client.store("key2", b"data2", password)
        local_client.store("secrets/key3", b"data3", password)

        keys = local_client.list_keys()

        assert "key1" in keys
        assert "key2" in keys
        assert "secrets/key3" in keys

    def test_delete_data(self, local_client):
        """Test deleting data."""
        password = "my-secure-password-12"
        local_client.store("test-key", b"data", password)

        result = local_client.delete("test-key")

        assert isinstance(result, DeletionResult)
        assert result.key == "test-key"
        assert len(result.deleted) > 0

        # Should no longer be in list
        assert "test-key" not in local_client.list_keys()

    def test_get_shard_status(self, local_client):
        """Test getting shard status."""
        password = "my-secure-password-12"
        local_client.store("test-key", b"data", password)

        status = local_client.get_shard_status("test-key")

        assert status["key"] == "test-key"
        assert status["threshold"] == 3
        assert status["total_shards"] == 5
        assert status["storage_mode"] == "local"
        assert status["can_reconstruct"] is True
        assert len(status["shards"]) == 5

    def test_store_with_metadata(self, local_client):
        """Test storing data with metadata."""
        password = "my-secure-password-12"
        metadata = {"environment": "test", "created_by": "test_suite"}

        result = local_client.store(
            "test-key",
            b"data",
            password,
            metadata=metadata,
        )

        assert result.success is True

    def test_integrity_verification(self, local_client):
        """Test that integrity verification works."""
        password = "my-secure-password-12"
        data = b"data to verify"

        local_client.store("test-key", data, password)
        retrieved = local_client.retrieve("test-key", password, verify_integrity=True)

        assert retrieved == data

    def test_large_data(self, local_client):
        """Test storing and retrieving large data."""
        password = "my-secure-password-12"
        large_data = b"x" * (100 * 1024)  # 100KB

        local_client.store("large-key", large_data, password)
        retrieved = local_client.retrieve("large-key", password)

        assert retrieved == large_data

    def test_binary_data(self, local_client):
        """Test storing and retrieving binary data."""
        password = "my-secure-password-12"
        binary_data = bytes(range(256))  # All byte values

        local_client.store("binary-key", binary_data, password)
        retrieved = local_client.retrieve("binary-key", password)

        assert retrieved == binary_data


class TestSecureShardingClientWithPasswordConfig:
    """Tests for SecureShardingClient with PasswordConfig."""

    @pytest.fixture
    def local_directories(self, tmp_path):
        """Create temporary directories for local storage."""
        dirs = []
        for i in range(4):
            d = tmp_path / f"shard{i}"
            d.mkdir()
            dirs.append(str(d))
        return dirs

    def test_store_with_password_config_single(self, local_directories):
        """Test storing with single password config."""
        client = SecureShardingClient.create_local(
            directories=local_directories,
            threshold=2,
        )
        passwords = PasswordConfig.single("my-secure-password-12")

        client.store("test-key", b"data", passwords)
        retrieved = client.retrieve("test-key", passwords)

        assert retrieved == b"data"

    def test_store_with_password_config_separate(self, local_directories):
        """Test storing with separate passwords config."""
        client = SecureShardingClient.create_local(
            directories=local_directories,
            threshold=2,
        )
        # For local mode, only local password is used
        passwords = PasswordConfig.separate(
            local="local-password-12",
            aws_account1="aws1-password-12",  # Not used in local mode
            aws_account2="aws2-password-12",  # Not used in local mode
        )

        client.store("test-key", b"data", passwords)
        retrieved = client.retrieve("test-key", passwords)

        assert retrieved == b"data"


class TestPartialShardRecovery:
    """Tests for recovering data with partial shards."""

    @pytest.fixture
    def local_directories(self, tmp_path):
        """Create temporary directories for local storage."""
        dirs = []
        for i in range(5):
            d = tmp_path / f"shard{i}"
            d.mkdir()
            dirs.append(str(d))
        return dirs

    def test_recover_with_threshold_shards(self, local_directories, tmp_path):
        """Test recovery when only threshold shards are available."""
        client = SecureShardingClient.create_local(
            directories=local_directories,
            threshold=3,
        )
        password = "my-secure-password-12"
        data = b"recoverable data"

        client.store("test-key", data, password)

        # Delete 2 shards (should still be able to recover with 3 remaining)
        for i in [0, 1]:
            shard_path = Path(local_directories[i]) / "test-key.shard0"
            if shard_path.exists():
                shard_path.unlink()

        # Should still work
        retrieved = client.retrieve("test-key", password)
        assert retrieved == data

    def test_insufficient_shards_raises_error(self, local_directories, tmp_path):
        """Test that insufficient shards raises InsufficientShardsError."""
        client = SecureShardingClient.create_local(
            directories=local_directories,
            threshold=3,
        )
        password = "my-secure-password-12"

        client.store("test-key", b"data", password)

        # Delete shards until below threshold
        for i, d in enumerate(local_directories):
            shard_file = Path(d) / f"test-key.shard{i}"
            if shard_file.exists():
                shard_file.unlink()
                if i >= 2:  # Keep deleting until insufficient
                    break

        # Now we should have fewer than 3 shards
        # Try to retrieve - this may or may not raise depending on which shards remain
        # Let's delete more to be sure
        for d in local_directories:
            for f in Path(d).glob("*.shard*"):
                f.unlink()

        with pytest.raises(InsufficientShardsError) as exc_info:
            client.retrieve("test-key", password)

        assert exc_info.value.available < exc_info.value.required


class TestStorageModeProperties:
    """Tests for storage mode properties."""

    def test_local_mode_properties(self, tmp_path):
        """Test local mode has correct properties."""
        dirs = [str(tmp_path / f"d{i}") for i in range(3)]
        client = SecureShardingClient.create_local(dirs, threshold=2)

        assert client.storage_mode == StorageMode.LOCAL
        assert len(client.local_backends) == 3
        assert len(client.s3_backends) == 0

    def test_distribution_access(self, tmp_path):
        """Test accessing distribution configuration."""
        dirs = [str(tmp_path / f"d{i}") for i in range(4)]
        client = SecureShardingClient.create_local(dirs, threshold=3)

        dist = client.distribution
        assert dist.total_shards == 4
        assert dist.threshold == 3
        assert dist.local_shards == 4

    def test_backends_access(self, tmp_path):
        """Test accessing backends list."""
        dirs = [str(tmp_path / f"d{i}") for i in range(3)]
        client = SecureShardingClient.create_local(dirs, threshold=2)

        backends = client.backends
        assert len(backends) == 3
