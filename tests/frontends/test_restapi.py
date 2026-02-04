"""
Tests for the REST API frontend.
"""

import base64
import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from fastapi.testclient import TestClient

from frontends.restapi.app import app, app_state


@pytest.fixture(autouse=True)
def reset_app_state():
    """Reset application state before each test."""
    app_state.reset()
    yield
    app_state.reset()


@pytest.fixture
def client():
    """Create a test client."""
    return TestClient(app)


@pytest.fixture
def temp_directories(tmp_path):
    """Create temporary directories for testing."""
    dirs = []
    for i in range(3):
        d = tmp_path / f"shard{i}"
        d.mkdir()
        dirs.append(str(d))
    return dirs


class TestHealthEndpoints:
    """Tests for health and status endpoints."""

    def test_health_check(self, client):
        """Test health endpoint returns ok."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert data["configured"] is False

    def test_status_unconfigured(self, client):
        """Test status when not configured."""
        response = client.get("/api/status")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "unconfigured"

    def test_reset_configuration(self, client):
        """Test reset endpoint."""
        response = client.post("/api/reset")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"


class TestLocalConfiguration:
    """Tests for local storage configuration."""

    def test_configure_local_success(self, client, temp_directories):
        """Test successful local configuration."""
        response = client.post(
            "/api/config/local",
            json={
                "directories": temp_directories,
                "threshold": 2,
                "passwords": {
                    "mode": "single",
                    "password": "test-password-12",
                },
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "ok"
        assert data["storage_mode"] == "local"
        assert data["total_shards"] == 3
        assert data["threshold"] == 2
        assert data["local_shards"] == 3

    def test_configure_local_too_few_directories(self, client, tmp_path):
        """Test configuration with too few directories."""
        single_dir = [str(tmp_path / "single")]
        response = client.post(
            "/api/config/local",
            json={
                "directories": single_dir,
                "threshold": 2,
            },
        )
        assert response.status_code == 422  # Validation error

    def test_health_after_config(self, client, temp_directories):
        """Test health endpoint after configuration."""
        # Configure first
        client.post(
            "/api/config/local",
            json={
                "directories": temp_directories,
                "threshold": 2,
                "passwords": {"mode": "single", "password": "test-password-12"},
            },
        )

        # Check health
        response = client.get("/health")
        data = response.json()
        assert data["configured"] is True
        assert data["storage_mode"] == "local"


class TestDataOperations:
    """Tests for data CRUD operations."""

    @pytest.fixture
    def configured_client(self, client, temp_directories):
        """Return a client with local storage configured."""
        client.post(
            "/api/config/local",
            json={
                "directories": temp_directories,
                "threshold": 2,
                "passwords": {"mode": "single", "password": "test-password-12"},
            },
        )
        return client

    def test_store_data(self, configured_client):
        """Test storing data."""
        response = configured_client.post(
            "/api/data/test-key",
            json={
                "data": "Hello, World!",
                "password": "test-password-12",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "ok"
        assert data["key"] == "test-key"
        assert data["stored_shards"] >= 2

    def test_store_data_base64(self, configured_client):
        """Test storing base64-encoded data."""
        binary_data = bytes(range(256))
        encoded = base64.b64encode(binary_data).decode("ascii")

        response = configured_client.post(
            "/api/data/binary-key",
            json={
                "data": encoded,
                "password": "test-password-12",
                "is_base64": True,
            },
        )
        assert response.status_code == 201

    def test_retrieve_data(self, configured_client):
        """Test retrieving data."""
        # Store first
        configured_client.post(
            "/api/data/retrieve-test",
            json={
                "data": "Secret data",
                "password": "test-password-12",
            },
        )

        # Retrieve
        response = configured_client.post(
            "/api/data/retrieve-test/retrieve",
            json={"password": "test-password-12"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

        # Decode and verify
        retrieved = base64.b64decode(data["data"]).decode("utf-8")
        assert retrieved == "Secret data"

    def test_retrieve_wrong_password(self, configured_client):
        """Test retrieval with wrong password fails."""
        # Store
        configured_client.post(
            "/api/data/wrong-pwd-test",
            json={
                "data": "Secret",
                "password": "correct-password",
            },
        )

        # Try to retrieve with wrong password
        response = configured_client.post(
            "/api/data/wrong-pwd-test/retrieve",
            json={"password": "wrong-password-12"},
        )
        assert response.status_code == 401

    def test_list_keys(self, configured_client):
        """Test listing keys."""
        # Store some data
        for key in ["key1", "key2", "nested/key3"]:
            configured_client.post(
                f"/api/data/{key}",
                json={
                    "data": f"Data for {key}",
                    "password": "test-password-12",
                },
            )

        # List
        response = configured_client.get("/api/keys")
        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 3
        assert "key1" in data["keys"]
        assert "key2" in data["keys"]
        assert "nested/key3" in data["keys"]

    def test_delete_data(self, configured_client):
        """Test deleting data."""
        # Store
        configured_client.post(
            "/api/data/delete-test",
            json={
                "data": "To be deleted",
                "password": "test-password-12",
            },
        )

        # Delete
        response = configured_client.delete(
            "/api/data/delete-test",
            json={"secure": True},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["deleted_count"] >= 2

        # Verify deletion
        list_response = configured_client.get("/api/keys")
        assert "delete-test" not in list_response.json()["keys"]

    def test_shard_status(self, configured_client):
        """Test getting shard status."""
        # Store
        configured_client.post(
            "/api/data/status-test",
            json={
                "data": "Status test data",
                "password": "test-password-12",
            },
        )

        # Get status
        response = configured_client.get("/api/data/status-test/status")
        assert response.status_code == 200
        data = response.json()
        assert data["key"] == "status-test"
        assert data["can_reconstruct"] is True
        assert data["storage_mode"] == "local"
        assert len(data["shards"]) == 3


class TestDataOperationsWithoutConfig:
    """Tests for data operations without configuration."""

    def test_list_keys_not_configured(self, client):
        """Test list keys returns 409 when not configured."""
        response = client.get("/api/keys")
        assert response.status_code == 409

    def test_store_data_not_configured(self, client):
        """Test store returns 409 when not configured."""
        response = client.post(
            "/api/data/test",
            json={"data": "test", "password": "test-password-12"},
        )
        assert response.status_code == 409


class TestPasswordModes:
    """Tests for different password configuration modes."""

    def test_separate_passwords(self, client, temp_directories):
        """Test configuration with separate passwords."""
        response = client.post(
            "/api/config/local",
            json={
                "directories": temp_directories,
                "threshold": 2,
                "passwords": {
                    "mode": "separate",
                    "local_password": "local-password-12",
                    "aws1_password": "aws1-password-123",
                    "aws2_password": "aws2-password-123",
                },
            },
        )
        assert response.status_code == 201

    def test_prefix_suffix_passwords(self, client, temp_directories):
        """Test configuration with prefix+suffix passwords."""
        response = client.post(
            "/api/config/local",
            json={
                "directories": temp_directories,
                "threshold": 2,
                "passwords": {
                    "mode": "prefix_suffix",
                    "prefix": "company-2024-",
                    "local_suffix": "local-abc",
                    "aws1_suffix": "aws1-defgh",
                    "aws2_suffix": "aws2-ijklm",
                },
            },
        )
        assert response.status_code == 201


class TestCredentialEndpoints:
    """Tests for credential management endpoints."""

    def test_list_credentials_no_path(self, client):
        """Test list credentials without store path."""
        response = client.get("/api/credentials")
        assert response.status_code == 400

    def test_list_credentials_empty(self, client, tmp_path):
        """Test list credentials when empty."""
        store_path = str(tmp_path / "credentials")
        response = client.get(f"/api/credentials?store_path={store_path}")
        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 0

    def test_store_credentials(self, client, tmp_path):
        """Test storing credentials."""
        store_path = str(tmp_path / "credentials")
        response = client.post(
            f"/api/credentials?store_path={store_path}",
            json={
                "account_id": "test-account",
                "credentials": {
                    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE",
                    "region": "us-east-1",
                },
                "password": "credential-password-12",
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["account_id"] == "test-account"

    def test_load_credentials(self, client, tmp_path):
        """Test loading credentials."""
        store_path = str(tmp_path / "credentials")

        # Store first
        client.post(
            f"/api/credentials?store_path={store_path}",
            json={
                "account_id": "load-test",
                "credentials": {
                    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE",
                },
                "password": "credential-password-12",
            },
        )

        # Load
        response = client.post(
            f"/api/credentials/load-test?store_path={store_path}",
            json={"password": "credential-password-12"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["account_id"] == "load-test"
        assert data["access_key_id_prefix"].startswith("AKIAIОСF")  # First 8 chars

    def test_delete_credentials(self, client, tmp_path):
        """Test deleting credentials."""
        store_path = str(tmp_path / "credentials")

        # Store
        client.post(
            f"/api/credentials?store_path={store_path}",
            json={
                "account_id": "delete-test",
                "credentials": {
                    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE",
                },
                "password": "credential-password-12",
            },
        )

        # Delete
        response = client.delete(
            f"/api/credentials/delete-test?store_path={store_path}"
        )
        assert response.status_code == 200


class TestErrorHandling:
    """Tests for error handling."""

    def test_password_too_short(self, client, temp_directories):
        """Test that short password returns 400."""
        response = client.post(
            "/api/config/local",
            json={
                "directories": temp_directories,
                "threshold": 2,
                "passwords": {"mode": "single", "password": "short"},
            },
        )
        assert response.status_code == 422  # Pydantic validation

    def test_store_without_password(self, client, temp_directories):
        """Test store without password returns 400."""
        # Configure without default password
        client.post(
            "/api/config/local",
            json={
                "directories": temp_directories,
                "threshold": 2,
            },
        )

        # Try to store without password
        response = client.post(
            "/api/data/test",
            json={"data": "test"},
        )
        assert response.status_code == 400

    def test_credential_not_found(self, client, tmp_path):
        """Test loading nonexistent credentials returns 404."""
        store_path = str(tmp_path / "credentials")
        Path(store_path).mkdir(parents=True, exist_ok=True)

        response = client.post(
            f"/api/credentials/nonexistent?store_path={store_path}",
            json={"password": "test-password-12"},
        )
        assert response.status_code == 400  # ConfigurationError -> 400


class TestMetadata:
    """Tests for metadata handling."""

    def test_store_with_metadata(self, client, temp_directories):
        """Test storing data with metadata."""
        client.post(
            "/api/config/local",
            json={
                "directories": temp_directories,
                "threshold": 2,
                "passwords": {"mode": "single", "password": "test-password-12"},
            },
        )

        response = client.post(
            "/api/data/metadata-test",
            json={
                "data": "Data with metadata",
                "password": "test-password-12",
                "metadata": {
                    "environment": "test",
                    "created_by": "test_suite",
                },
            },
        )
        assert response.status_code == 201
