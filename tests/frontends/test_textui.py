"""
Tests for the Text-UI frontend application.
"""

import json
import pytest
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from frontends.textui.app import TextUIApp, main
from src.client import SecureShardingClient, StorageMode
from src.passwords import PasswordConfig
from src.exceptions import DecryptionError, InsufficientShardsError


class TestTextUIAppInitialization:
    """Tests for TextUIApp initialization."""

    def test_init_default_state(self):
        """Test that app initializes with correct default state."""
        app = TextUIApp()
        assert app.client is None
        assert app.config_path is None
        assert app.credential_store_path is None
        assert app._passwords is None

    def test_min_password_length(self):
        """Test that MIN_PASSWORD_LENGTH is set correctly."""
        app = TextUIApp()
        assert app.MIN_PASSWORD_LENGTH == 12


class TestTextUIAppHelperMethods:
    """Tests for TextUIApp helper methods."""

    @pytest.fixture
    def app(self):
        """Create a TextUIApp instance."""
        return TextUIApp()

    def test_get_threshold_valid(self, app):
        """Test getting valid threshold input."""
        with patch("builtins.input", return_value="3"):
            threshold = app._get_threshold(5)
            assert threshold == 3

    def test_get_threshold_default(self, app):
        """Test getting default threshold when empty input."""
        with patch("builtins.input", return_value=""):
            threshold = app._get_threshold(5)
            assert threshold == 3  # Default

    def test_get_threshold_too_low(self, app):
        """Test threshold validation for too low values."""
        with patch("builtins.input", side_effect=["1", "2"]):
            with patch("builtins.print"):  # Suppress output
                threshold = app._get_threshold(5)
                assert threshold == 2  # Second valid input

    def test_get_int_valid(self, app):
        """Test getting valid integer input."""
        with patch("builtins.input", return_value="5"):
            value = app._get_int("Test", default=3, min_val=1, max_val=10)
            assert value == 5

    def test_get_int_default(self, app):
        """Test getting default integer when empty input."""
        with patch("builtins.input", return_value=""):
            value = app._get_int("Test", default=7)
            assert value == 7

    def test_get_int_min_validation(self, app):
        """Test integer minimum validation."""
        with patch("builtins.input", side_effect=["0", "5"]):
            with patch("builtins.print"):
                value = app._get_int("Test", default=3, min_val=1)
                assert value == 5

    def test_get_int_max_validation(self, app):
        """Test integer maximum validation."""
        with patch("builtins.input", side_effect=["15", "8"]):
            with patch("builtins.print"):
                value = app._get_int("Test", default=3, max_val=10)
                assert value == 8

    def test_get_aws_config(self, app):
        """Test getting AWS configuration."""
        inputs = [
            "my-bucket",      # bucket
            "us-east-1",      # region
            "my-profile",     # profile
            "",               # role_arn (empty)
            "custom/prefix/", # prefix
        ]
        with patch("builtins.input", side_effect=inputs):
            config = app._get_aws_config("Test Account")

        assert config["bucket"] == "my-bucket"
        assert config["region"] == "us-east-1"
        assert config["profile_name"] == "my-profile"
        assert "role_arn" not in config
        assert config["prefix"] == "custom/prefix/"


class TestTextUIAppLocalConfiguration:
    """Tests for local storage configuration."""

    @pytest.fixture
    def app(self):
        """Create a TextUIApp instance."""
        return TextUIApp()

    @pytest.fixture
    def temp_dirs(self, tmp_path):
        """Create temporary directories."""
        dirs = []
        for i in range(3):
            d = tmp_path / f"shard{i}"
            d.mkdir()
            dirs.append(str(d))
        return dirs

    def test_configure_local_success(self, app, temp_dirs):
        """Test successful local configuration."""
        inputs = [
            temp_dirs[0],  # dir 1
            temp_dirs[1],  # dir 2
            temp_dirs[2],  # dir 3
            "",            # done entering dirs
            "2",           # threshold
            "my-password-12345",  # password
            "my-password-12345",  # confirm
        ]
        with patch("builtins.input", side_effect=inputs):
            with patch("getpass.getpass", side_effect=["my-password-12345", "my-password-12345"]):
                with patch("builtins.print"):
                    app._configure_local()

        assert app.client is not None
        assert app.client.storage_mode == StorageMode.LOCAL
        assert len(app.client.backends) == 3


class TestTextUIAppDataOperations:
    """Tests for data operations."""

    @pytest.fixture
    def app_with_client(self, tmp_path):
        """Create an app with a configured local client."""
        app = TextUIApp()
        dirs = []
        for i in range(3):
            d = tmp_path / f"shard{i}"
            d.mkdir()
            dirs.append(str(d))

        app.client = SecureShardingClient.create_local(
            directories=dirs,
            threshold=2,
            password="test-password-12",
        )
        app._passwords = PasswordConfig.single("test-password-12")
        return app

    def test_store_data_text_input(self, app_with_client):
        """Test storing data via text input."""
        inputs = [
            "test-key",     # key
            "1",            # text input
            "Hello World",  # data
            "Y",            # use configured passwords
            "n",            # no metadata
        ]
        with patch("builtins.input", side_effect=inputs):
            with patch("builtins.print") as mock_print:
                app_with_client._store_data()

        # Check that success message was printed
        call_args = [str(c) for c in mock_print.call_args_list]
        assert any("OK" in str(c) for c in call_args)

    def test_store_data_from_file(self, app_with_client, tmp_path):
        """Test storing data from file."""
        # Create a test file
        test_file = tmp_path / "test_data.txt"
        test_file.write_bytes(b"File content to store")

        inputs = [
            "file-key",           # key
            "2",                  # file input
            str(test_file),       # file path
            "Y",                  # use configured passwords
            "n",                  # no metadata
        ]
        with patch("builtins.input", side_effect=inputs):
            with patch("builtins.print"):
                app_with_client._store_data()

        # Verify data was stored
        assert "file-key" in app_with_client.client.list_keys()

    def test_retrieve_data_display_text(self, app_with_client):
        """Test retrieving and displaying data as text."""
        # First store some data
        app_with_client.client.store(
            "retrieve-key",
            b"Data to retrieve",
            app_with_client._passwords,
        )

        inputs = [
            "retrieve-key",  # key
            "Y",             # use configured passwords
            "1",             # display as text
        ]
        with patch("builtins.input", side_effect=inputs):
            with patch("builtins.print") as mock_print:
                app_with_client._retrieve_data()

        # Check output contains the data
        call_args = [str(c) for c in mock_print.call_args_list]
        assert any("Data to retrieve" in str(c) for c in call_args)

    def test_list_keys(self, app_with_client):
        """Test listing stored keys."""
        # Store some data
        password = app_with_client._passwords
        app_with_client.client.store("key1", b"data1", password)
        app_with_client.client.store("key2", b"data2", password)

        with patch("builtins.print") as mock_print:
            app_with_client._list_keys()

        call_args = [str(c) for c in mock_print.call_args_list]
        assert any("key1" in str(c) for c in call_args)
        assert any("key2" in str(c) for c in call_args)

    def test_check_status(self, app_with_client):
        """Test checking shard status."""
        app_with_client.client.store(
            "status-key",
            b"data",
            app_with_client._passwords,
        )

        inputs = ["status-key"]
        with patch("builtins.input", side_effect=inputs):
            with patch("builtins.print") as mock_print:
                app_with_client._check_status()

        call_args = [str(c) for c in mock_print.call_args_list]
        assert any("status-key" in str(c) for c in call_args)
        assert any("Threshold" in str(c) for c in call_args)

    def test_delete_data(self, app_with_client):
        """Test deleting data."""
        app_with_client.client.store(
            "delete-key",
            b"data to delete",
            app_with_client._passwords,
        )

        inputs = [
            "delete-key",  # key
            "y",           # confirm
            "Y",           # secure delete
        ]
        with patch("builtins.input", side_effect=inputs):
            with patch("builtins.print"):
                app_with_client._delete_data()

        # Verify deletion
        assert "delete-key" not in app_with_client.client.list_keys()


class TestTextUIAppPasswordConfiguration:
    """Tests for password configuration."""

    @pytest.fixture
    def app(self):
        """Create a TextUIApp instance."""
        return TextUIApp()

    def test_configure_passwords_single_mode(self, app):
        """Test configuring single password mode."""
        inputs = ["1"]  # Single mode
        with patch("builtins.input", side_effect=inputs):
            with patch("getpass.getpass", side_effect=["my-password-12345", "my-password-12345"]):
                with patch("builtins.print"):
                    passwords = app._configure_passwords(has_local=True)

        assert passwords.mode.value == "single"

    def test_configure_passwords_separate_mode(self, app):
        """Test configuring separate passwords mode."""
        inputs = ["2"]  # Separate mode
        password_inputs = [
            "local-password-12",
            "local-password-12",
            "aws1-password-123",
            "aws1-password-123",
            "aws2-password-123",
            "aws2-password-123",
        ]
        with patch("builtins.input", side_effect=inputs):
            with patch("getpass.getpass", side_effect=password_inputs):
                with patch("builtins.print"):
                    passwords = app._configure_passwords(has_local=True)

        assert passwords.mode.value == "separate"
        storage_pwds = passwords.get_passwords()
        assert storage_pwds.local == "local-password-12"
        assert storage_pwds.aws_account1 == "aws1-password-123"

    def test_configure_passwords_prefix_suffix_mode(self, app):
        """Test configuring prefix+suffix mode."""
        inputs = [
            "3",               # prefix_suffix mode
            "company-2024-",   # prefix
            "local-suffix",    # local suffix
            "aws1-suffix-x",   # aws1 suffix
            "aws2-suffix-y",   # aws2 suffix
        ]
        with patch("builtins.input", side_effect=inputs):
            with patch("builtins.print"):
                passwords = app._configure_passwords(has_local=True)

        assert passwords.mode.value == "prefix_suffix"
        storage_pwds = passwords.get_passwords()
        assert storage_pwds.local == "company-2024-local-suffix"


class TestTextUIAppLoadConfig:
    """Tests for loading configuration."""

    @pytest.fixture
    def app(self):
        """Create a TextUIApp instance."""
        return TextUIApp()

    def test_load_local_config(self, app, tmp_path):
        """Test loading a local storage configuration."""
        # Create directories
        dirs = []
        for i in range(3):
            d = tmp_path / f"shard{i}"
            d.mkdir()
            dirs.append(str(d))

        # Create config file
        config = {
            "storage_mode": "local",
            "directories": dirs,
            "threshold": 2,
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        # Mock password input
        password_inputs = ["my-password-12345", "my-password-12345"]
        with patch("builtins.input", return_value="1"):  # Single password mode
            with patch("getpass.getpass", side_effect=password_inputs):
                with patch("builtins.print"):
                    app._load_config(config_file)

        assert app.client is not None
        assert app.client.storage_mode == StorageMode.LOCAL

    def test_load_nonexistent_config(self, app, tmp_path):
        """Test loading nonexistent configuration file."""
        with patch("builtins.print") as mock_print:
            app._load_config(tmp_path / "nonexistent.json")

        call_args = [str(c) for c in mock_print.call_args_list]
        assert any("ERROR" in str(c) for c in call_args)


class TestTextUIAppCredentialManagement:
    """Tests for credential management."""

    @pytest.fixture
    def app(self):
        """Create a TextUIApp instance."""
        return TextUIApp()

    def test_list_credentials_empty(self, app, tmp_path):
        """Test listing credentials when none exist."""
        inputs = [str(tmp_path / "creds")]
        with patch("builtins.input", side_effect=inputs):
            with patch("builtins.print") as mock_print:
                app._list_credentials()

        call_args = [str(c) for c in mock_print.call_args_list]
        # Should indicate no credentials or not found
        assert any("No" in str(c) for c in call_args) or any("not" in str(c).lower() for c in call_args)


class TestMainFunction:
    """Tests for the main entry point."""

    def test_main_exit_immediately(self):
        """Test that main exits cleanly when 0 is selected."""
        with patch("builtins.input", return_value="0"):
            with patch("builtins.print"):
                with patch("sys.argv", ["app"]):
                    main()

    def test_main_keyboard_interrupt(self):
        """Test handling of keyboard interrupt."""
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            with patch("builtins.print"):
                with patch("sys.exit") as mock_exit:
                    with patch("sys.argv", ["app"]):
                        main()
                    mock_exit.assert_called_once_with(0)


class TestTextUIAppErrorHandling:
    """Tests for error handling in TextUIApp."""

    @pytest.fixture
    def app_with_client(self, tmp_path):
        """Create an app with a configured local client."""
        app = TextUIApp()
        dirs = []
        for i in range(3):
            d = tmp_path / f"shard{i}"
            d.mkdir()
            dirs.append(str(d))

        app.client = SecureShardingClient.create_local(
            directories=dirs,
            threshold=2,
            password="test-password-12",
        )
        return app

    def test_store_no_client(self):
        """Test storing without configured client."""
        app = TextUIApp()
        with patch("builtins.print") as mock_print:
            app._store_data()

        call_args = [str(c) for c in mock_print.call_args_list]
        assert any("ERROR" in str(c) for c in call_args)

    def test_retrieve_no_client(self):
        """Test retrieving without configured client."""
        app = TextUIApp()
        with patch("builtins.print") as mock_print:
            app._retrieve_data()

        call_args = [str(c) for c in mock_print.call_args_list]
        assert any("ERROR" in str(c) for c in call_args)

    def test_list_keys_no_client(self):
        """Test listing keys without configured client."""
        app = TextUIApp()
        with patch("builtins.print") as mock_print:
            app._list_keys()

        call_args = [str(c) for c in mock_print.call_args_list]
        assert any("ERROR" in str(c) for c in call_args)

    def test_store_cancelled(self, app_with_client):
        """Test store operation when cancelled."""
        inputs = [""]  # Empty key cancels
        with patch("builtins.input", side_effect=inputs):
            with patch("builtins.print") as mock_print:
                app_with_client._store_data()

        call_args = [str(c) for c in mock_print.call_args_list]
        assert any("Cancelled" in str(c) for c in call_args)

    def test_retrieve_cancelled(self, app_with_client):
        """Test retrieve operation when cancelled."""
        inputs = [""]  # Empty key cancels
        with patch("builtins.input", side_effect=inputs):
            with patch("builtins.print") as mock_print:
                app_with_client._retrieve_data()

        call_args = [str(c) for c in mock_print.call_args_list]
        assert any("Cancelled" in str(c) for c in call_args)
