"""
Text-UI Frontend for Text File Manager.

This module provides an interactive command-line interface for the
secure sharding backend. Users can configure storage, store/retrieve
encrypted data, and manage AWS credentials.

Usage:
    python -m frontends.textui.app

    Or with a configuration file:
    python -m frontends.textui.app --config /path/to/config.json
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src import (
    AWSCredentials,
    ConfigurationError,
    CredentialStore,
    DecryptionError,
    InsufficientShardsError,
    IntegrityError,
    PasswordConfig,
    PasswordTooShortError,
    SecureShardingClient,
    ShardManagerError,
    StorageMode,
)

if TYPE_CHECKING:
    from typing import Any


__all__ = ["TextUIApp", "main"]


class TextUIApp:
    """
    Interactive text-based UI for managing encrypted sharded data.

    Provides a menu-driven interface for:
    - Configuring storage backends (local, cloud, hybrid)
    - Storing and retrieving encrypted data
    - Managing AWS credentials
    - Viewing shard status

    Attributes:
        client: The configured SecureShardingClient instance.
        config_path: Path to configuration file (if loaded).
        credential_store_path: Path to encrypted credential storage.
    """

    MIN_PASSWORD_LENGTH = 12

    def __init__(self) -> None:
        """Initialize the Text UI application."""
        self.client: SecureShardingClient | None = None
        self.config_path: Path | None = None
        self.credential_store_path: Path | None = None
        self._passwords: PasswordConfig | None = None

    def run(self, config_path: str | None = None) -> None:
        """
        Run the interactive text UI.

        Args:
            config_path: Optional path to a configuration file.
        """
        self._print_header()

        if config_path:
            self._load_config(Path(config_path))

        self._main_menu()

    def _print_header(self) -> None:
        """Print the application header."""
        print("\n" + "=" * 60)
        print("  TEXT FILE MANAGER - Secure Encrypted Sharding")
        print("=" * 60)
        print("  ChaCha20-Poly1305 encryption with Shamir's Secret Sharing")
        print("  Per-location password support for local and cloud storage")
        print("=" * 60 + "\n")

    def _main_menu(self) -> None:
        """Display and handle the main menu."""
        while True:
            print("\n" + "-" * 40)
            print("MAIN MENU")
            print("-" * 40)

            if self.client:
                print(f"  [Active: {self.client.storage_mode.value} mode]")
            else:
                print("  [No storage configured]")

            print("\nConfiguration:")
            print("  1. Configure Local Storage")
            print("  2. Configure Cloud Storage (2 AWS Accounts)")
            print("  3. Configure Hybrid Storage (Local + Cloud)")
            print("  4. Load Existing Configuration")

            if self.client:
                print("\nData Operations:")
                print("  5. Store Data")
                print("  6. Retrieve Data")
                print("  7. List Stored Keys")
                print("  8. Check Shard Status")
                print("  9. Delete Data")

            print("\nCredentials:")
            print("  10. Manage AWS Credentials")

            print("\n  0. Exit")
            print("-" * 40)

            choice = input("Select option: ").strip()

            if choice == "0":
                print("\nGoodbye!")
                break
            elif choice == "1":
                self._configure_local()
            elif choice == "2":
                self._configure_cloud()
            elif choice == "3":
                self._configure_hybrid()
            elif choice == "4":
                self._load_config_interactive()
            elif choice == "5" and self.client:
                self._store_data()
            elif choice == "6" and self.client:
                self._retrieve_data()
            elif choice == "7" and self.client:
                self._list_keys()
            elif choice == "8" and self.client:
                self._check_status()
            elif choice == "9" and self.client:
                self._delete_data()
            elif choice == "10":
                self._manage_credentials()
            else:
                print("\nInvalid option. Please try again.")

    # -------------------------------------------------------------------------
    # Configuration Methods
    # -------------------------------------------------------------------------

    def _configure_local(self) -> None:
        """Configure local storage mode."""
        print("\n" + "=" * 40)
        print("CONFIGURE LOCAL STORAGE")
        print("=" * 40)

        print("\nEnter local directories for shard storage.")
        print("Each shard will be stored in a separate directory.")
        print("Enter blank line when done (minimum 2 directories).\n")

        directories: list[str] = []
        while True:
            prompt = f"Directory {len(directories) + 1}: "
            dir_path = input(prompt).strip()

            if not dir_path:
                if len(directories) < 2:
                    print("  Need at least 2 directories. Please continue.")
                    continue
                break

            # Expand path and validate
            dir_path = os.path.expanduser(dir_path)
            directories.append(dir_path)

        # Get threshold
        print(f"\nYou have {len(directories)} directories.")
        threshold = self._get_threshold(len(directories))

        # Get password
        password = self._get_password("Enter encryption password")

        try:
            self.client = SecureShardingClient.create_local(
                directories=directories,
                threshold=threshold,
                password=password,
            )
            self._passwords = PasswordConfig.single(password)
            print(f"\n[OK] Local storage configured with {len(directories)} locations")
            print(f"     Threshold: {threshold} shards required for reconstruction")
        except Exception as e:
            print(f"\n[ERROR] Configuration failed: {e}")

    def _configure_cloud(self) -> None:
        """Configure cloud storage mode with 2 AWS accounts."""
        print("\n" + "=" * 40)
        print("CONFIGURE CLOUD STORAGE")
        print("=" * 40)
        print("\nThis mode stores shards across 2 AWS S3 accounts.\n")

        # AWS Account 1
        print("--- AWS Account 1 ---")
        aws1_config = self._get_aws_config("Account 1")
        aws1_creds = self._get_aws_credentials("Account 1")
        account1_shards = self._get_int("Number of shards in Account 1", default=3, min_val=1)

        # AWS Account 2
        print("\n--- AWS Account 2 ---")
        aws2_config = self._get_aws_config("Account 2")
        aws2_creds = self._get_aws_credentials("Account 2")
        account2_shards = self._get_int("Number of shards in Account 2", default=2, min_val=1)

        total_shards = account1_shards + account2_shards
        threshold = self._get_threshold(total_shards)

        # Password configuration
        passwords = self._configure_passwords(has_local=False)

        # Credential store path
        self.credential_store_path = self._get_credential_store_path()

        try:
            self.client = SecureShardingClient.create_cloud(
                aws_account1_config=aws1_config,
                aws_account2_config=aws2_config,
                threshold=threshold,
                account1_shards=account1_shards,
                account2_shards=account2_shards,
                aws_account1_credentials=aws1_creds,
                aws_account2_credentials=aws2_creds,
                passwords=passwords,
                credential_store_path=self.credential_store_path,
            )
            self._passwords = passwords
            print(f"\n[OK] Cloud storage configured")
            print(f"     {account1_shards} shards in Account 1, {account2_shards} in Account 2")
            print(f"     Threshold: {threshold} shards required for reconstruction")
        except Exception as e:
            print(f"\n[ERROR] Configuration failed: {e}")

    def _configure_hybrid(self) -> None:
        """Configure hybrid storage mode (local + 2 AWS accounts)."""
        print("\n" + "=" * 40)
        print("CONFIGURE HYBRID STORAGE")
        print("=" * 40)
        print("\nThis mode distributes shards across local storage and 2 AWS accounts.")
        print("Security: No single storage type can reconstruct data alone.\n")

        # Local directories
        print("--- Local Storage ---")
        directories: list[str] = []
        print("Enter local directories (minimum 1):")
        while True:
            dir_path = input(f"Directory {len(directories) + 1}: ").strip()
            if not dir_path:
                if len(directories) < 1:
                    print("  Need at least 1 local directory.")
                    continue
                break
            directories.append(os.path.expanduser(dir_path))

        local_shards = self._get_int(
            "Number of local shards",
            default=len(directories),
            min_val=1,
            max_val=len(directories)
        )

        # AWS Account 1
        print("\n--- AWS Account 1 ---")
        aws1_config = self._get_aws_config("Account 1")
        aws1_creds = self._get_aws_credentials("Account 1")
        account1_shards = self._get_int("Number of shards in Account 1", default=2, min_val=1)

        # AWS Account 2
        print("\n--- AWS Account 2 ---")
        aws2_config = self._get_aws_config("Account 2")
        aws2_creds = self._get_aws_credentials("Account 2")
        account2_shards = self._get_int("Number of shards in Account 2", default=2, min_val=1)

        # Password configuration
        passwords = self._configure_passwords(has_local=True)

        # Credential store path
        self.credential_store_path = self._get_credential_store_path()

        try:
            self.client = SecureShardingClient.create_hybrid(
                local_directories=directories,
                aws_account1_config=aws1_config,
                aws_account2_config=aws2_config,
                local_shards=local_shards,
                account1_shards=account1_shards,
                account2_shards=account2_shards,
                aws_account1_credentials=aws1_creds,
                aws_account2_credentials=aws2_creds,
                passwords=passwords,
                credential_store_path=self.credential_store_path,
            )
            self._passwords = passwords

            dist = self.client.distribution
            print(f"\n[OK] Hybrid storage configured")
            print(f"     Local: {dist.local_shards} shards")
            print(f"     AWS-1: {dist.cloud_account1_shards} shards")
            print(f"     AWS-2: {dist.cloud_account2_shards} shards")
            print(f"     Threshold: {dist.threshold} shards (need 2+ storage types)")
        except ConfigurationError as e:
            print(f"\n[ERROR] Configuration failed: {e}")
        except Exception as e:
            print(f"\n[ERROR] Unexpected error: {e}")

    def _load_config_interactive(self) -> None:
        """Load configuration from a file interactively."""
        print("\n" + "=" * 40)
        print("LOAD CONFIGURATION")
        print("=" * 40)

        config_path = input("\nConfiguration file path: ").strip()
        if not config_path:
            print("Cancelled.")
            return

        self._load_config(Path(os.path.expanduser(config_path)))

    def _load_config(self, config_path: Path) -> None:
        """Load configuration from a JSON file."""
        try:
            if not config_path.exists():
                print(f"\n[ERROR] Configuration file not found: {config_path}")
                return

            with open(config_path) as f:
                config = json.load(f)

            mode = StorageMode(config.get("storage_mode", "local"))

            # Get passwords
            passwords = self._configure_passwords(
                has_local=(mode != StorageMode.CLOUD)
            )

            if mode == StorageMode.LOCAL:
                self.client = SecureShardingClient.create_local(
                    directories=config["directories"],
                    threshold=config.get("threshold", 3),
                    password=passwords.get_password("local"),
                )
            elif mode == StorageMode.CLOUD:
                self.client = SecureShardingClient.load_with_credentials(
                    credential_store_path=config["credential_store_path"],
                    passwords=passwords,
                    aws_account1_config=config["aws_account1"],
                    aws_account2_config=config["aws_account2"],
                    storage_mode=StorageMode.CLOUD,
                    account1_shards=config.get("account1_shards", 3),
                    account2_shards=config.get("account2_shards", 2),
                )
            else:  # HYBRID
                self.client = SecureShardingClient.load_with_credentials(
                    credential_store_path=config["credential_store_path"],
                    passwords=passwords,
                    local_directories=config["local_directories"],
                    aws_account1_config=config["aws_account1"],
                    aws_account2_config=config["aws_account2"],
                    storage_mode=StorageMode.HYBRID,
                    local_shards=config.get("local_shards"),
                    account1_shards=config.get("account1_shards"),
                    account2_shards=config.get("account2_shards"),
                )

            self._passwords = passwords
            self.config_path = config_path
            print(f"\n[OK] Configuration loaded from {config_path}")
            print(f"     Storage mode: {mode.value}")

        except json.JSONDecodeError as e:
            print(f"\n[ERROR] Invalid JSON in config file: {e}")
        except KeyError as e:
            print(f"\n[ERROR] Missing required config key: {e}")
        except Exception as e:
            print(f"\n[ERROR] Failed to load configuration: {e}")

    # -------------------------------------------------------------------------
    # Data Operations
    # -------------------------------------------------------------------------

    def _store_data(self) -> None:
        """Store encrypted data."""
        if not self.client:
            print("\n[ERROR] No storage configured")
            return

        print("\n" + "=" * 40)
        print("STORE DATA")
        print("=" * 40)

        # Get key
        key = input("\nStorage key (e.g., 'secrets/api-key'): ").strip()
        if not key:
            print("Cancelled.")
            return

        # Get data source
        print("\nData source:")
        print("  1. Enter text directly")
        print("  2. Read from file")
        choice = input("Select [1/2]: ").strip()

        data: bytes
        if choice == "2":
            file_path = input("File path: ").strip()
            file_path = os.path.expanduser(file_path)
            try:
                with open(file_path, "rb") as f:
                    data = f.read()
                print(f"  Read {len(data)} bytes from file")
            except Exception as e:
                print(f"\n[ERROR] Failed to read file: {e}")
                return
        else:
            text = input("Enter data: ")
            data = text.encode("utf-8")

        # Get password (or use configured)
        password: str | PasswordConfig | None = None
        if self._passwords:
            use_configured = input("\nUse configured passwords? [Y/n]: ").strip().lower()
            if use_configured != "n":
                password = self._passwords

        if not password:
            password = self._get_password("Encryption password")

        # Optional metadata
        metadata: dict[str, str] | None = None
        add_metadata = input("\nAdd metadata? [y/N]: ").strip().lower()
        if add_metadata == "y":
            metadata = {}
            print("Enter key=value pairs (blank line to finish):")
            while True:
                line = input("  ").strip()
                if not line:
                    break
                if "=" in line:
                    k, v = line.split("=", 1)
                    metadata[k.strip()] = v.strip()

        # Store
        try:
            result = self.client.store(key, data, password, metadata)
            print(f"\n[OK] Data stored successfully")
            print(f"     Key: {result.key}")
            print(f"     Shards: {result.total_shares} total, {result.threshold} required")
            print(f"     Hash: {result.data_hash[:16]}...")
            print(f"     Mode: {result.storage_mode.value}")
        except PasswordTooShortError as e:
            print(f"\n[ERROR] Password too short (minimum {e.min_length} characters)")
        except InsufficientShardsError as e:
            print(f"\n[ERROR] Could only store {e.available}/{e.required} required shards")
        except Exception as e:
            print(f"\n[ERROR] Storage failed: {e}")

    def _retrieve_data(self) -> None:
        """Retrieve and decrypt data."""
        if not self.client:
            print("\n[ERROR] No storage configured")
            return

        print("\n" + "=" * 40)
        print("RETRIEVE DATA")
        print("=" * 40)

        # Get key
        key = input("\nStorage key: ").strip()
        if not key:
            print("Cancelled.")
            return

        # Get password
        password: str | PasswordConfig | None = None
        if self._passwords:
            use_configured = input("Use configured passwords? [Y/n]: ").strip().lower()
            if use_configured != "n":
                password = self._passwords

        if not password:
            password = self._get_password("Decryption password")

        # Retrieve
        try:
            data = self.client.retrieve(key, password, verify_integrity=True)

            print(f"\n[OK] Data retrieved successfully ({len(data)} bytes)")
            print("-" * 40)

            # Output options
            print("\nOutput:")
            print("  1. Display as text")
            print("  2. Display as hex")
            print("  3. Save to file")
            choice = input("Select [1/2/3]: ").strip()

            if choice == "2":
                print(f"\n{data.hex()}")
            elif choice == "3":
                out_path = input("Output file path: ").strip()
                out_path = os.path.expanduser(out_path)
                with open(out_path, "wb") as f:
                    f.write(data)
                print(f"\n[OK] Saved to {out_path}")
            else:
                try:
                    print(f"\n{data.decode('utf-8')}")
                except UnicodeDecodeError:
                    print("\n[Binary data - showing hex]")
                    print(data.hex())

        except DecryptionError as e:
            print(f"\n[ERROR] Decryption failed: {e}")
            print("  Check that you're using the correct password.")
        except InsufficientShardsError as e:
            print(f"\n[ERROR] Not enough shards: {e.available}/{e.required} available")
            print(f"  Available indices: {e.shard_indices}")
        except IntegrityError as e:
            print(f"\n[ERROR] Data integrity check failed!")
            print(f"  Expected: {e.expected_hash[:16]}...")
            print(f"  Got:      {e.actual_hash[:16]}...")
        except Exception as e:
            print(f"\n[ERROR] Retrieval failed: {e}")

    def _list_keys(self) -> None:
        """List all stored keys."""
        if not self.client:
            print("\n[ERROR] No storage configured")
            return

        print("\n" + "=" * 40)
        print("STORED KEYS")
        print("=" * 40)

        try:
            keys = self.client.list_keys()

            if not keys:
                print("\n  (no data stored)")
            else:
                print(f"\n  Found {len(keys)} key(s):\n")
                for key in keys:
                    print(f"    - {key}")
        except Exception as e:
            print(f"\n[ERROR] Failed to list keys: {e}")

    def _check_status(self) -> None:
        """Check shard status for a key."""
        if not self.client:
            print("\n[ERROR] No storage configured")
            return

        print("\n" + "=" * 40)
        print("SHARD STATUS")
        print("=" * 40)

        key = input("\nStorage key: ").strip()
        if not key:
            print("Cancelled.")
            return

        try:
            status = self.client.get_shard_status(key)

            print(f"\nKey: {status['key']}")
            print(f"Mode: {status['storage_mode']}")
            print(f"Threshold: {status['threshold']}/{status['total_shards']}")

            can_recover = status['can_reconstruct']
            print(f"Can Reconstruct: {'Yes' if can_recover else 'NO'}")

            print(f"\nAvailability:")
            print(f"  Local:   {status['local_available']} shards")
            print(f"  AWS-1:   {status['cloud_account1_available']} shards")
            print(f"  AWS-2:   {status['cloud_account2_available']} shards")

            print(f"\nShard Details:")
            for shard in status['shards']:
                status_char = "[x]" if shard['exists'] else "[ ]"
                print(f"  {status_char} Shard {shard['index']}: {shard['backend_type']}")

        except Exception as e:
            print(f"\n[ERROR] Failed to get status: {e}")

    def _delete_data(self) -> None:
        """Delete stored data."""
        if not self.client:
            print("\n[ERROR] No storage configured")
            return

        print("\n" + "=" * 40)
        print("DELETE DATA")
        print("=" * 40)

        key = input("\nStorage key to delete: ").strip()
        if not key:
            print("Cancelled.")
            return

        # Confirm
        confirm = input(f"\nDelete all shards for '{key}'? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Cancelled.")
            return

        secure = input("Secure delete (overwrite before delete)? [Y/n]: ").strip().lower()
        secure_delete = secure != "n"

        try:
            result = self.client.delete(key, secure=secure_delete)

            print(f"\n[OK] Deletion complete")
            print(f"     Deleted: {len(result.deleted)} shards")

            if result.failed:
                print(f"     Failed:  {len(result.failed)} shards")
                for fail in result.failed:
                    print(f"       - Shard {fail['shard_index']}: {fail['error']}")

        except Exception as e:
            print(f"\n[ERROR] Deletion failed: {e}")

    # -------------------------------------------------------------------------
    # Credential Management
    # -------------------------------------------------------------------------

    def _manage_credentials(self) -> None:
        """Manage AWS credentials."""
        print("\n" + "=" * 40)
        print("AWS CREDENTIALS MANAGEMENT")
        print("=" * 40)

        print("\n  1. Store new credentials")
        print("  2. List stored credentials")
        print("  3. Delete credentials")
        print("  4. Test credential decryption")
        print("  0. Back")

        choice = input("\nSelect: ").strip()

        if choice == "1":
            self._store_credentials()
        elif choice == "2":
            self._list_credentials()
        elif choice == "3":
            self._delete_credentials()
        elif choice == "4":
            self._test_credentials()

    def _get_credential_store_path(self) -> Path:
        """Get the path for credential storage."""
        default = os.path.expanduser("~/.text-file-manager/credentials")
        path = input(f"\nCredential store path [{default}]: ").strip()
        return Path(os.path.expanduser(path) if path else default)

    def _store_credentials(self) -> None:
        """Store new AWS credentials."""
        store_path = self._get_credential_store_path()
        cred_store = CredentialStore(store_path)

        account_id = input("Account identifier (e.g., 'aws_account1'): ").strip()
        if not account_id:
            print("Cancelled.")
            return

        creds = self._get_aws_credentials(account_id)
        if not creds:
            print("Cancelled.")
            return

        password = self._get_password("Encryption password for credentials")

        try:
            path = cred_store.store_credentials(account_id, creds, password)
            print(f"\n[OK] Credentials stored: {path}")
        except Exception as e:
            print(f"\n[ERROR] Failed to store credentials: {e}")

    def _list_credentials(self) -> None:
        """List stored credentials."""
        store_path = self._get_credential_store_path()

        if not store_path.exists():
            print(f"\n  No credential store at {store_path}")
            return

        cred_store = CredentialStore(store_path)
        accounts = cred_store.list_accounts()

        if not accounts:
            print("\n  No credentials stored")
        else:
            print(f"\n  Stored credentials ({len(accounts)}):")
            for account in accounts:
                print(f"    - {account}")

    def _delete_credentials(self) -> None:
        """Delete stored credentials."""
        store_path = self._get_credential_store_path()
        cred_store = CredentialStore(store_path)

        account_id = input("Account identifier to delete: ").strip()
        if not account_id:
            print("Cancelled.")
            return

        confirm = input(f"Delete credentials for '{account_id}'? [y/N]: ").strip().lower()
        if confirm != "y":
            print("Cancelled.")
            return

        if cred_store.delete_credentials(account_id, secure=True):
            print(f"\n[OK] Credentials deleted")
        else:
            print(f"\n[ERROR] Credentials not found")

    def _test_credentials(self) -> None:
        """Test decrypting stored credentials."""
        store_path = self._get_credential_store_path()

        if not store_path.exists():
            print(f"\n  No credential store at {store_path}")
            return

        cred_store = CredentialStore(store_path)

        account_id = input("Account identifier: ").strip()
        if not account_id:
            print("Cancelled.")
            return

        password = self._get_password("Decryption password")

        try:
            creds = cred_store.load_credentials(account_id, password)
            print(f"\n[OK] Credentials decrypted successfully")
            print(f"     Access Key ID: {creds.access_key_id[:8]}...")
            print(f"     Region: {creds.region or '(not set)'}")
        except DecryptionError:
            print(f"\n[ERROR] Wrong password")
        except ConfigurationError as e:
            print(f"\n[ERROR] {e}")
        except Exception as e:
            print(f"\n[ERROR] Failed to decrypt: {e}")

    # -------------------------------------------------------------------------
    # Helper Methods
    # -------------------------------------------------------------------------

    def _get_password(self, prompt: str) -> str:
        """Get a password from the user with confirmation."""
        while True:
            password = getpass.getpass(f"{prompt} (min {self.MIN_PASSWORD_LENGTH} chars): ")

            if len(password) < self.MIN_PASSWORD_LENGTH:
                print(f"  Password must be at least {self.MIN_PASSWORD_LENGTH} characters")
                continue

            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("  Passwords don't match. Try again.")
                continue

            return password

    def _get_threshold(self, total_shards: int) -> int:
        """Get threshold value from user."""
        default = min(3, total_shards)
        while True:
            try:
                threshold = input(f"Threshold (shards needed to recover) [{default}]: ").strip()
                threshold = int(threshold) if threshold else default

                if threshold < 2:
                    print("  Threshold must be at least 2")
                    continue
                if threshold > total_shards:
                    print(f"  Threshold cannot exceed total shards ({total_shards})")
                    continue

                return threshold
            except ValueError:
                print("  Please enter a valid number")

    def _get_int(
        self,
        prompt: str,
        default: int = 0,
        min_val: int | None = None,
        max_val: int | None = None,
    ) -> int:
        """Get an integer from the user."""
        while True:
            try:
                value = input(f"{prompt} [{default}]: ").strip()
                value = int(value) if value else default

                if min_val is not None and value < min_val:
                    print(f"  Value must be at least {min_val}")
                    continue
                if max_val is not None and value > max_val:
                    print(f"  Value cannot exceed {max_val}")
                    continue

                return value
            except ValueError:
                print("  Please enter a valid number")

    def _get_aws_config(self, account_name: str) -> dict[str, Any]:
        """Get AWS configuration from user."""
        print(f"\nAWS Configuration for {account_name}:")

        bucket = input("  S3 bucket name: ").strip()
        region = input("  AWS region (e.g., us-east-1): ").strip()

        config: dict[str, Any] = {
            "bucket": bucket,
            "region": region,
        }

        profile = input("  AWS profile name (optional): ").strip()
        if profile:
            config["profile_name"] = profile

        role_arn = input("  IAM role ARN for assume-role (optional): ").strip()
        if role_arn:
            config["role_arn"] = role_arn

        prefix = input("  S3 key prefix [shards/]: ").strip()
        if prefix:
            config["prefix"] = prefix

        return config

    def _get_aws_credentials(self, account_name: str) -> AWSCredentials | None:
        """Get AWS credentials from user."""
        print(f"\nAWS Credentials for {account_name}:")
        print("  (leave blank to use environment/profile credentials)")

        access_key = input("  Access Key ID: ").strip()
        if not access_key:
            return None

        secret_key = getpass.getpass("  Secret Access Key: ")
        session_token = input("  Session Token (optional): ").strip() or None
        region = input("  Region (optional): ").strip() or None

        return AWSCredentials(
            access_key_id=access_key,
            secret_access_key=secret_key,
            session_token=session_token,
            region=region,
        )

    def _configure_passwords(self, has_local: bool = True) -> PasswordConfig:
        """Configure password mode."""
        print("\n" + "-" * 40)
        print("PASSWORD CONFIGURATION")
        print("-" * 40)
        print("\nPassword modes:")
        print("  1. Single password for all locations")
        print("  2. Separate passwords for each location")
        print("  3. Common prefix with different suffixes")

        choice = input("\nSelect mode [1]: ").strip() or "1"

        if choice == "2":
            print("\nEnter separate passwords:")
            if has_local:
                local_pwd = self._get_password("  Local password")
            else:
                local_pwd = "unused-local-password"
            aws1_pwd = self._get_password("  AWS Account 1 password")
            aws2_pwd = self._get_password("  AWS Account 2 password")
            return PasswordConfig.separate(local_pwd, aws1_pwd, aws2_pwd)

        elif choice == "3":
            print("\nEnter prefix and suffixes:")
            prefix = input("  Common prefix: ").strip()
            if has_local:
                local_suffix = input("  Local suffix: ").strip()
            else:
                local_suffix = "unused"
            aws1_suffix = input("  AWS-1 suffix: ").strip()
            aws2_suffix = input("  AWS-2 suffix: ").strip()

            # Validate combined length
            test_pwd = prefix + local_suffix
            if len(test_pwd) < self.MIN_PASSWORD_LENGTH:
                print(f"  Warning: Combined password is only {len(test_pwd)} chars")
                print(f"  Minimum is {self.MIN_PASSWORD_LENGTH}")

            return PasswordConfig.prefix_suffix(prefix, local_suffix, aws1_suffix, aws2_suffix)

        else:
            password = self._get_password("Enter password for all locations")
            return PasswordConfig.single(password)


def main() -> None:
    """Main entry point for the Text UI application."""
    parser = argparse.ArgumentParser(
        description="Text File Manager - Interactive CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                         Start interactive mode
  %(prog)s --config config.json    Load configuration and start

Configuration file format (JSON):
  {
    "storage_mode": "hybrid",
    "local_directories": ["/path/to/dir1", "/path/to/dir2"],
    "credential_store_path": "/path/to/credentials",
    "aws_account1": {"bucket": "bucket1", "region": "us-east-1"},
    "aws_account2": {"bucket": "bucket2", "region": "eu-west-1"},
    "local_shards": 2,
    "account1_shards": 2,
    "account2_shards": 2
  }
        """,
    )
    parser.add_argument(
        "--config", "-c",
        type=str,
        help="Path to configuration file",
    )

    args = parser.parse_args()

    app = TextUIApp()
    try:
        app.run(args.config)
    except KeyboardInterrupt:
        print("\n\nInterrupted. Goodbye!")
        sys.exit(0)


if __name__ == "__main__":
    main()
