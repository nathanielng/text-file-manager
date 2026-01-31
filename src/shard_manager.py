"""
Secure Local File Sharding Module.

This module provides encrypted data sharding using Shamir's Secret Sharing
combined with ChaCha20-Poly1305 authenticated encryption. It is designed
for securely storing sensitive data across multiple local directories.

Security Features:
    - PBKDF2-HMAC-SHA256 key derivation (600,000 iterations per OWASP 2023)
    - ChaCha20-Poly1305 authenticated encryption (AEAD)
    - Unique salt and nonce per shard
    - Shamir's Secret Sharing for data redundancy
    - SHA-256 integrity verification
    - Secure file deletion with random data overwriting
    - Restrictive file permissions (0o600 for files, 0o700 for directories)

Example:
    >>> client = SecureLocalShardingClient(['/path/shard1', '/path/shard2', '/path/shard3'])
    >>> result = client.store_sharded('my-key', b'secret data', 'strong-password-12chars')
    >>> data = client.retrieve_sharded('my-key', 'strong-password-12chars')
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv
from sslib import shamir

from src.exceptions import (
    DecryptionError,
    DirectoryError,
    InsufficientShardsError,
    IntegrityError,
    PasswordTooShortError,
    ThresholdError,
)

if TYPE_CHECKING:
    from typing import Any

__all__ = ["SecureLocalShardingClient", "ShardResult", "DeletionResult"]

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class ShardResult:
    """Result of a shard storage operation."""

    key: str
    threshold: int
    total_shares: int
    data_hash: str
    stored_shards: list[dict[str, Any]]
    success: bool

    def __post_init__(self) -> None:
        """Validate the result after initialization."""
        if self.success and len(self.stored_shards) < self.threshold:
            self.success = False


@dataclass
class DeletionResult:
    """Result of a shard deletion operation."""

    key: str
    deleted: list[dict[str, Any]]
    failed: list[dict[str, Any]]
    success: bool


class SecureLocalShardingClient:
    """
    Secure client for storing and retrieving encrypted sharded secrets.

    This client implements a defense-in-depth approach to data security:
    1. Data is split using Shamir's Secret Sharing (K-of-N threshold scheme)
    2. Each shard is encrypted with a unique key derived from the user's password
    3. Shards are stored across multiple directories for physical separation

    Security parameters follow OWASP 2023 recommendations for password storage.

    Attributes:
        PBKDF2_ITERATIONS: Number of PBKDF2 iterations (600,000 per OWASP 2023).
        SALT_SIZE: Size of random salt in bytes (32 bytes = 256 bits).
        NONCE_SIZE: Size of ChaCha20 nonce in bytes (12 bytes = 96 bits).
        KEY_SIZE: Size of encryption key in bytes (32 bytes = 256 bits).
        MIN_PASSWORD_LENGTH: Minimum required password length (12 characters).

    Example:
        >>> directories = ['/secure/drive1', '/secure/drive2', '/secure/drive3']
        >>> client = SecureLocalShardingClient(directories)
        >>> client.store_sharded('api-key', b'secret-value', 'my-secure-password')
    """

    # Security parameters (OWASP 2023 recommendations)
    PBKDF2_ITERATIONS: int = 600_000
    SALT_SIZE: int = 32  # 256 bits
    NONCE_SIZE: int = 12  # 96 bits for ChaCha20Poly1305
    KEY_SIZE: int = 32  # 256 bits
    MIN_PASSWORD_LENGTH: int = 12

    # File format version for forward compatibility
    SHARD_FORMAT_VERSION: str = "1.0"

    def __init__(self, shard_directories: list[str]) -> None:
        """
        Initialize the sharding client with storage directories.

        Creates directories if they don't exist and sets restrictive permissions
        (0o700 - owner read/write/execute only).

        Args:
            shard_directories: List of directory paths where shards will be stored.
                               Each directory should ideally be on a separate
                               physical storage device for maximum security.

        Raises:
            DirectoryError: If a directory cannot be created or accessed.
            ValueError: If no directories are provided.
        """
        if not shard_directories:
            raise ValueError("At least one shard directory must be provided")

        self.shard_directories: list[Path] = [Path(d) for d in shard_directories]

        # Create directories with secure permissions
        for directory in self.shard_directories:
            try:
                directory.mkdir(parents=True, exist_ok=True)
                os.chmod(directory, 0o700)
                logger.info(f"Initialized shard directory: {directory}")
            except PermissionError as e:
                raise DirectoryError(
                    f"Permission denied creating directory", str(directory)
                ) from e
            except OSError as e:
                logger.warning(f"Could not set permissions on {directory}: {e}")

        logger.info(
            f"Initialized SecureLocalShardingClient with {len(shard_directories)} directories"
        )

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2-HMAC-SHA256.

        Uses a high iteration count to make brute-force attacks computationally
        expensive. Each shard uses a unique salt to prevent rainbow table attacks.

        Args:
            password: User-provided password.
            salt: Unique random salt for this key derivation.

        Returns:
            32-byte derived encryption key.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )
        return kdf.derive(password.encode("utf-8"))

    def _encrypt_shard(self, data: bytes, password: str) -> tuple[bytes, bytes, bytes]:
        """
        Encrypt shard data with ChaCha20-Poly1305 authenticated encryption.

        ChaCha20-Poly1305 provides both confidentiality and authenticity,
        ensuring data cannot be read or modified without detection.

        Args:
            data: Plaintext data to encrypt.
            password: Encryption password.

        Returns:
            Tuple of (salt, nonce, ciphertext) where:
                - salt: Random bytes used for key derivation
                - nonce: Random bytes used for encryption (must never be reused)
                - ciphertext: Encrypted data with authentication tag
        """
        salt = secrets.token_bytes(self.SALT_SIZE)
        nonce = secrets.token_bytes(self.NONCE_SIZE)

        key = self._derive_key(password, salt)
        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(nonce, data, None)

        return salt, nonce, ciphertext

    def _decrypt_shard(
        self, salt: bytes, nonce: bytes, ciphertext: bytes, password: str
    ) -> bytes:
        """
        Decrypt shard data with ChaCha20-Poly1305 authenticated decryption.

        Verifies the authentication tag before returning decrypted data,
        ensuring data integrity and authenticity.

        Args:
            salt: Salt used for key derivation.
            nonce: Nonce used for encryption.
            ciphertext: Encrypted data with authentication tag.
            password: Decryption password.

        Returns:
            Decrypted plaintext data.

        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails
                (wrong password or tampered data).
        """
        key = self._derive_key(password, salt)
        cipher = ChaCha20Poly1305(key)
        return cipher.decrypt(nonce, ciphertext, None)

    def _compute_integrity_hash(self, data: bytes) -> str:
        """
        Compute SHA-256 hash for data integrity verification.

        This hash is stored with the shard metadata and verified during
        reconstruction to detect any data corruption.

        Args:
            data: Data to hash.

        Returns:
            Hex-encoded SHA-256 hash string.
        """
        return hashlib.sha256(data).hexdigest()

    def store_sharded(
        self,
        key: str,
        data: bytes,
        password: str,
        threshold: int = 3,
        total_shares: int | None = None,
        metadata: dict[str, str] | None = None,
    ) -> ShardResult:
        """
        Split data into encrypted shards and store across local directories.

        Uses Shamir's Secret Sharing to split data into N shares where any K
        shares can reconstruct the original data. Each share is then encrypted
        with the user's password before storage.

        Args:
            key: Unique identifier/path for the sharded data.
            data: Raw bytes to shard and store.
            password: Password for encrypting shards (min 12 characters).
            threshold: Minimum shards needed to reconstruct (K).
            total_shares: Total shards to create (N). Defaults to directory count.
            metadata: Optional key-value metadata (stored unencrypted with shards).

        Returns:
            ShardResult containing storage details and success status.

        Raises:
            TypeError: If data is not bytes.
            PasswordTooShortError: If password is less than 12 characters.
            ThresholdError: If threshold exceeds total_shares.
            DirectoryError: If total_shares exceeds available directories.
            InsufficientShardsError: If not enough shards could be stored.

        Example:
            >>> result = client.store_sharded(
            ...     key='secrets/api-key',
            ...     data=b'my-secret-api-key',
            ...     password='secure-password-here',
            ...     threshold=2,
            ...     total_shares=3
            ... )
            >>> print(f"Stored {len(result.stored_shards)} shards")
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes")

        if not password or len(password) < self.MIN_PASSWORD_LENGTH:
            raise PasswordTooShortError(self.MIN_PASSWORD_LENGTH)

        total_shares = total_shares or len(self.shard_directories)

        if total_shares > len(self.shard_directories):
            raise DirectoryError(
                f"total_shares ({total_shares}) exceeds available directories "
                f"({len(self.shard_directories)})"
            )

        if threshold > total_shares:
            raise ThresholdError(threshold, total_shares)

        logger.info(
            f"Splitting '{key}' into {total_shares} encrypted shards "
            f"(threshold: {threshold}, size: {len(data)} bytes)"
        )

        # Compute integrity hash of original data
        data_hash = self._compute_integrity_hash(data)

        # Split the data using Shamir's Secret Sharing
        shares = shamir.to_base64(shamir.split_secret(data, threshold, total_shares))

        # Prepare metadata
        shard_metadata = dict(metadata) if metadata else {}
        shard_metadata.update(
            {
                "threshold": str(threshold),
                "total-shares": str(total_shares),
                "original-key": key,
                "data-hash": data_hash,
                "pbkdf2-iterations": str(self.PBKDF2_ITERATIONS),
            }
        )

        # Store each shard in a different directory
        stored_shards: list[dict[str, Any]] = []
        for i, share in enumerate(shares):
            shard_dir = self.shard_directories[i]

            # Create subdirectories if key contains paths
            key_path = Path(key)
            if key_path.parent != Path("."):
                (shard_dir / key_path.parent).mkdir(parents=True, exist_ok=True)

            shard_filename = f"{key}.shard{i}"
            shard_path = shard_dir / shard_filename

            try:
                # Encrypt the shard
                share_bytes = share.encode("utf-8")
                salt, nonce, ciphertext = self._encrypt_shard(share_bytes, password)

                # Create shard file structure
                shard_data = {
                    "version": self.SHARD_FORMAT_VERSION,
                    "salt": base64.b64encode(salt).decode("ascii"),
                    "nonce": base64.b64encode(nonce).decode("ascii"),
                    "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                    "metadata": shard_metadata,
                }

                # Write encrypted shard with secure permissions
                shard_path.write_text(json.dumps(shard_data, indent=2), encoding="utf-8")

                try:
                    os.chmod(shard_path, 0o600)
                except OSError as e:
                    logger.warning(f"Could not set permissions on {shard_path}: {e}")

                stored_shards.append(
                    {
                        "shard_index": i,
                        "directory": str(shard_dir),
                        "path": str(shard_path),
                        "encrypted_size": len(ciphertext),
                    }
                )
                logger.info(f"Stored encrypted shard {i} at {shard_path}")

            except Exception as e:
                logger.error(
                    f"Failed to store shard {i} in {shard_dir}: {e}", exc_info=True
                )
                continue

        if len(stored_shards) < threshold:
            raise InsufficientShardsError(
                available=len(stored_shards),
                required=threshold,
                shard_indices=[s["shard_index"] for s in stored_shards],
            )

        logger.info(
            f"Successfully stored {len(stored_shards)}/{total_shares} "
            f"encrypted shards for '{key}'"
        )

        return ShardResult(
            key=key,
            threshold=threshold,
            total_shares=total_shares,
            data_hash=data_hash,
            stored_shards=stored_shards,
            success=True,
        )

    def retrieve_sharded(
        self,
        key: str,
        password: str,
        threshold: int | None = None,
        required_shards: list[int] | None = None,
        verify_integrity: bool = True,
    ) -> bytes:
        """
        Retrieve and reconstruct data from encrypted shards.

        Reads the minimum required number of shards, decrypts each one,
        and uses Shamir's Secret Sharing to reconstruct the original data.

        Args:
            key: Original file key used during storage.
            password: Password for decrypting shards.
            threshold: Expected threshold (auto-detected from metadata if None).
            required_shards: Specific shard indices to retrieve (optional).
            verify_integrity: Whether to verify SHA-256 hash after reconstruction.

        Returns:
            Reconstructed original data as bytes.

        Raises:
            DecryptionError: If shard decryption fails (wrong password or corruption).
            InsufficientShardsError: If not enough shards are available.
            IntegrityError: If data integrity verification fails.
            ValueError: If threshold cannot be determined.

        Example:
            >>> data = client.retrieve_sharded('secrets/api-key', 'my-password')
            >>> print(data.decode('utf-8'))
        """
        logger.info(f"Retrieving encrypted shards for '{key}'")

        shares: list[str] = []
        shard_indices: list[int] = []
        detected_threshold: int | None = None
        expected_hash: str | None = None

        # Determine which shards to attempt retrieval
        shard_range: range | list[int]
        if required_shards:
            shard_range = required_shards
        else:
            shard_range = range(len(self.shard_directories))

        for i in shard_range:
            if i >= len(self.shard_directories):
                logger.warning(f"Shard index {i} exceeds directory count")
                continue

            # Stop early if we have enough shards
            if detected_threshold and len(shares) >= detected_threshold:
                break

            shard_dir = self.shard_directories[i]
            shard_filename = f"{key}.shard{i}"
            shard_path = shard_dir / shard_filename

            try:
                if not shard_path.exists():
                    logger.warning(f"Shard {i} not found at {shard_path}")
                    continue

                # Read and parse encrypted shard
                shard_data = json.loads(shard_path.read_text(encoding="utf-8"))

                salt = base64.b64decode(shard_data["salt"])
                nonce = base64.b64decode(shard_data["nonce"])
                ciphertext = base64.b64decode(shard_data["ciphertext"])

                # Decrypt the shard
                try:
                    decrypted = self._decrypt_shard(salt, nonce, ciphertext, password)
                    share = decrypted.decode("utf-8")
                    shares.append(share)
                    shard_indices.append(i)
                    logger.info(f"Decrypted shard {i} from {shard_path}")
                except Exception as e:
                    logger.error(f"Failed to decrypt shard {i}: {e}")
                    raise DecryptionError(i, "Wrong password or corrupted data") from e

                # Extract metadata for threshold detection
                metadata = shard_data.get("metadata", {})
                if not detected_threshold and "threshold" in metadata:
                    detected_threshold = int(metadata["threshold"])
                    logger.info(f"Detected threshold: {detected_threshold}")

                if not expected_hash and "data-hash" in metadata:
                    expected_hash = metadata["data-hash"]

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse shard {i}: {e}")
                continue
            except DecryptionError:
                raise
            except Exception as e:
                logger.error(f"Failed to retrieve shard {i}: {e}")
                continue

        # Validate we have enough shards
        actual_threshold = threshold or detected_threshold

        if not actual_threshold:
            raise ValueError(
                "Could not determine threshold. Specify explicitly or ensure "
                "shard metadata is available."
            )

        if len(shares) < actual_threshold:
            raise InsufficientShardsError(
                available=len(shares),
                required=actual_threshold,
                shard_indices=shard_indices,
            )

        logger.info(
            f"Reconstructing data from {len(shares)} decrypted shards "
            f"(indices: {shard_indices})"
        )

        # Reconstruct the original data
        share_tuples = shamir.from_base64(shares[:actual_threshold])
        reconstructed = shamir.recover_secret(share_tuples)

        # Verify integrity if requested
        if verify_integrity and expected_hash:
            actual_hash = self._compute_integrity_hash(reconstructed)
            if actual_hash != expected_hash:
                raise IntegrityError(expected_hash, actual_hash)
            logger.info("Integrity check passed")

        logger.info(f"Successfully reconstructed '{key}' ({len(reconstructed)} bytes)")
        return reconstructed

    def delete_sharded(self, key: str, secure_delete: bool = True) -> DeletionResult:
        """
        Delete all shards for a given key.

        Optionally performs secure deletion by overwriting file contents with
        random data before unlinking, making recovery more difficult.

        Args:
            key: Original file key to delete.
            secure_delete: If True, overwrite files with random data before deletion.

        Returns:
            DeletionResult containing deletion details and success status.

        Example:
            >>> result = client.delete_sharded('secrets/api-key', secure_delete=True)
            >>> print(f"Deleted {len(result.deleted)} shards")
        """
        logger.info(f"Deleting all shards for '{key}'")

        deleted_shards: list[dict[str, Any]] = []
        failed_deletions: list[dict[str, Any]] = []

        for i, shard_dir in enumerate(self.shard_directories):
            shard_filename = f"{key}.shard{i}"
            shard_path = shard_dir / shard_filename

            try:
                if shard_path.exists():
                    if secure_delete:
                        # Overwrite with random data before deletion
                        file_size = shard_path.stat().st_size
                        shard_path.write_bytes(secrets.token_bytes(file_size))

                    shard_path.unlink()
                    deleted_shards.append({"shard_index": i, "path": str(shard_path)})
                    logger.info(f"Deleted shard {i} from {shard_path}")

            except Exception as e:
                logger.error(f"Failed to delete shard {i}: {e}")
                failed_deletions.append(
                    {"shard_index": i, "path": str(shard_path), "error": str(e)}
                )

        logger.info(
            f"Deletion complete: {len(deleted_shards)} deleted, "
            f"{len(failed_deletions)} failed"
        )

        return DeletionResult(
            key=key,
            deleted=deleted_shards,
            failed=failed_deletions,
            success=len(failed_deletions) == 0,
        )

    def list_sharded_files(self) -> list[str]:
        """
        List all sharded files across directories.

        Scans all shard directories for shard files and extracts the unique
        keys from their filenames.

        Returns:
            Sorted list of unique keys for all stored sharded files.

        Example:
            >>> files = client.list_sharded_files()
            >>> for key in files:
            ...     print(key)
        """
        keys: set[str] = set()

        for shard_dir in self.shard_directories:
            if not shard_dir.exists():
                continue

            for shard_file in shard_dir.rglob("*.shard*"):
                # Extract original key from shard filename
                relative_path = str(shard_file.relative_to(shard_dir))
                # Remove .shard{N} suffix
                key = relative_path.rsplit(".shard", 1)[0]
                keys.add(key)

        return sorted(keys)


def main() -> None:
    """
    Example usage with interactive password input.

    Demonstrates storing and retrieving encrypted sharded data using
    environment-configured directories.
    """
    # Load environment variables
    load_dotenv()

    # Configure local directories from environment or defaults
    shard_directories = [
        os.getenv("SHARD_DIR_1", "/tmp/secure_shards/drive1"),
        os.getenv("SHARD_DIR_2", "/tmp/secure_shards/drive2"),
        os.getenv("SHARD_DIR_3", "/tmp/secure_shards/drive3"),
        os.getenv("SHARD_DIR_4", "/tmp/secure_shards/drive4"),
        os.getenv("SHARD_DIR_5", "/tmp/secure_shards/drive5"),
    ]

    # Initialize client
    client = SecureLocalShardingClient(shard_directories)

    # Example secret data
    secret_data = b"This is highly sensitive data that should be sharded and encrypted"

    # Get password from user
    print("Enter a strong password (min 12 characters) to encrypt shards:")
    password = getpass()

    if len(password) < SecureLocalShardingClient.MIN_PASSWORD_LENGTH:
        logger.error(
            f"Password must be at least {SecureLocalShardingClient.MIN_PASSWORD_LENGTH} characters"
        )
        return

    # Store the secret
    result = client.store_sharded(
        key="secrets/api-keys/production",
        data=secret_data,
        password=password,
        threshold=3,
        total_shares=5,
        metadata={"environment": "production", "app": "api-gateway"},
    )

    logger.info(f"Storage result: {result}")

    # Retrieve and verify
    print("\nEnter password to decrypt and reconstruct:")
    decrypt_password = getpass()

    try:
        reconstructed = client.retrieve_sharded(
            key="secrets/api-keys/production",
            password=decrypt_password,
            threshold=3,
            verify_integrity=True,
        )

        assert reconstructed == secret_data
        logger.info("Data successfully reconstructed and verified!")

    except (DecryptionError, IntegrityError, InsufficientShardsError) as e:
        logger.error(f"Failed to reconstruct: {e}")


if __name__ == "__main__":
    main()
