"""
Secure Local File Sharding - Encrypted shards with password-based key derivation
"""
import os
import logging
import secrets
import hashlib
from typing import List, Optional, Tuple
from pathlib import Path
from getpass import getpass
from dotenv import load_dotenv
from sslib import shamir
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import json
import base64

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SecureLocalShardingClient:
    """
    Secure client for storing and retrieving encrypted sharded secrets.
    
    Security features:
    - Password-based key derivation (PBKDF2-HMAC-SHA256)
    - Unique salt per shard
    - ChaCha20-Poly1305 authenticated encryption
    - Shamir's Secret Sharing for data sharding
    - Constant-time password verification
    """
    
    # Security parameters
    PBKDF2_ITERATIONS = 600_000  # OWASP 2023 recommendation
    SALT_SIZE = 32  # 256 bits
    NONCE_SIZE = 12  # 96 bits for ChaCha20Poly1305
    KEY_SIZE = 32  # 256 bits
    
    def __init__(self, shard_directories: List[str]):
        """
        Initialize the sharding client.
        
        Args:
            shard_directories: List of directory paths where shards will be stored
        """
        self.shard_directories = [Path(d) for d in shard_directories]
        
        # Create directories if they don't exist
        for directory in self.shard_directories:
            directory.mkdir(parents=True, exist_ok=True)
            # Set restrictive permissions (owner only)
            try:
                os.chmod(directory, 0o700)
            except Exception as e:
                logger.warning(f"Could not set permissions on {directory}: {e}")
            logger.info(f"Initialized shard directory: {directory}")
        
        logger.info(f"Initialized SecureLocalShardingClient with {len(shard_directories)} directories")
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2-HMAC-SHA256.
        
        Args:
            password: User password
            salt: Unique salt for this derivation
            
        Returns:
            Derived encryption key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )
        return kdf.derive(password.encode('utf-8'))
    
    def _encrypt_shard(self, data: bytes, password: str) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt shard data with authenticated encryption.
        
        Args:
            data: Plaintext data to encrypt
            password: Encryption password
            
        Returns:
            Tuple of (salt, nonce, ciphertext)
        """
        # Generate unique salt and nonce
        salt = secrets.token_bytes(self.SALT_SIZE)
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        
        # Derive encryption key
        key = self._derive_key(password, salt)
        
        # Encrypt with ChaCha20-Poly1305 (authenticated encryption)
        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(nonce, data, None)
        
        return salt, nonce, ciphertext
    
    def _decrypt_shard(self, salt: bytes, nonce: bytes, ciphertext: bytes, password: str) -> bytes:
        """
        Decrypt shard data with authenticated encryption.
        
        Args:
            salt: Salt used for key derivation
            nonce: Nonce used for encryption
            ciphertext: Encrypted data
            password: Decryption password
            
        Returns:
            Decrypted plaintext data
            
        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails (wrong password or tampered data)
        """
        # Derive encryption key
        key = self._derive_key(password, salt)
        
        # Decrypt with ChaCha20-Poly1305
        cipher = ChaCha20Poly1305(key)
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        
        return plaintext
    
    def _compute_integrity_hash(self, data: bytes) -> str:
        """
        Compute SHA-256 hash for integrity verification.
        
        Args:
            data: Data to hash
            
        Returns:
            Hex-encoded hash
        """
        return hashlib.sha256(data).hexdigest()
    
    def store_sharded(
        self,
        key: str,
        data: bytes,
        password: str,
        threshold: int = 3,
        total_shares: Optional[int] = None,
        metadata: Optional[dict] = None
    ) -> dict:
        """
        Split data into encrypted shards and store across local directories.
        
        Args:
            key: File key/path for the sharded data
            data: Bytes to shard and store
            password: Password for encrypting shards
            threshold: Minimum shards needed to reconstruct (K)
            total_shares: Total shards to create (N). Defaults to directory count.
            metadata: Optional metadata (stored unencrypted)
            
        Returns:
            dict with shard storage information
        """
        if not isinstance(data, bytes):
            raise TypeError("Data must be bytes")
        
        if not password or len(password) < 12:
            raise ValueError("Password must be at least 12 characters long")
        
        total_shares = total_shares or len(self.shard_directories)
        
        if total_shares > len(self.shard_directories):
            raise ValueError(
                f"total_shares ({total_shares}) exceeds available directories "
                f"({len(self.shard_directories)})"
            )
        
        if threshold > total_shares:
            raise ValueError(
                f"threshold ({threshold}) cannot exceed total_shares ({total_shares})"
            )
        
        logger.info(
            f"Splitting '{key}' into {total_shares} encrypted shards "
            f"(threshold: {threshold}, size: {len(data)} bytes)"
        )
        
        # Compute integrity hash of original data
        data_hash = self._compute_integrity_hash(data)
        
        # Split the data using Shamir's Secret Sharing
        shares = shamir.to_base64(
            shamir.split_secret(data, threshold, total_shares)
        )
        
        # Prepare metadata
        shard_metadata = metadata or {}
        shard_metadata.update({
            'threshold': str(threshold),
            'total-shares': str(total_shares),
            'original-key': key,
            'data-hash': data_hash,
            'pbkdf2-iterations': str(self.PBKDF2_ITERATIONS)
        })
        
        # Store each shard in a different directory
        stored_shards = []
        for i, share in enumerate(shares):
            shard_dir = self.shard_directories[i]
            
            # Create subdirectories if key contains paths
            key_path = Path(key)
            if key_path.parent != Path('.'):
                (shard_dir / key_path.parent).mkdir(parents=True, exist_ok=True)
            
            shard_filename = f"{key}.shard{i}"
            shard_path = shard_dir / shard_filename
            
            try:
                # Encrypt the shard
                share_bytes = share.encode('utf-8')
                salt, nonce, ciphertext = self._encrypt_shard(share_bytes, password)
                
                # Create shard file structure
                shard_data = {
                    'version': '1.0',
                    'salt': base64.b64encode(salt).decode('ascii'),
                    'nonce': base64.b64encode(nonce).decode('ascii'),
                    'ciphertext': base64.b64encode(ciphertext).decode('ascii'),
                    'metadata': shard_metadata
                }
                
                # Write encrypted shard
                shard_path.write_text(json.dumps(shard_data, indent=2), encoding='utf-8')
                
                # Set restrictive permissions (owner only)
                try:
                    os.chmod(shard_path, 0o600)
                except Exception as e:
                    logger.warning(f"Could not set permissions on {shard_path}: {e}")
                
                stored_shards.append({
                    'shard_index': i,
                    'directory': str(shard_dir),
                    'path': str(shard_path),
                    'encrypted_size': len(ciphertext)
                })
                
                logger.info(f"Stored encrypted shard {i} at {shard_path}")
                
            except Exception as e:
                logger.error(
                    f"Failed to store shard {i} in {shard_dir}: {e}",
                    exc_info=True
                )
                continue
        
        if len(stored_shards) < threshold:
            raise RuntimeError(
                f"Only stored {len(stored_shards)}/{threshold} required shards. "
                "Data cannot be reliably reconstructed."
            )
        
        logger.info(
            f"Successfully stored {len(stored_shards)}/{total_shares} encrypted shards for '{key}'"
        )
        
        return {
            'key': key,
            'threshold': threshold,
            'total_shares': total_shares,
            'data_hash': data_hash,
            'stored_shards': stored_shards,
            'success': True
        }
    
    def retrieve_sharded(
        self,
        key: str,
        password: str,
        threshold: Optional[int] = None,
        required_shards: Optional[List[int]] = None,
        verify_integrity: bool = True
    ) -> bytes:
        """
        Retrieve and reconstruct data from encrypted shards.
        
        Args:
            key: Original file key
            password: Password for decrypting shards
            threshold: Expected threshold (for validation). Auto-detected if None.
            required_shards: Specific shard indices to retrieve
            verify_integrity: Whether to verify data integrity hash
            
        Returns:
            Reconstructed original data as bytes
            
        Raises:
            ValueError: If wrong password or data integrity check fails
        """
        logger.info(f"Retrieving encrypted shards for '{key}'")
        
        shares = []
        shard_indices = []
        detected_threshold = None
        expected_hash = None
        
        # Determine which shards to attempt retrieval
        if required_shards:
            shard_range = required_shards
        else:
            shard_range = range(len(self.shard_directories))
        
        for i in shard_range:
            if i >= len(self.shard_directories):
                logger.warning(f"Shard index {i} exceeds directory count")
                continue
            
            # Stop if we have enough shards (and we know the threshold)
            if detected_threshold and len(shares) >= detected_threshold:
                break
            
            shard_dir = self.shard_directories[i]
            shard_filename = f"{key}.shard{i}"
            shard_path = shard_dir / shard_filename
            
            try:
                if not shard_path.exists():
                    logger.warning(f"Shard {i} not found at {shard_path}")
                    continue
                
                # Read encrypted shard
                shard_data = json.loads(shard_path.read_text(encoding='utf-8'))
                
                # Extract components
                salt = base64.b64decode(shard_data['salt'])
                nonce = base64.b64decode(shard_data['nonce'])
                ciphertext = base64.b64decode(shard_data['ciphertext'])
                
                # Decrypt the shard
                try:
                    decrypted = self._decrypt_shard(salt, nonce, ciphertext, password)
                    share = decrypted.decode('utf-8')
                    shares.append(share)
                    shard_indices.append(i)
                    
                    logger.info(f"Decrypted shard {i} from {shard_path}")
                except Exception as e:
                    logger.error(f"Failed to decrypt shard {i} (wrong password?): {e}")
                    raise ValueError(f"Failed to decrypt shard {i}. Wrong password or corrupted data.") from e
                
                # Extract metadata
                metadata = shard_data.get('metadata', {})
                if not detected_threshold and 'threshold' in metadata:
                    detected_threshold = int(metadata['threshold'])
                    logger.info(f"Detected threshold: {detected_threshold}")
                
                if not expected_hash and 'data-hash' in metadata:
                    expected_hash = metadata['data-hash']
                
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse shard {i}: {e}")
                continue
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
            raise RuntimeError(
                f"Only retrieved {len(shares)}/{actual_threshold} required shards. "
                f"Cannot reconstruct data. Retrieved shards: {shard_indices}"
            )
        
        logger.info(
            f"Reconstructing data from {len(shares)} decrypted shards "
            f"(indices: {shard_indices})"
        )
        
        # Reconstruct the original data
        try:
            # Convert base64 shares back to tuples
            share_tuples = shamir.from_base64(shares[:actual_threshold])
            
            # Recover the secret
            reconstructed = shamir.recover_secret(share_tuples)
            
            # Verify integrity if requested
            if verify_integrity and expected_hash:
                actual_hash = self._compute_integrity_hash(reconstructed)
                if actual_hash != expected_hash:
                    raise ValueError(
                        f"Integrity check failed! Data may be corrupted. "
                        f"Expected hash: {expected_hash}, got: {actual_hash}"
                    )
                logger.info("Integrity check passed ✓")
            
            logger.info(
                f"Successfully reconstructed '{key}' ({len(reconstructed)} bytes)"
            )
            return reconstructed
            
        except Exception as e:
            logger.error(f"Failed to reconstruct data: {e}", exc_info=True)
            raise
    
    def delete_sharded(self, key: str, secure_delete: bool = True) -> dict:
        """
        Delete all shards for a given key.
        
        Args:
            key: Original file key
            secure_delete: If True, overwrite files before deletion
            
        Returns:
            dict with deletion results
        """
        logger.info(f"Deleting all shards for '{key}'")
        
        deleted_shards = []
        failed_deletions = []
        
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
                    deleted_shards.append({
                        'shard_index': i,
                        'path': str(shard_path)
                    })
                    logger.info(f"Deleted shard {i} from {shard_path}")
                
            except Exception as e:
                logger.error(f"Failed to delete shard {i}: {e}")
                failed_deletions.append({
                    'shard_index': i,
                    'path': str(shard_path),
                    'error': str(e)
                })
        
        logger.info(
            f"Deletion complete: {len(deleted_shards)} deleted, "
            f"{len(failed_deletions)} failed"
        )
        
        return {
            'key': key,
            'deleted': deleted_shards,
            'failed': failed_deletions,
            'success': len(failed_deletions) == 0
        }
    
    def list_sharded_files(self) -> List[str]:
        """List all sharded files across directories."""
        keys = set()
        
        for shard_dir in self.shard_directories:
            if not shard_dir.exists():
                continue
            
            for shard_file in shard_dir.rglob('*.shard*'):
                # Extract original key from shard filename
                key = str(shard_file.relative_to(shard_dir))
                # Remove .shard{N} suffix
                key = key.rsplit('.shard', 1)[0]
                keys.add(key)
        
        return sorted(keys)


def main():
    """Example usage with interactive password input"""
    
    # Configure local directories
    shard_directories = [
        os.getenv('SHARD_DIR_1', '/tmp/secure_shards/drive1'),
        os.getenv('SHARD_DIR_2', '/tmp/secure_shards/drive2'),
        os.getenv('SHARD_DIR_3', '/tmp/secure_shards/drive3'),
        os.getenv('SHARD_DIR_4', '/tmp/secure_shards/drive4'),
        os.getenv('SHARD_DIR_5', '/tmp/secure_shards/drive5'),
    ]
    
    # Initialize client
    client = SecureLocalShardingClient(shard_directories)
    
    # Example: Store secret data with password
    secret_data = b"This is highly sensitive data that should be sharded and encrypted"
    
    # Get password from user (in production, use getpass for security)
    print("Enter a strong password (min 12 characters) to encrypt shards:")
    password = getpass()
    
    if len(password) < 12:
        logger.error("Password must be at least 12 characters")
        return
    
    result = client.store_sharded(
        key='secrets/api-keys/production',
        data=secret_data,
        password=password,
        threshold=3,
        total_shares=5,
        metadata={'environment': 'production', 'app': 'api-gateway'}
    )
    
    logger.info(f"Storage result: {result}")
    
    # Example: Retrieve and reconstruct with password
    print("\nEnter password to decrypt and reconstruct:")
    decrypt_password = getpass()
    
    try:
        reconstructed = client.retrieve_sharded(
            key='secrets/api-keys/production',
            password=decrypt_password,
            threshold=3,
            verify_integrity=True
        )
        
        assert reconstructed == secret_data
        logger.info("Data successfully reconstructed and verified! ✓")
        
    except ValueError as e:
        logger.error(f"Failed to reconstruct: {e}")
        return
    
    # Example: Secure deletion
    # deletion_result = client.delete_sharded('secrets/api-keys/production', secure_delete=True)
    # logger.info(f"Deletion result: {deletion_result}")


if __name__ == '__main__':
    main()
