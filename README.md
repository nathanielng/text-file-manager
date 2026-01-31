# Text File Manager

A secure Python library for managing sensitive data using encrypted sharding with Shamir's Secret Sharing.

## Overview

Text File Manager provides a defense-in-depth approach to storing sensitive data:

1. **Data Sharding**: Splits data using Shamir's Secret Sharing (K-of-N threshold scheme)
2. **Encryption**: Each shard is encrypted with ChaCha20-Poly1305 authenticated encryption
3. **Physical Separation**: Shards are stored across multiple directories (ideally on separate drives)

Even if an attacker gains access to some shards, they cannot reconstruct the original data without reaching the threshold.

## Features

- **Shamir's Secret Sharing**: Configure any K-of-N threshold (e.g., 3-of-5 means any 3 shards can reconstruct data)
- **ChaCha20-Poly1305**: Modern authenticated encryption providing confidentiality and integrity
- **PBKDF2-HMAC-SHA256**: Password-based key derivation with 600,000 iterations (OWASP 2023 recommendation)
- **Unique Cryptographic Material**: Each shard uses unique salt and nonce
- **Integrity Verification**: SHA-256 hash verification on reconstruction
- **Secure Deletion**: Optional secure file deletion with random data overwriting
- **Restrictive Permissions**: Files created with 0o600, directories with 0o700

## Installation

### Using pip

```bash
pip install cryptography sslib python-dotenv
```

### Using uv

```bash
uv pip install cryptography sslib python-dotenv
```

### Development Installation

```bash
# Clone the repository
git clone https://github.com/example/text-file-manager.git
cd text-file-manager

# Install with development dependencies
pip install -e ".[dev]"
```

## Quick Start

```python
from src import SecureLocalShardingClient

# Configure shard directories (ideally on separate drives)
directories = [
    '/secure/drive1/shards',
    '/secure/drive2/shards',
    '/secure/drive3/shards',
]

# Initialize the client
client = SecureLocalShardingClient(directories)

# Store sensitive data (requires password of 12+ characters)
result = client.store_sharded(
    key='secrets/api-key',
    data=b'my-super-secret-api-key',
    password='my-secure-password-here',
    threshold=2,  # Need 2 shards to reconstruct
    total_shares=3,  # Create 3 shards total
)

# Retrieve and reconstruct data
data = client.retrieve_sharded(
    key='secrets/api-key',
    password='my-secure-password-here',
)
print(data.decode('utf-8'))  # 'my-super-secret-api-key'
```

## API Reference

### SecureLocalShardingClient

The main class for storing and retrieving encrypted sharded data.

#### Constructor

```python
SecureLocalShardingClient(shard_directories: list[str])
```

**Parameters:**
- `shard_directories`: List of directory paths where shards will be stored

**Raises:**
- `ValueError`: If no directories are provided
- `DirectoryError`: If a directory cannot be created

#### Methods

##### store_sharded

```python
store_sharded(
    key: str,
    data: bytes,
    password: str,
    threshold: int = 3,
    total_shares: int | None = None,
    metadata: dict[str, str] | None = None,
) -> ShardResult
```

Split data into encrypted shards and store across directories.

**Parameters:**
- `key`: Unique identifier for the sharded data
- `data`: Raw bytes to shard and store
- `password`: Encryption password (minimum 12 characters)
- `threshold`: Minimum shards needed to reconstruct (default: 3)
- `total_shares`: Total shards to create (default: number of directories)
- `metadata`: Optional metadata stored with shards (unencrypted)

**Returns:** `ShardResult` with storage details

**Raises:**
- `TypeError`: If data is not bytes
- `PasswordTooShortError`: If password < 12 characters
- `ThresholdError`: If threshold > total_shares
- `InsufficientShardsError`: If not enough shards could be stored

##### retrieve_sharded

```python
retrieve_sharded(
    key: str,
    password: str,
    threshold: int | None = None,
    required_shards: list[int] | None = None,
    verify_integrity: bool = True,
) -> bytes
```

Retrieve and reconstruct data from encrypted shards.

**Parameters:**
- `key`: Original file key
- `password`: Decryption password
- `threshold`: Expected threshold (auto-detected if None)
- `required_shards`: Specific shard indices to retrieve
- `verify_integrity`: Whether to verify SHA-256 hash (default: True)

**Returns:** Reconstructed original data as bytes

**Raises:**
- `DecryptionError`: If decryption fails (wrong password)
- `InsufficientShardsError`: If not enough shards available
- `IntegrityError`: If integrity verification fails

##### delete_sharded

```python
delete_sharded(key: str, secure_delete: bool = True) -> DeletionResult
```

Delete all shards for a given key.

**Parameters:**
- `key`: File key to delete
- `secure_delete`: Overwrite with random data before deletion (default: True)

**Returns:** `DeletionResult` with deletion details

##### list_sharded_files

```python
list_sharded_files() -> list[str]
```

List all sharded file keys across directories.

**Returns:** Sorted list of unique keys

### Exception Classes

| Exception | Description |
|-----------|-------------|
| `ShardManagerError` | Base exception for all shard manager errors |
| `PasswordError` | Password validation failed |
| `PasswordTooShortError` | Password below minimum length |
| `DecryptionError` | Shard decryption failed |
| `IntegrityError` | Data integrity verification failed |
| `InsufficientShardsError` | Not enough shards for reconstruction |
| `ThresholdError` | Invalid threshold configuration |
| `DirectoryError` | Issues with shard directories |

## Configuration

### Environment Variables

Configure shard directories via environment variables:

```bash
export SHARD_DIR_1=/path/to/shard1
export SHARD_DIR_2=/path/to/shard2
export SHARD_DIR_3=/path/to/shard3
```

Or use a `.env` file:

```env
SHARD_DIR_1=/secure/drive1/shards
SHARD_DIR_2=/secure/drive2/shards
SHARD_DIR_3=/secure/drive3/shards
```

## Security Considerations

### Best Practices

1. **Use Strong Passwords**: Minimum 12 characters, prefer passphrases
2. **Separate Storage**: Store shards on physically separate drives or locations
3. **Backup Shards**: Maintain backups, but keep them separated
4. **Monitor Access**: Log and monitor access to shard directories
5. **Secure Deletion**: Use `secure_delete=True` when removing sensitive data

### Threat Model

This library protects against:
- **Data theft**: Encrypted shards are useless without the password
- **Partial compromise**: Attackers need K shards to reconstruct data
- **Brute force**: PBKDF2 with 600K iterations makes password cracking expensive
- **Tampering**: ChaCha20-Poly1305 detects any modifications

This library does NOT protect against:
- **Compromised passwords**: Use strong, unique passwords
- **Memory attacks**: Secrets exist in memory during processing
- **Compromised threshold**: If attacker gets K+ shards AND password

### Cryptographic Details

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Key Derivation | PBKDF2-HMAC-SHA256 | 600,000 iterations |
| Encryption | ChaCha20-Poly1305 | 256-bit key, 96-bit nonce |
| Integrity | SHA-256 | Pre-encryption hash |
| Secret Sharing | Shamir's SSS | Configurable K-of-N |
| Random Generation | `secrets` module | Cryptographically secure |

## Development

### Running Tests

```bash
pytest
```

### Type Checking

```bash
mypy src/
```

### Linting

```bash
ruff check src/
ruff format src/
```

## License

MIT License - see LICENSE file for details.
