# Text File Manager

A secure Python library for managing sensitive data using encrypted sharding with Shamir's Secret Sharing. Supports local storage, cloud storage (AWS S3), and hybrid configurations for maximum security and redundancy.

## Overview

Text File Manager provides a defense-in-depth approach to storing sensitive data:

1. **Data Sharding**: Splits data using Shamir's Secret Sharing (K-of-N threshold scheme)
2. **Encryption**: Each shard is encrypted with ChaCha20-Poly1305 authenticated encryption
3. **Distribution**: Shards can be stored locally, in AWS S3, or across multiple locations

## Storage Modes

### 1. Local Mode (100% Local)

All shards stored on the local filesystem across multiple directories (ideally on separate drives).

```python
from src import SecureShardingClient

client = SecureShardingClient.create_local(
    directories=['/secure/drive1', '/secure/drive2', '/secure/drive3'],
    threshold=2,  # Need 2 of 3 shards to reconstruct
)
```

**Use case**: Single-machine security, air-gapped systems, local development.

### 2. Cloud Mode (100% Cloud)

All shards stored in AWS S3, distributed across 2 separate AWS accounts for cross-account redundancy.

```python
from src import SecureShardingClient

client = SecureShardingClient.create_cloud(
    aws_account1_config={
        'bucket': 'shards-account1',
        'region': 'us-east-1',
        'profile_name': 'account1-profile',  # or use role_arn
    },
    aws_account2_config={
        'bucket': 'shards-account2',
        'region': 'us-west-2',
        'profile_name': 'account2-profile',
    },
    threshold=3,
    account1_shards=3,
    account2_shards=2,
)
```

**Use case**: Cloud-native applications, serverless architectures, multi-region redundancy.

### 3. Hybrid Mode (50% Local + 50% Cloud)

Shards distributed between local storage and 2 AWS accounts. This mode is designed with specific security properties:

- **Local alone cannot reconstruct**: Prevents recovery if only local storage is accessed
- **Single AWS account alone cannot reconstruct**: Prevents recovery if one cloud account is compromised
- **Local + any one AWS account CAN reconstruct**: Allows recovery with partial access
- **Both AWS accounts CAN reconstruct**: Allows recovery even if local storage is lost

```python
from src import SecureShardingClient

client = SecureShardingClient.create_hybrid(
    local_directories=['/secure/drive1', '/secure/drive2'],
    aws_account1_config={
        'bucket': 'shards-account1',
        'region': 'us-east-1',
    },
    aws_account2_config={
        'bucket': 'shards-account2',
        'region': 'us-west-2',
    },
    local_shards=2,
    account1_shards=2,
    account2_shards=2,
)
# Default distribution: 6 shards, threshold 3
# - 2 local shards
# - 2 AWS account 1 shards
# - 2 AWS account 2 shards
# Recovery requires: local + AWS1, OR local + AWS2, OR AWS1 + AWS2
```

**Use case**: High-security applications, compliance requirements, disaster recovery.

## Features

- **Shamir's Secret Sharing**: Configure any K-of-N threshold
- **ChaCha20-Poly1305**: Modern authenticated encryption (AEAD)
- **PBKDF2-HMAC-SHA256**: 600,000 iterations (OWASP 2023 recommendation)
- **Cross-Account Storage**: Distribute across multiple AWS accounts
- **Unique Cryptographic Material**: Each shard uses unique salt and nonce
- **Integrity Verification**: SHA-256 hash verification on reconstruction
- **Secure Deletion**: Random data overwriting before file deletion
- **Restrictive Permissions**: Files (0o600), directories (0o700)

## Installation

### Basic (Local Storage Only)

```bash
pip install cryptography sslib python-dotenv
```

### With AWS Support

```bash
pip install cryptography sslib python-dotenv boto3
```

### Development Installation

```bash
git clone https://github.com/example/text-file-manager.git
cd text-file-manager
pip install -e ".[all]"  # Includes AWS and dev dependencies
```

## Quick Start

### Store and Retrieve Data

```python
from src import SecureShardingClient

# Create client (local mode for this example)
client = SecureShardingClient.create_local(
    directories=['/tmp/shards/d1', '/tmp/shards/d2', '/tmp/shards/d3'],
    threshold=2,
)

# Store sensitive data
result = client.store(
    key='secrets/api-key',
    data=b'my-super-secret-api-key',
    password='my-secure-password-here',  # Min 12 characters
)
print(f"Stored {len(result.stored_shards)} shards")

# Retrieve data
data = client.retrieve(
    key='secrets/api-key',
    password='my-secure-password-here',
)
print(data.decode('utf-8'))  # 'my-super-secret-api-key'

# Check shard status
status = client.get_shard_status('secrets/api-key')
print(f"Can reconstruct: {status['can_reconstruct']}")

# Delete when done
client.delete('secrets/api-key', secure=True)
```

### Hybrid Mode Example

```python
from src import SecureShardingClient

# Configure hybrid storage
client = SecureShardingClient.create_hybrid(
    local_directories=['/secure/local1', '/secure/local2'],
    aws_account1_config={
        'bucket': 'company-shards-primary',
        'region': 'us-east-1',
        'profile_name': 'primary-account',
    },
    aws_account2_config={
        'bucket': 'company-shards-backup',
        'region': 'eu-west-1',
        'profile_name': 'backup-account',
    },
)

# Store with automatic distribution
result = client.store(
    key='secrets/database-credentials',
    data=b'{"host": "...", "password": "..."}',
    password='ultra-secure-password',
    metadata={'environment': 'production'},
)

# Check distribution
print(f"Storage mode: {result.storage_mode.value}")
print(f"Threshold: {result.threshold}/{result.total_shares}")
print(f"Local shards: {result.distribution.local_shards}")
print(f"Cloud shards: {result.distribution.cloud_account1_shards + result.distribution.cloud_account2_shards}")
```

## API Reference

### SecureShardingClient

The main class for multi-backend sharding operations.

#### Factory Methods

```python
# 100% Local storage
SecureShardingClient.create_local(
    directories: list[str],
    threshold: int = 3,
) -> SecureShardingClient

# 100% Cloud storage (2 AWS accounts)
SecureShardingClient.create_cloud(
    aws_account1_config: dict,
    aws_account2_config: dict,
    threshold: int = 3,
    account1_shards: int = 3,
    account2_shards: int = 2,
) -> SecureShardingClient

# Hybrid local + cloud storage
SecureShardingClient.create_hybrid(
    local_directories: list[str],
    aws_account1_config: dict,
    aws_account2_config: dict,
    local_shards: int | None = None,
    account1_shards: int | None = None,
    account2_shards: int | None = None,
) -> SecureShardingClient
```

#### AWS Config Options

```python
aws_config = {
    'bucket': str,           # Required: S3 bucket name
    'region': str,           # Required: AWS region
    'profile_name': str,     # Optional: AWS CLI profile
    'role_arn': str,         # Optional: IAM role for cross-account
    'prefix': str,           # Optional: S3 key prefix (default: 'shards/')
    'endpoint_url': str,     # Optional: Custom endpoint (for LocalStack)
}
```

#### Methods

```python
# Store data
store(key: str, data: bytes, password: str, metadata: dict | None = None) -> ShardResult

# Retrieve data
retrieve(key: str, password: str, verify_integrity: bool = True) -> bytes

# Delete data
delete(key: str, secure: bool = True) -> DeletionResult

# List all keys
list_keys() -> list[str]

# Get shard status
get_shard_status(key: str) -> dict
```

### Storage Backends

For advanced use cases, you can use backends directly:

```python
from src import LocalStorageBackend, S3StorageBackend

# Local backend
local = LocalStorageBackend('/path/to/shards')

# S3 backend
s3 = S3StorageBackend(
    bucket_name='my-bucket',
    region='us-east-1',
    prefix='shards/',
)
```

### Exception Classes

| Exception | Description |
|-----------|-------------|
| `ShardManagerError` | Base exception for all errors |
| `PasswordTooShortError` | Password below 12 characters |
| `DecryptionError` | Shard decryption failed |
| `IntegrityError` | Data integrity check failed |
| `InsufficientShardsError` | Not enough shards for reconstruction |
| `ThresholdError` | Invalid threshold configuration |
| `DirectoryError` | Local directory issues |
| `StorageError` | Backend storage operation failed |
| `ConfigurationError` | Invalid storage mode configuration |

## Security Considerations

### Hybrid Mode Security Properties

The hybrid mode (default: 6 shards, threshold 4) ensures:

| Scenario | Can Reconstruct? |
|----------|------------------|
| Local only (2 shards) | No |
| AWS Account 1 only (2 shards) | No |
| AWS Account 2 only (2 shards) | No |
| Local + AWS Account 1 (4 shards) | Yes |
| Local + AWS Account 2 (4 shards) | Yes |
| AWS Account 1 + AWS Account 2 (4 shards) | Yes |
| All three (6 shards) | Yes |

### Best Practices

1. **Use Strong Passwords**: Minimum 12 characters, prefer passphrases
2. **Separate AWS Accounts**: Use different AWS accounts, not just different buckets
3. **Enable S3 Versioning**: Protect against accidental deletion
4. **Use IAM Roles**: Prefer role assumption over long-lived credentials
5. **Physical Separation**: For local mode, use different physical drives
6. **Regular Backups**: Maintain independent backups of shard locations
7. **Monitor Access**: Enable CloudTrail for S3 access logging

### Threat Model

**Protects against:**
- Data theft from single storage location
- Compromise of single AWS account
- Brute force attacks (600K PBKDF2 iterations)
- Data tampering (ChaCha20-Poly1305 authentication)

**Does NOT protect against:**
- Compromised passwords
- Compromise of threshold+ storage locations
- Memory-based attacks during processing
- Quantum computing attacks (future consideration)

### Cryptographic Details

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Key Derivation | PBKDF2-HMAC-SHA256 | 600,000 iterations |
| Encryption | ChaCha20-Poly1305 | 256-bit key, 96-bit nonce |
| Integrity | SHA-256 | Pre-encryption hash |
| Secret Sharing | Shamir's SSS | Configurable K-of-N |
| Random Generation | `secrets` module | Cryptographically secure |

## Configuration

### Environment Variables

```bash
# Local shard directories
export SHARD_DIR_1=/path/to/shard1
export SHARD_DIR_2=/path/to/shard2

# AWS configuration (or use AWS CLI profiles)
export AWS_PROFILE_ACCOUNT1=primary-account
export AWS_PROFILE_ACCOUNT2=backup-account
```

### AWS IAM Policy (Minimum Required)

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject",
                "s3:ListBucket",
                "s3:HeadObject"
            ],
            "Resource": [
                "arn:aws:s3:::your-shard-bucket",
                "arn:aws:s3:::your-shard-bucket/*"
            ]
        }
    ]
}
```

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

## Legacy API

The original `SecureLocalShardingClient` is still available for backwards compatibility:

```python
from src import SecureLocalShardingClient

client = SecureLocalShardingClient(['/path/shard1', '/path/shard2', '/path/shard3'])
client.store_sharded('key', b'data', 'password')
```

## License

MIT License - see LICENSE file for details.
