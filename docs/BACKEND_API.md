# Text File Manager - Backend API Specification

This document provides a complete specification of the backend API for building frontend applications. The backend is located in the `src/` directory and provides secure encrypted data sharding with multi-location storage support.

## Table of Contents

1. [Overview](#overview)
2. [Core Concepts](#core-concepts)
3. [Storage Modes](#storage-modes)
4. [Password Configuration](#password-configuration)
5. [AWS Credentials Management](#aws-credentials-management)
6. [Client API](#client-api)
7. [Data Types](#data-types)
8. [Exceptions](#exceptions)
9. [Backend Interfaces](#backend-interfaces)
10. [Usage Examples](#usage-examples)

---

## Overview

The backend provides encrypted data sharding using Shamir's Secret Sharing, distributing encrypted shards across local storage and/or AWS S3 buckets. Key security features:

- **Encryption**: ChaCha20-Poly1305 authenticated encryption (AEAD)
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 600,000 iterations
- **Secret Sharing**: Shamir's Secret Sharing with configurable K-of-N threshold
- **Integrity**: SHA-256 hash verification on reconstruction
- **Per-Location Passwords**: Different passwords for local, AWS-1, and AWS-2 storage

### Import Statement

```python
from src import (
    # Main client
    SecureShardingClient,
    StorageMode,
    ShardDistribution,

    # Password configuration
    PasswordConfig,
    PasswordMode,
    StoragePasswords,

    # AWS credentials
    AWSCredentials,
    CredentialStore,

    # Result types
    ShardResult,
    DeletionResult,

    # Exceptions
    ShardManagerError,
    PasswordTooShortError,
    DecryptionError,
    IntegrityError,
    InsufficientShardsError,
    ConfigurationError,
    StorageError,
)
```

---

## Core Concepts

### Sharding

Data is split into N shares using Shamir's Secret Sharing, where any K shares can reconstruct the original data. Each share is encrypted before storage.

### Threshold

The minimum number of shards (K) required to reconstruct data. Must be ≤ total shards (N).

### Storage Locations

Three types of storage locations:
1. **Local**: Directories on the local filesystem
2. **AWS Account 1**: S3 bucket in first AWS account
3. **AWS Account 2**: S3 bucket in second AWS account

---

## Storage Modes

### StorageMode Enum

```python
class StorageMode(Enum):
    LOCAL = "local"    # 100% local storage
    CLOUD = "cloud"    # 100% cloud storage (2 AWS accounts)
    HYBRID = "hybrid"  # Mixed local + cloud storage
```

### Mode Details

| Mode | Description | Shards Distribution |
|------|-------------|---------------------|
| `LOCAL` | All shards stored locally | All in local directories |
| `CLOUD` | All shards in AWS S3 | Split across 2 AWS accounts |
| `HYBRID` | Mixed local and cloud | Local + AWS-1 + AWS-2 |

### HYBRID Mode Security Properties

Default configuration: 6 shards (2 local, 2 AWS-1, 2 AWS-2), threshold 3

| Access Scenario | Shards Available | Can Reconstruct? |
|-----------------|------------------|------------------|
| Local only | 2 | No |
| AWS-1 only | 2 | No |
| AWS-2 only | 2 | No |
| Local + AWS-1 | 4 | Yes |
| Local + AWS-2 | 4 | Yes |
| AWS-1 + AWS-2 | 4 | Yes |
| All three | 6 | Yes |

---

## Password Configuration

### PasswordConfig Class

Factory class for creating password configurations.

#### Methods

##### `PasswordConfig.single(password: str) -> PasswordConfig`

Create configuration with same password for all locations.

**Parameters:**
- `password`: Password string (minimum 12 characters)

**Returns:** `PasswordConfig` instance

**Example:**
```python
passwords = PasswordConfig.single("my-secure-password-12chars")
```

##### `PasswordConfig.separate(local: str, aws_account1: str, aws_account2: str) -> PasswordConfig`

Create configuration with different password for each location.

**Parameters:**
- `local`: Password for local storage (min 12 chars)
- `aws_account1`: Password for AWS account 1 (min 12 chars)
- `aws_account2`: Password for AWS account 2 (min 12 chars)

**Returns:** `PasswordConfig` instance

**Example:**
```python
passwords = PasswordConfig.separate(
    local="local-password-12",
    aws_account1="aws1-password-12",
    aws_account2="aws2-password-12",
)
```

##### `PasswordConfig.prefix_suffix(prefix: str, local_suffix: str, aws1_suffix: str, aws2_suffix: str) -> PasswordConfig`

Create configuration with common prefix and unique suffixes.

**Parameters:**
- `prefix`: Common prefix for all passwords
- `local_suffix`: Suffix for local password
- `aws1_suffix`: Suffix for AWS-1 password
- `aws2_suffix`: Suffix for AWS-2 password

**Returns:** `PasswordConfig` instance

**Example:**
```python
passwords = PasswordConfig.prefix_suffix(
    prefix="company-2024-",
    local_suffix="local-drive",
    aws1_suffix="primary-cloud",
    aws2_suffix="backup-cloud",
)
# Results in:
# - local: "company-2024-local-drive"
# - aws1: "company-2024-primary-cloud"
# - aws2: "company-2024-backup-cloud"
```

#### Instance Methods

##### `get_passwords() -> StoragePasswords`

Get resolved passwords for all locations.

##### `get_password(location: str) -> str`

Get password for specific location.

**Parameters:**
- `location`: One of "local", "aws_account1", "aws_account2"

### StoragePasswords Dataclass

```python
@dataclass
class StoragePasswords:
    local: str           # Password for local storage
    aws_account1: str    # Password for AWS account 1
    aws_account2: str    # Password for AWS account 2
```

---

## AWS Credentials Management

### AWSCredentials Dataclass

Container for AWS credentials.

```python
@dataclass
class AWSCredentials:
    access_key_id: str
    secret_access_key: str
    session_token: str | None = None
    region: str | None = None
```

#### Methods

##### `to_dict() -> dict`

Convert to dictionary for serialization.

##### `from_dict(data: dict) -> AWSCredentials` (classmethod)

Create from dictionary.

##### `to_boto3_config() -> dict`

Convert to boto3 client configuration.

### CredentialStore Class

Secure encrypted storage for AWS credentials.

#### Constructor

```python
CredentialStore(storage_path: str | Path)
```

**Parameters:**
- `storage_path`: Directory for storing encrypted credential files

#### Methods

##### `store_credentials(account_id: str, credentials: AWSCredentials, password: str, metadata: dict | None = None) -> Path`

Store encrypted AWS credentials.

**Parameters:**
- `account_id`: Unique identifier (e.g., "aws_account1")
- `credentials`: AWS credentials to encrypt
- `password`: Encryption password (min 12 chars)
- `metadata`: Optional metadata (stored unencrypted)

**Returns:** Path to stored credential file

**Raises:** `ConfigurationError` if password too short

##### `load_credentials(account_id: str, password: str) -> AWSCredentials`

Load and decrypt AWS credentials.

**Parameters:**
- `account_id`: Identifier for credentials to load
- `password`: Decryption password

**Returns:** Decrypted `AWSCredentials`

**Raises:**
- `ConfigurationError` if credentials not found
- `DecryptionError` if wrong password

##### `has_credentials(account_id: str) -> bool`

Check if credentials exist for an account.

##### `delete_credentials(account_id: str, secure: bool = True) -> bool`

Delete stored credentials.

**Parameters:**
- `account_id`: Identifier for credentials
- `secure`: Overwrite with random data before deletion

**Returns:** True if deleted, False if not found

##### `list_accounts() -> list[str]`

List all stored account IDs.

---

## Client API

### SecureShardingClient Class

Main client for storing and retrieving encrypted sharded data.

#### Factory Methods

##### `SecureShardingClient.create_local(directories: list[str], threshold: int = 3, password: str | None = None) -> SecureShardingClient`

Create client for 100% local storage.

**Parameters:**
- `directories`: List of local directory paths
- `threshold`: Minimum shards for reconstruction (default: 3)
- `password`: Optional default password

**Returns:** Configured client

**Raises:** `ConfigurationError` if directories < threshold

**Example:**
```python
client = SecureShardingClient.create_local(
    directories=['/data/shard1', '/data/shard2', '/data/shard3'],
    threshold=2,
)
```

##### `SecureShardingClient.create_cloud(aws_account1_config: dict, aws_account2_config: dict, threshold: int = 3, account1_shards: int = 3, account2_shards: int = 2, aws_account1_credentials: AWSCredentials | None = None, aws_account2_credentials: AWSCredentials | None = None, passwords: PasswordConfig | None = None, credential_store_path: str | Path | None = None) -> SecureShardingClient`

Create client for 100% cloud storage.

**Parameters:**
- `aws_account1_config`: S3 config for account 1 (see AWS Config below)
- `aws_account2_config`: S3 config for account 2
- `threshold`: Minimum shards for reconstruction
- `account1_shards`: Number of shards in account 1
- `account2_shards`: Number of shards in account 2
- `aws_account1_credentials`: Optional AWS credentials for account 1
- `aws_account2_credentials`: Optional AWS credentials for account 2
- `passwords`: Optional password configuration
- `credential_store_path`: Path to store encrypted credentials

**Returns:** Configured client

##### `SecureShardingClient.create_hybrid(local_directories: list[str], aws_account1_config: dict, aws_account2_config: dict, local_shards: int | None = None, account1_shards: int | None = None, account2_shards: int | None = None, aws_account1_credentials: AWSCredentials | None = None, aws_account2_credentials: AWSCredentials | None = None, passwords: PasswordConfig | None = None, credential_store_path: str | Path | None = None) -> SecureShardingClient`

Create client for hybrid local + cloud storage.

**Parameters:**
- `local_directories`: List of local directory paths
- `aws_account1_config`: S3 config for account 1
- `aws_account2_config`: S3 config for account 2
- `local_shards`: Number of local shards (default: len(directories))
- `account1_shards`: Shards in account 1 (default: 2)
- `account2_shards`: Shards in account 2 (default: 2)
- `aws_account1_credentials`: Optional AWS credentials
- `aws_account2_credentials`: Optional AWS credentials
- `passwords`: Optional password configuration
- `credential_store_path`: Path to store encrypted credentials

**Returns:** Configured client

##### `SecureShardingClient.load_with_credentials(credential_store_path: str | Path, passwords: PasswordConfig, ...) -> SecureShardingClient`

Load client using previously stored encrypted credentials.

**Parameters:**
- `credential_store_path`: Path where credentials are stored
- `passwords`: Passwords for decryption
- Additional parameters same as create_hybrid

**Returns:** Configured client with loaded credentials

#### AWS Config Dictionary

```python
aws_config = {
    'bucket': str,           # Required: S3 bucket name
    'region': str,           # Required: AWS region (e.g., 'us-east-1')
    'profile_name': str,     # Optional: AWS CLI profile name
    'role_arn': str,         # Optional: IAM role ARN for assume-role
    'prefix': str,           # Optional: S3 key prefix (default: 'shards/')
    'endpoint_url': str,     # Optional: Custom endpoint (for LocalStack)
}
```

#### Instance Methods

##### `store(key: str, data: bytes, password: str | PasswordConfig | None = None, metadata: dict[str, str] | None = None) -> ShardResult`

Store data as encrypted shards.

**Parameters:**
- `key`: Unique identifier for the data (supports paths like "secrets/api-key")
- `data`: Raw bytes to store
- `password`: Encryption password (str, PasswordConfig, or None to use configured)
- `metadata`: Optional metadata (stored unencrypted with each shard)

**Returns:** `ShardResult` with storage details

**Raises:**
- `TypeError` if data is not bytes
- `PasswordTooShortError` if password < 12 characters
- `ConfigurationError` if no password provided/configured
- `InsufficientShardsError` if storage fails

**Example:**
```python
result = client.store(
    key='secrets/database-password',
    data=b'my-secret-password',
    password='encryption-password',
    metadata={'environment': 'production'},
)
print(f"Stored {result.total_shares} shards, need {result.threshold} to recover")
```

##### `retrieve(key: str, password: str | PasswordConfig | None = None, verify_integrity: bool = True) -> bytes`

Retrieve and reconstruct data from shards.

**Parameters:**
- `key`: Original key used during storage
- `password`: Decryption password
- `verify_integrity`: Verify SHA-256 hash (default: True)

**Returns:** Reconstructed data as bytes

**Raises:**
- `DecryptionError` if wrong password
- `InsufficientShardsError` if not enough shards available
- `IntegrityError` if data integrity check fails
- `ConfigurationError` if no password provided/configured

**Example:**
```python
data = client.retrieve('secrets/database-password', 'encryption-password')
print(data.decode('utf-8'))
```

##### `delete(key: str, secure: bool = True) -> DeletionResult`

Delete all shards for a key.

**Parameters:**
- `key`: Key to delete
- `secure`: Overwrite with random data before deletion (default: True)

**Returns:** `DeletionResult` with deletion details

**Example:**
```python
result = client.delete('secrets/database-password')
print(f"Deleted {len(result.deleted)} shards")
```

##### `list_keys() -> list[str]`

List all stored keys across all backends.

**Returns:** Sorted list of unique keys

**Example:**
```python
keys = client.list_keys()
for key in keys:
    print(f"  - {key}")
```

##### `get_shard_status(key: str) -> dict`

Get detailed status of shards for a key.

**Returns:** Dictionary with structure:
```python
{
    "key": str,                        # The key
    "threshold": int,                  # Required shards
    "total_shards": int,               # Total shards
    "storage_mode": str,               # "local", "cloud", or "hybrid"
    "shards": [                        # List of shard info
        {
            "index": int,
            "backend_type": str,       # "local" or "aws_s3"
            "location": str,
            "exists": bool,
        },
        ...
    ],
    "local_available": int,            # Available local shards
    "cloud_account1_available": int,   # Available AWS-1 shards
    "cloud_account2_available": int,   # Available AWS-2 shards
    "can_reconstruct": bool,           # True if enough shards available
}
```

#### Properties

##### `storage_mode: StorageMode`

Current storage mode.

##### `distribution: ShardDistribution`

Current shard distribution configuration.

##### `backends: list[StorageBackend]`

List of storage backends.

---

## Data Types

### ShardResult Dataclass

Result of a store operation.

```python
@dataclass
class ShardResult:
    key: str                           # Storage key
    threshold: int                     # Reconstruction threshold
    total_shares: int                  # Total shards created
    data_hash: str                     # SHA-256 hash of original data
    storage_mode: StorageMode          # Storage mode used
    distribution: ShardDistribution    # Shard distribution config
    stored_shards: list[dict]          # List of stored shard info
    success: bool                      # True if enough shards stored
```

### DeletionResult Dataclass

Result of a delete operation.

```python
@dataclass
class DeletionResult:
    key: str                           # Deleted key
    deleted: list[dict]                # Successfully deleted shards
    failed: list[dict]                 # Failed deletions with errors
    success: bool                      # True if all deletions succeeded
```

### ShardDistribution Dataclass

Shard distribution configuration.

```python
@dataclass
class ShardDistribution:
    total_shards: int                  # Total number of shards
    threshold: int                     # Reconstruction threshold
    local_shards: int                  # Number of local shards
    cloud_account1_shards: int         # Shards in AWS account 1
    cloud_account2_shards: int         # Shards in AWS account 2
```

---

## Exceptions

All exceptions inherit from `ShardManagerError`.

| Exception | Description | Attributes |
|-----------|-------------|------------|
| `ShardManagerError` | Base exception | - |
| `PasswordError` | Password validation failed | - |
| `PasswordTooShortError` | Password < 12 characters | `min_length: int` |
| `DecryptionError` | Shard decryption failed | `shard_index: int` |
| `IntegrityError` | Data integrity check failed | `expected_hash: str`, `actual_hash: str` |
| `InsufficientShardsError` | Not enough shards available | `available: int`, `required: int`, `shard_indices: list[int]` |
| `ThresholdError` | Invalid threshold config | `threshold: int`, `total_shares: int` |
| `DirectoryError` | Local directory issues | `directory: str` |
| `StorageError` | Backend operation failed | `backend: str`, `location: str` |
| `ConfigurationError` | Invalid configuration | - |

### Exception Handling Example

```python
from src import (
    SecureShardingClient,
    DecryptionError,
    InsufficientShardsError,
    IntegrityError,
)

try:
    data = client.retrieve('my-key', 'my-password')
except DecryptionError as e:
    print(f"Wrong password for shard {e.shard_index}")
except InsufficientShardsError as e:
    print(f"Only {e.available}/{e.required} shards available")
    print(f"Available indices: {e.shard_indices}")
except IntegrityError as e:
    print(f"Data corrupted! Expected {e.expected_hash}, got {e.actual_hash}")
```

---

## Backend Interfaces

For advanced use cases, backends can be used directly.

### StorageBackend Abstract Class

Base class for all storage backends.

#### Abstract Properties

- `storage_type: StorageType` - Backend type (LOCAL or AWS_S3)
- `location: StorageLocation` - Location configuration

#### Abstract Methods

- `write_shard(key, shard_index, data) -> dict`
- `read_shard(key, shard_index) -> str | None`
- `delete_shard(key, shard_index, secure) -> bool`
- `shard_exists(key, shard_index) -> bool`
- `list_shards(key=None) -> list[tuple[str, int]]`

### LocalStorageBackend

Local filesystem backend.

```python
from src import LocalStorageBackend

backend = LocalStorageBackend('/path/to/shards')
backend.write_shard('my-key', 0, '{"data": "..."}')
data = backend.read_shard('my-key', 0)
```

### S3StorageBackend

AWS S3 backend.

```python
from src import S3StorageBackend

backend = S3StorageBackend(
    bucket_name='my-bucket',
    region='us-east-1',
    prefix='shards/',
    profile_name='my-profile',  # or role_arn
)
```

---

## Usage Examples

### Example 1: Simple Local Storage

```python
from src import SecureShardingClient

# Create client
client = SecureShardingClient.create_local(
    directories=['/tmp/shard1', '/tmp/shard2', '/tmp/shard3'],
    threshold=2,
)

# Store secret
client.store('api-key', b'secret-value', 'my-password-12')

# Retrieve secret
data = client.retrieve('api-key', 'my-password-12')
print(data.decode())  # 'secret-value'

# List and delete
print(client.list_keys())  # ['api-key']
client.delete('api-key')
```

### Example 2: Hybrid Mode with Per-Location Passwords

```python
from src import SecureShardingClient, PasswordConfig, AWSCredentials

# Configure different passwords for each location
passwords = PasswordConfig.separate(
    local="local-secure-pwd",
    aws_account1="aws1-secure-pwd",
    aws_account2="aws2-secure-pwd",
)

# Create hybrid client
client = SecureShardingClient.create_hybrid(
    local_directories=['/secure/drive1', '/secure/drive2'],
    aws_account1_config={'bucket': 'shards-primary', 'region': 'us-east-1'},
    aws_account2_config={'bucket': 'shards-backup', 'region': 'eu-west-1'},
    aws_account1_credentials=AWSCredentials('AKIA...', 'secret1...'),
    aws_account2_credentials=AWSCredentials('AKIA...', 'secret2...'),
    passwords=passwords,
    credential_store_path='/secure/credentials',
)

# Store with per-location encryption
result = client.store(
    key='production/database-creds',
    data=b'{"host": "db.example.com", "password": "..."}',
    password=passwords,
)

# Check status
status = client.get_shard_status('production/database-creds')
print(f"Can reconstruct: {status['can_reconstruct']}")
print(f"Local: {status['local_available']}")
print(f"AWS-1: {status['cloud_account1_available']}")
print(f"AWS-2: {status['cloud_account2_available']}")
```

### Example 3: Loading Stored Credentials

```python
from src import SecureShardingClient, PasswordConfig

# Later session - load using stored encrypted credentials
passwords = PasswordConfig.separate(
    local="local-secure-pwd",
    aws_account1="aws1-secure-pwd",
    aws_account2="aws2-secure-pwd",
)

client = SecureShardingClient.load_with_credentials(
    credential_store_path='/secure/credentials',
    passwords=passwords,
    local_directories=['/secure/drive1', '/secure/drive2'],
    aws_account1_config={'bucket': 'shards-primary', 'region': 'us-east-1'},
    aws_account2_config={'bucket': 'shards-backup', 'region': 'eu-west-1'},
)

# Retrieve with per-location passwords
data = client.retrieve('production/database-creds', passwords)
```

---

## Security Considerations

### Password Requirements

- Minimum 12 characters
- Unique per location recommended for hybrid mode
- Stored encrypted credentials use same security as shards

### Cryptographic Parameters

| Parameter | Value |
|-----------|-------|
| Key Derivation | PBKDF2-HMAC-SHA256 |
| Iterations | 600,000 |
| Encryption | ChaCha20-Poly1305 |
| Key Size | 256 bits |
| Nonce Size | 96 bits |
| Salt Size | 256 bits |
| Integrity Hash | SHA-256 |

### File Permissions

- Directories: 0o700 (owner only)
- Shard files: 0o600 (owner read/write only)
- Credential files: 0o600

---

## Version

Current API Version: **2.1** (Shard format version in stored files)

Package Version: **0.3.0**

---

## REST API Reference

The REST API frontend provides HTTP access to all backend functionality. See below for endpoint specifications.

### Base URL

Default: `http://localhost:8000`

### Authentication

The REST API does not implement authentication. Deploy behind a reverse proxy with authentication for production use.

### Common Response Format

All responses include a `status` field:
- Success: `{"status": "ok", ...}`
- Error: `{"status": "error", "error": "ErrorType", "message": "..."}`

### Endpoints

#### Health & Status

##### `GET /health`

Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "version": "1.0.0",
  "configured": true,
  "storage_mode": "hybrid"
}
```

##### `GET /api/status`

Get current configuration status.

**Response:**
```json
{
  "status": "configured",
  "message": "Storage configured in hybrid mode"
}
```

##### `POST /api/reset`

Reset storage configuration.

**Response:**
```json
{
  "status": "ok",
  "message": "Configuration reset successfully"
}
```

#### Configuration

##### `POST /api/config/local`

Configure local storage mode.

**Request Body:**
```json
{
  "directories": ["/path/to/shard1", "/path/to/shard2", "/path/to/shard3"],
  "threshold": 2,
  "passwords": {
    "mode": "single",
    "password": "my-secure-password-12"
  }
}
```

**Response (201 Created):**
```json
{
  "status": "ok",
  "storage_mode": "local",
  "total_shards": 3,
  "threshold": 2,
  "local_shards": 3,
  "cloud_account1_shards": 0,
  "cloud_account2_shards": 0
}
```

##### `POST /api/config/cloud`

Configure cloud storage mode.

**Request Body:**
```json
{
  "aws_account1": {
    "bucket": "my-bucket-1",
    "region": "us-east-1",
    "prefix": "shards/"
  },
  "aws_account2": {
    "bucket": "my-bucket-2",
    "region": "eu-west-1"
  },
  "threshold": 3,
  "account1_shards": 3,
  "account2_shards": 2,
  "aws_account1_credentials": {
    "access_key_id": "AKIA...",
    "secret_access_key": "...",
    "region": "us-east-1"
  },
  "aws_account2_credentials": {
    "access_key_id": "AKIA...",
    "secret_access_key": "..."
  },
  "passwords": {
    "mode": "separate",
    "local_password": "local-pwd-12345",
    "aws1_password": "aws1-pwd-123456",
    "aws2_password": "aws2-pwd-123456"
  },
  "credential_store_path": "/path/to/credentials"
}
```

##### `POST /api/config/hybrid`

Configure hybrid storage mode.

**Request Body:**
```json
{
  "local_directories": ["/path/to/local1", "/path/to/local2"],
  "aws_account1": {
    "bucket": "my-bucket-1",
    "region": "us-east-1"
  },
  "aws_account2": {
    "bucket": "my-bucket-2",
    "region": "eu-west-1"
  },
  "local_shards": 2,
  "account1_shards": 2,
  "account2_shards": 2,
  "passwords": {
    "mode": "prefix_suffix",
    "prefix": "company-2024-",
    "local_suffix": "local-xyz",
    "aws1_suffix": "aws1-abc123",
    "aws2_suffix": "aws2-def456"
  }
}
```

#### Data Operations

##### `GET /api/keys`

List all stored keys.

**Response:**
```json
{
  "status": "ok",
  "keys": ["secrets/api-key", "config/database"],
  "count": 2
}
```

##### `POST /api/data/{key}`

Store encrypted data.

**Path Parameters:**
- `key`: Storage key (supports path segments like `secrets/api-key`)

**Request Body:**
```json
{
  "data": "my-secret-data",
  "password": "my-secure-password-12",
  "metadata": {
    "environment": "production"
  },
  "is_base64": false
}
```

For binary data, set `is_base64: true` and provide base64-encoded data.

**Response (201 Created):**
```json
{
  "status": "ok",
  "key": "secrets/api-key",
  "threshold": 2,
  "total_shares": 3,
  "stored_shards": 3,
  "data_hash": "a1b2c3d4...",
  "storage_mode": "local"
}
```

##### `POST /api/data/{key}/retrieve`

Retrieve and decrypt data.

**Request Body:**
```json
{
  "password": "my-secure-password-12",
  "verify_integrity": true
}
```

**Response:**
```json
{
  "status": "ok",
  "key": "secrets/api-key",
  "data": "bXktc2VjcmV0LWRhdGE=",
  "size": 14,
  "integrity_verified": true
}
```

Note: `data` is always base64-encoded.

##### `DELETE /api/data/{key}`

Delete stored data.

**Request Body (optional):**
```json
{
  "secure": true
}
```

**Response:**
```json
{
  "status": "ok",
  "key": "secrets/api-key",
  "deleted_count": 3,
  "failed_count": 0
}
```

##### `GET /api/data/{key}/status`

Get shard status.

**Response:**
```json
{
  "status": "ok",
  "key": "secrets/api-key",
  "threshold": 2,
  "total_shards": 3,
  "storage_mode": "local",
  "can_reconstruct": true,
  "local_available": 3,
  "cloud_account1_available": 0,
  "cloud_account2_available": 0,
  "shards": [
    {
      "index": 0,
      "backend_type": "local",
      "location": "/path/to/shard1",
      "exists": true
    }
  ]
}
```

#### Credential Management

##### `GET /api/credentials?store_path=/path/to/store`

List stored credential accounts.

**Query Parameters:**
- `store_path`: Path to credential store (optional if configured)

**Response:**
```json
{
  "status": "ok",
  "accounts": ["aws_account1", "aws_account2"],
  "count": 2
}
```

##### `POST /api/credentials?store_path=/path/to/store`

Store encrypted credentials.

**Request Body:**
```json
{
  "account_id": "aws_account1",
  "credentials": {
    "access_key_id": "AKIA...",
    "secret_access_key": "...",
    "region": "us-east-1"
  },
  "password": "credential-password-12",
  "metadata": {
    "environment": "production"
  }
}
```

**Response (201 Created):**
```json
{
  "status": "ok",
  "account_id": "aws_account1",
  "path": "/path/to/store/aws_account1.credentials.enc"
}
```

##### `POST /api/credentials/{account_id}?store_path=/path/to/store`

Load and verify credentials (for testing password).

**Request Body:**
```json
{
  "password": "credential-password-12"
}
```

**Response:**
```json
{
  "status": "ok",
  "account_id": "aws_account1",
  "access_key_id_prefix": "AKIA1234...",
  "region": "us-east-1"
}
```

##### `DELETE /api/credentials/{account_id}?store_path=/path/to/store&secure=true`

Delete stored credentials.

**Query Parameters:**
- `store_path`: Path to credential store
- `secure`: Secure deletion (default: true)

**Response:**
```json
{
  "status": "ok",
  "message": "Credentials for aws_account1 deleted"
}
```

### Error Responses

#### 400 Bad Request

Invalid request or configuration error.

```json
{
  "status": "error",
  "error": "ConfigurationError",
  "message": "Password must be at least 12 characters"
}
```

#### 401 Unauthorized

Authentication/decryption failed.

```json
{
  "status": "error",
  "error": "DecryptionError",
  "message": "Decryption failed: wrong password or corrupted data"
}
```

#### 404 Not Found

Resource not found.

```json
{
  "status": "error",
  "error": "NotFound",
  "message": "Credentials not found for account: unknown"
}
```

#### 409 Conflict

Storage not configured.

```json
{
  "status": "error",
  "error": "Conflict",
  "message": "Storage not configured. Call POST /api/config/* first."
}
```

#### 422 Unprocessable Entity

Operation cannot be completed (e.g., insufficient shards).

```json
{
  "status": "error",
  "error": "InsufficientShardsError",
  "message": "Insufficient shards: 1/2 available"
}
```

### Password Configuration Modes

The `passwords` object in configuration requests supports three modes:

#### Single Mode
```json
{
  "mode": "single",
  "password": "same-password-for-all-12"
}
```

#### Separate Mode
```json
{
  "mode": "separate",
  "local_password": "local-password-12",
  "aws1_password": "aws1-password-123",
  "aws2_password": "aws2-password-123"
}
```

#### Prefix+Suffix Mode
```json
{
  "mode": "prefix_suffix",
  "prefix": "company-",
  "local_suffix": "local-2024-abc",
  "aws1_suffix": "aws1-2024-def",
  "aws2_suffix": "aws2-2024-ghi"
}
```
