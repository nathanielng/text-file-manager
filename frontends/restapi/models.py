"""
Pydantic models for REST API request/response schemas.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class StorageModeEnum(str, Enum):
    """Storage mode options."""

    LOCAL = "local"
    CLOUD = "cloud"
    HYBRID = "hybrid"


class PasswordModeEnum(str, Enum):
    """Password configuration mode."""

    SINGLE = "single"
    SEPARATE = "separate"
    PREFIX_SUFFIX = "prefix_suffix"


# -----------------------------------------------------------------------------
# Configuration Models
# -----------------------------------------------------------------------------


class AWSConfigRequest(BaseModel):
    """AWS S3 configuration."""

    bucket: str = Field(..., description="S3 bucket name")
    region: str = Field(..., description="AWS region")
    profile_name: str | None = Field(None, description="AWS CLI profile name")
    role_arn: str | None = Field(None, description="IAM role ARN for assume-role")
    prefix: str = Field("shards/", description="S3 key prefix")


class AWSCredentialsRequest(BaseModel):
    """AWS credentials for storage."""

    access_key_id: str = Field(..., description="AWS access key ID")
    secret_access_key: str = Field(..., description="AWS secret access key")
    session_token: str | None = Field(None, description="Session token for temporary credentials")
    region: str | None = Field(None, description="AWS region")


class PasswordConfigRequest(BaseModel):
    """Password configuration."""

    mode: PasswordModeEnum = Field(PasswordModeEnum.SINGLE, description="Password mode")
    password: str | None = Field(None, description="Single password (for single mode)")
    local_password: str | None = Field(None, description="Local password (for separate mode)")
    aws1_password: str | None = Field(None, description="AWS account 1 password (for separate mode)")
    aws2_password: str | None = Field(None, description="AWS account 2 password (for separate mode)")
    prefix: str | None = Field(None, description="Common prefix (for prefix_suffix mode)")
    local_suffix: str | None = Field(None, description="Local suffix (for prefix_suffix mode)")
    aws1_suffix: str | None = Field(None, description="AWS-1 suffix (for prefix_suffix mode)")
    aws2_suffix: str | None = Field(None, description="AWS-2 suffix (for prefix_suffix mode)")

    @field_validator("password", "local_password", "aws1_password", "aws2_password")
    @classmethod
    def validate_password_length(cls, v: str | None) -> str | None:
        if v is not None and len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        return v


class LocalConfigRequest(BaseModel):
    """Configuration for local storage mode."""

    directories: list[str] = Field(..., min_length=2, description="Local directory paths")
    threshold: int = Field(3, ge=2, description="Minimum shards for reconstruction")
    passwords: PasswordConfigRequest | None = Field(None, description="Password configuration")


class CloudConfigRequest(BaseModel):
    """Configuration for cloud storage mode."""

    aws_account1: AWSConfigRequest = Field(..., description="AWS account 1 configuration")
    aws_account2: AWSConfigRequest = Field(..., description="AWS account 2 configuration")
    threshold: int = Field(3, ge=2, description="Minimum shards for reconstruction")
    account1_shards: int = Field(3, ge=1, description="Shards in account 1")
    account2_shards: int = Field(2, ge=1, description="Shards in account 2")
    aws_account1_credentials: AWSCredentialsRequest | None = Field(
        None, description="AWS account 1 credentials"
    )
    aws_account2_credentials: AWSCredentialsRequest | None = Field(
        None, description="AWS account 2 credentials"
    )
    passwords: PasswordConfigRequest | None = Field(None, description="Password configuration")
    credential_store_path: str | None = Field(None, description="Path for encrypted credential storage")


class HybridConfigRequest(BaseModel):
    """Configuration for hybrid storage mode."""

    local_directories: list[str] = Field(..., min_length=1, description="Local directory paths")
    aws_account1: AWSConfigRequest = Field(..., description="AWS account 1 configuration")
    aws_account2: AWSConfigRequest = Field(..., description="AWS account 2 configuration")
    local_shards: int | None = Field(None, ge=1, description="Number of local shards")
    account1_shards: int = Field(2, ge=1, description="Shards in account 1")
    account2_shards: int = Field(2, ge=1, description="Shards in account 2")
    aws_account1_credentials: AWSCredentialsRequest | None = Field(
        None, description="AWS account 1 credentials"
    )
    aws_account2_credentials: AWSCredentialsRequest | None = Field(
        None, description="AWS account 2 credentials"
    )
    passwords: PasswordConfigRequest | None = Field(None, description="Password configuration")
    credential_store_path: str | None = Field(None, description="Path for encrypted credential storage")


# -----------------------------------------------------------------------------
# Data Operation Models
# -----------------------------------------------------------------------------


class StoreDataRequest(BaseModel):
    """Request to store data."""

    data: str = Field(..., description="Data to store (base64-encoded for binary)")
    password: str | None = Field(None, min_length=12, description="Encryption password")
    passwords: PasswordConfigRequest | None = Field(None, description="Per-location passwords")
    metadata: dict[str, str] | None = Field(None, description="Optional metadata")
    is_base64: bool = Field(False, description="Whether data is base64-encoded")


class RetrieveDataRequest(BaseModel):
    """Request to retrieve data."""

    password: str | None = Field(None, min_length=12, description="Decryption password")
    passwords: PasswordConfigRequest | None = Field(None, description="Per-location passwords")
    verify_integrity: bool = Field(True, description="Verify SHA-256 hash")


class DeleteDataRequest(BaseModel):
    """Request to delete data."""

    secure: bool = Field(True, description="Overwrite with random data before deletion")


# -----------------------------------------------------------------------------
# Credential Models
# -----------------------------------------------------------------------------


class StoreCredentialsRequest(BaseModel):
    """Request to store AWS credentials."""

    account_id: str = Field(..., description="Account identifier")
    credentials: AWSCredentialsRequest = Field(..., description="AWS credentials")
    password: str = Field(..., min_length=12, description="Encryption password")
    metadata: dict[str, str] | None = Field(None, description="Optional metadata")


class LoadCredentialsRequest(BaseModel):
    """Request to load AWS credentials."""

    password: str = Field(..., min_length=12, description="Decryption password")


# -----------------------------------------------------------------------------
# Response Models
# -----------------------------------------------------------------------------


class StatusResponse(BaseModel):
    """Generic status response."""

    status: str = Field(..., description="Operation status")
    message: str | None = Field(None, description="Additional message")


class ConfigResponse(BaseModel):
    """Configuration response."""

    status: str = Field("ok", description="Operation status")
    storage_mode: str = Field(..., description="Configured storage mode")
    total_shards: int = Field(..., description="Total number of shards")
    threshold: int = Field(..., description="Shards required for reconstruction")
    local_shards: int = Field(0, description="Number of local shards")
    cloud_account1_shards: int = Field(0, description="Number of AWS account 1 shards")
    cloud_account2_shards: int = Field(0, description="Number of AWS account 2 shards")


class StoreResponse(BaseModel):
    """Response from store operation."""

    status: str = Field("ok", description="Operation status")
    key: str = Field(..., description="Storage key")
    threshold: int = Field(..., description="Shards required for reconstruction")
    total_shares: int = Field(..., description="Total shards created")
    stored_shards: int = Field(..., description="Number of shards successfully stored")
    data_hash: str = Field(..., description="SHA-256 hash of original data")
    storage_mode: str = Field(..., description="Storage mode used")


class RetrieveResponse(BaseModel):
    """Response from retrieve operation."""

    status: str = Field("ok", description="Operation status")
    key: str = Field(..., description="Storage key")
    data: str = Field(..., description="Retrieved data (base64-encoded)")
    size: int = Field(..., description="Data size in bytes")
    integrity_verified: bool = Field(..., description="Whether integrity was verified")


class DeleteResponse(BaseModel):
    """Response from delete operation."""

    status: str = Field("ok", description="Operation status")
    key: str = Field(..., description="Storage key")
    deleted_count: int = Field(..., description="Number of shards deleted")
    failed_count: int = Field(..., description="Number of deletion failures")


class KeyListResponse(BaseModel):
    """Response listing all keys."""

    status: str = Field("ok", description="Operation status")
    keys: list[str] = Field(..., description="List of stored keys")
    count: int = Field(..., description="Number of keys")


class ShardInfo(BaseModel):
    """Information about a single shard."""

    index: int = Field(..., description="Shard index")
    backend_type: str = Field(..., description="Backend type (local/aws_s3)")
    location: str = Field(..., description="Storage location")
    exists: bool = Field(..., description="Whether shard exists")


class ShardStatusResponse(BaseModel):
    """Response with shard status."""

    status: str = Field("ok", description="Operation status")
    key: str = Field(..., description="Storage key")
    threshold: int = Field(..., description="Shards required for reconstruction")
    total_shards: int = Field(..., description="Total shards")
    storage_mode: str = Field(..., description="Storage mode")
    can_reconstruct: bool = Field(..., description="Whether data can be reconstructed")
    local_available: int = Field(..., description="Available local shards")
    cloud_account1_available: int = Field(..., description="Available AWS account 1 shards")
    cloud_account2_available: int = Field(..., description="Available AWS account 2 shards")
    shards: list[ShardInfo] = Field(..., description="Detailed shard information")


class CredentialListResponse(BaseModel):
    """Response listing stored credentials."""

    status: str = Field("ok", description="Operation status")
    accounts: list[str] = Field(..., description="List of account IDs")
    count: int = Field(..., description="Number of accounts")


class CredentialStoreResponse(BaseModel):
    """Response from credential store operation."""

    status: str = Field("ok", description="Operation status")
    account_id: str = Field(..., description="Account identifier")
    path: str = Field(..., description="Path to stored credentials")


class CredentialLoadResponse(BaseModel):
    """Response from credential load operation."""

    status: str = Field("ok", description="Operation status")
    account_id: str = Field(..., description="Account identifier")
    access_key_id_prefix: str = Field(..., description="First 8 chars of access key ID")
    region: str | None = Field(None, description="AWS region if set")


class ErrorResponse(BaseModel):
    """Error response."""

    status: str = Field("error", description="Error status")
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    details: dict[str, Any] | None = Field(None, description="Additional error details")


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = Field("ok", description="Service status")
    version: str = Field(..., description="API version")
    configured: bool = Field(..., description="Whether storage is configured")
    storage_mode: str | None = Field(None, description="Current storage mode")
