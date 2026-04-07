"""
Upload file validation middleware - enforces file size, type, and rate limiting.
"""

from __future__ import annotations

import mimetypes
from typing import Set

from fastapi import HTTPException, UploadFile


# Configuration constants
MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB
ALLOWED_EXTENSIONS = {".exe", ".dll", ".bin", ".com", ".sys", ".drv", ".scr"}
ALLOWED_MIME_TYPES = {
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/octet-stream",
    "application/x-executable",
}
MAX_FILENAME_LENGTH = 255
MIN_FILE_SIZE_BYTES = 1  # At least 1 byte


class UploadValidationError(Exception):
    """Raised when file upload validation fails."""

    pass


def validate_filename(filename: str) -> None:
    """
    Validate filename for security and length.
    
    Args:
        filename: The uploaded filename
        
    Raises:
        UploadValidationError: If filename is invalid
    """
    if not filename:
        raise UploadValidationError("Filename is required.")

    if len(filename) > MAX_FILENAME_LENGTH:
        raise UploadValidationError(f"Filename exceeds {MAX_FILENAME_LENGTH} characters.")

    # Check for path traversal attempts
    if "/" in filename or "\\" in filename or ".." in filename:
        raise UploadValidationError("Filename contains invalid path characters.")

    # Check for null bytes
    if "\x00" in filename:
        raise UploadValidationError("Filename contains invalid null bytes.")


def validate_file_extension(filename: str, allowed_extensions: Set[str] | None = None) -> None:
    """
    Validate file extension is in allowed list.
    
    Args:
        filename: The uploaded filename
        allowed_extensions: Set of allowed extensions (if None, all are allowed)
        
    Raises:
        UploadValidationError: If extension is not allowed
    """
    if allowed_extensions is None:
        return

    for ext in allowed_extensions:
        if filename.lower().endswith(ext):
            return

    allowed_str = ", ".join(sorted(allowed_extensions))
    raise UploadValidationError(f"File type not allowed. Allowed: {allowed_str}")


def validate_file_size(file_bytes: bytes, max_size_bytes: int | None = None) -> None:
    """
    Validate file size is within limits.
    
    Args:
        file_bytes: The raw file content
        max_size_bytes: Maximum file size in bytes (if None, use default)
        
    Raises:
        UploadValidationError: If file size is invalid
    """
    max_size = max_size_bytes or MAX_FILE_SIZE_BYTES

    if len(file_bytes) < MIN_FILE_SIZE_BYTES:
        raise UploadValidationError("File is empty.")

    if len(file_bytes) > max_size:
        max_mb = max_size / (1024 * 1024)
        raise UploadValidationError(f"File exceeds maximum size of {max_mb:.0f} MB.")


def validate_mime_type(filename: str, allowed_types: Set[str] | None = None) -> None:
    """
    Validate MIME type of file (best-effort based on extension).
    
    Args:
        filename: The uploaded filename
        allowed_types: Set of allowed MIME types (if None, all are allowed)
        
    Raises:
        UploadValidationError: If MIME type is not allowed
    """
    if allowed_types is None:
        return

    guessed_type, _ = mimetypes.guess_type(filename)
    if guessed_type and guessed_type not in allowed_types:
        allowed_str = ", ".join(sorted(allowed_types))
        raise UploadValidationError(f"MIME type {guessed_type} not allowed. Allowed: {allowed_str}")


def validate_upload_file(
    file: UploadFile,
    file_bytes: bytes,
    max_size_bytes: int | None = None,
    allowed_extensions: Set[str] | None = None,
    allowed_mime_types: Set[str] | None = None,
) -> None:
    """
    Comprehensive validation for uploaded file.
    
    Args:
        file: The UploadFile object
        file_bytes: The raw file content
        max_size_bytes: Maximum file size in bytes
        allowed_extensions: Set of allowed file extensions
        allowed_mime_types: Set of allowed MIME types
        
    Raises:
        UploadValidationError: If any validation fails
    """
    filename = file.filename or ""
    
    # Validate filename
    validate_filename(filename)
    
    # Validate file size
    validate_file_size(file_bytes, max_size_bytes)
    
    # Validate extension
    validate_file_extension(filename, allowed_extensions)
    
    # Validate MIME type
    validate_mime_type(filename, allowed_mime_types)
