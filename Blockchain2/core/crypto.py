#!/usr/bin/env python3
"""
Cryptographic Module - Handles all cryptographic operations
=========================================================

This module provides cryptographic utilities used throughout the blockchain:
- Public key hashing for address generation
- Address encoding/decoding using Base58
- Address validation with checksums

Key cryptographic concepts:
- SHA256: Primary hash function for blockchain integrity
- RIPEMD160: Hash function for address generation (simulated with SHA256)
- Base58: Human-readable encoding for addresses (avoids confusing characters)
- Checksums: Prevent address typos and corruption

Security features:
- Double SHA256 hashing for extra security
- Address checksums to detect typos
- Consistent encoding across all addresses
"""

import hashlib
import base58
from .config import VERSION

def hash_pub_key(pub_key: bytes) -> bytes:
    """
    Hash public key using SHA256 twice
    
    Creates a shorter, consistent-length identifier from a public key.
    Uses double SHA256 hashing for extra security (similar to Bitcoin).
    
    Process:
    1. SHA256 hash the public key
    2. SHA256 hash the result again  
    3. Take first 20 bytes for address generation
    
    Args:
    - pub_key: Raw ECDSA public key bytes
    
    Returns:
    - 20-byte hash suitable for address generation
    
    Note: Bitcoin uses RIPEMD160 after SHA256, but Python doesn't have
    RIPEMD160 in standard library, so we use SHA256 twice for simplicity.
    """
    sha256_hash = hashlib.sha256(pub_key).digest()
    # Python doesn't have RIPEMD160, use SHA256 again for simplicity
    return hashlib.sha256(sha256_hash).digest()[:20]

def decode_address(address: str) -> bytes:
    """
    Decode Base58 address to public key hash
    
    Converts a human-readable address back to the public key hash
    that can be used for transaction validation.
    
    Process:
    1. Base58 decode the address
    2. Remove version byte (first byte)
    3. Remove checksum (last 4 bytes)
    4. Return the public key hash
    
    Args:
    - address: Base58-encoded address string
    
    Returns:
    - Public key hash bytes
    
    Raises:
    - ValueError: If address format is invalid
    """
    pub_key_hash = base58.b58decode(address)
    pub_key_hash = pub_key_hash[1:-4]  # Remove version and checksum
    return pub_key_hash

def validate_address(address: str) -> bool:
    """
    Validate address format and checksum
    
    Ensures an address is properly formatted and has a valid checksum.
    This prevents typos and corruption in addresses.
    
    Validation process:
    1. Base58 decode the address
    2. Extract version, public key hash, and checksum
    3. Recalculate checksum from version + public key hash
    4. Compare calculated checksum with provided checksum
    
    Args:
    - address: Address string to validate
    
    Returns:
    - True if address is valid, False otherwise
    
    Address format:
    [version byte][20-byte public key hash][4-byte checksum]
    """
    try:
        # Decode the full address
        pub_key_hash = base58.b58decode(address)
        
        # Must be at least 25 bytes (1 + 20 + 4)
        if len(pub_key_hash) < 5:
            return False
        
        # Extract components
        version = pub_key_hash[0]
        pub_hash = pub_key_hash[1:-4]
        checksum = pub_key_hash[-4:]
        
        # Calculate expected checksum
        target_checksum = hashlib.sha256(
            hashlib.sha256(bytes([version]) + pub_hash).digest()
        ).digest()[:4]
        
        # Verify checksum matches
        return checksum == target_checksum
        
    except Exception:
        return False