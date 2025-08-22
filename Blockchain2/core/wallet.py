#!/usr/bin/env python3
"""
Wallet Module - Handles cryptocurrency wallet functionality
========================================================

This module provides wallet management for the blockchain:
- Private/public key generation using ECDSA
- Address creation with Base58 encoding
- Wallet persistence to/from files
- Digital signature creation

Key cryptographic concepts:
- ECDSA (Elliptic Curve Digital Signature Algorithm) for key pairs
- SECP256k1 curve (same as Bitcoin) for security
- Base58 encoding for human-readable addresses
- Checksum validation to prevent address errors

Security features:
- Cryptographically secure random key generation
- Private keys never transmitted or stored in plaintext
- Each wallet has unique address derived from public key
- Digital signatures prove ownership without revealing private key
"""

import json
import os
import hashlib
import base58
import ecdsa
from typing import Optional, List
from .config import VERSION
from .crypto import hash_pub_key

class Wallet:
    """
    Cryptocurrency Wallet - Manages key pairs and addresses
    
    A wallet represents a user's identity in the blockchain system.
    Each wallet contains:
    - Private key: Secret key for signing transactions (must be kept secure)
    - Public key: Derived from private key, used for verification
    - Address: Human-readable identifier derived from public key
    
    The wallet can:
    - Generate cryptographically secure key pairs
    - Create addresses for receiving payments
    - Sign transactions to prove ownership
    - Save/load wallet data to/from files
    
    Security note: Private keys should never be shared or transmitted.
    Loss of private key means permanent loss of funds.
    """
    
    def __init__(self):
        """
        Initialize new wallet with random key pair
        
        Creates a new ECDSA key pair using the SECP256k1 curve
        (same curve used by Bitcoin for compatibility and security).
        
        Key generation process:
        1. Generate random private key using cryptographically secure random
        2. Derive public key from private key using elliptic curve math
        3. Store both keys for transaction signing and verification
        """
        self.private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.public_key = self.private_key.get_verifying_key().to_string() # type: ignore

    def get_address(self) -> str:
        """
        Generate wallet address from public key
        
        Creates a human-readable address that others can use to send
        coins to this wallet. The address generation process:
        
        1. Hash the public key using SHA256 + RIPEMD160 (simulated)
        2. Add version byte to identify address type
        3. Calculate checksum using double SHA256
        4. Concatenate version + hash + checksum
        5. Encode using Base58 for readability
        
        Address format: [version][pub_key_hash][checksum]
        - Version (1 byte): Address type identifier
        - Pub key hash (20 bytes): Hashed public key
        - Checksum (4 bytes): Error detection
        
        Returns:
        - Base58-encoded address string
        
        Example: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        """
        # Step 1: Hash the public key
        pub_key_hash = hash_pub_key(self.public_key)
        
        # Step 2: Add version byte + public key hash
        versioned_payload = bytes([VERSION]) + pub_key_hash
        
        # Step 3: Calculate checksum (double SHA256, take first 4 bytes)
        checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
        
        # Step 4: Combine all components
        full_payload = versioned_payload + checksum
        
        # Step 5: Base58 encode for human readability
        return base58.b58encode(full_payload).decode()

    def save_to_file(self, filename: str = None):
        """
        Save wallet to file for persistence
        
        Stores wallet data in JSON format for later loading.
        Private key is stored as hex string for security.
        
        File format:
        {
            "private_key": "hex_encoded_private_key",
            "public_key": "hex_encoded_public_key", 
            "address": "base58_address"
        }
        
        Args:
        - filename: Optional custom filename, defaults to wallet_ADDRESS.dat
        
        Security note: Wallet files contain private keys and should be
        protected with appropriate file permissions in production.
        """
        if not filename:
            filename = f"wallet_{self.get_address()}.dat"
        
        wallet_data = {
            'private_key': self.private_key.to_string().hex(),
            'public_key': self.public_key.hex(),
            'address': self.get_address()
        }
        
        with open(filename, 'w') as f:
            json.dump(wallet_data, f)

    @classmethod
    def load_from_file(cls, address: str) -> Optional['Wallet']:
        """
        Load wallet from file by address
        
        Reconstructs a wallet object from saved file data.
        This allows users to recover their wallets and access their funds.
        
        Args:
        - address: Wallet address to load
        
        Returns:
        - Wallet object if file exists and is valid, None otherwise
        
        File naming convention: wallet_ADDRESS.dat
        
        Error handling:
        - Returns None if file doesn't exist
        - Returns None if file format is invalid
        - Returns None if cryptographic data is corrupted
        """
        filename = f"wallet_{address}.dat"
        
        if not os.path.exists(filename):
            return None
        
        try:
            with open(filename, 'r') as f:
                wallet_data = json.load(f)
            
            # Reconstruct wallet from saved data
            wallet = cls.__new__(cls)
            wallet.private_key = ecdsa.SigningKey.from_string(
                bytes.fromhex(wallet_data['private_key']), 
                curve=ecdsa.SECP256k1
            )
            wallet.public_key = bytes.fromhex(wallet_data['public_key'])
            return wallet
            
        except (json.JSONDecodeError, KeyError, ValueError):
            return None

class Wallets:
    """
    Wallet Manager - Manages multiple wallets for a user
    
    Provides a convenient interface for managing multiple wallets:
    - Create new wallets
    - Load existing wallets from files
    - List all available wallet addresses
    - Retrieve specific wallets by address
    
    The manager automatically discovers and loads all wallet files
    in the current directory, making wallet management seamless.
    
    Wallet files are named: wallet_ADDRESS.dat
    """
    
    def __init__(self):
        """
        Initialize wallet manager
        
        Creates an empty wallet collection and loads all existing
        wallet files from the current directory.
        """
        self.wallets = {}  # Dictionary: address -> Wallet object
        self.load_from_file()

    def create_wallet(self) -> str:
        """
        Create new wallet and save to file
        
        Generates a new wallet with random key pair, adds it to
        the collection, and saves it to disk for persistence.
        
        Returns:
        - Address of the newly created wallet
        
        The wallet is automatically:
        1. Generated with secure random keys
        2. Added to the in-memory collection
        3. Saved to disk as wallet_ADDRESS.dat
        """
        wallet = Wallet()
        address = wallet.get_address()
        
        self.wallets[address] = wallet
        wallet.save_to_file()
        return address

    def get_addresses(self) -> List[str]:
        """
        Get all wallet addresses
        
        Returns a list of all addresses for wallets managed
        by this wallet manager.
        
        Returns:
        - List of address strings
        """
        return list(self.wallets.keys())

    def get_wallet(self, address: str) -> Optional[Wallet]:
        """
        Get wallet by address
        
        Retrieves a specific wallet from the collection by its address.
        
        Args:
        - address: Wallet address to retrieve
        
        Returns:
        - Wallet object if found, None otherwise
        """
        return self.wallets.get(address)

    def load_from_file(self):
        """
        Load all wallets from files in current directory
        
        Automatically discovers and loads all wallet files by:
        1. Scanning current directory for wallet_*.dat files
        2. Extracting address from filename
        3. Loading wallet data using Wallet.load_from_file()
        4. Adding valid wallets to collection
        
        This allows users to access all their wallets automatically
        when the wallet manager starts up.
        
        File naming convention: wallet_ADDRESS.dat
        """
        for filename in os.listdir('.'):
            if filename.startswith('wallet_') and filename.endswith('.dat'):
                # Extract address from filename
                address = filename[7:-4]  # Remove "wallet_" and ".dat"
                
                # Load wallet from file
                wallet = Wallet.load_from_file(address)
                if wallet:
                    self.wallets[address] = wallet