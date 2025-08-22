#!/usr/bin/env python3
"""
Block Module - Handles blockchain block structure and operations
=============================================================

This module contains the Block class which represents individual blocks
in the blockchain. Each block contains:
- Timestamp: When the block was created
- Transactions: List of transactions included in the block
- Previous block hash: Links to the parent block in the chain
- Height: Position of block in the blockchain (0 = genesis block)
- Difficulty: Mining difficulty used for this block
- Nonce: Proof of Work solution found by miners
- Hash: Unique identifier calculated after mining

Key Features:
- Merkle tree hashing for transaction integrity
- Proof of Work mining integration
- Block serialization for network transmission and storage
- JSON conversion for API responses
- Chain linking through previous block hashes

Block Structure:
┌──────────────────┐
│   Block Header   │ ← Contains metadata and proof of work
├──────────────────┤
│   Transactions   │ ← List of transactions in this block
│   [TX1, TX2...]  │
└──────────────────┘

Security Properties:
- Each block is cryptographically linked to its parent
- Merkle tree ensures transaction integrity
- Proof of Work prevents block tampering
- Hash provides unique block identification
"""

import hashlib
import pickle
import time
from typing import List, Dict
from .transaction import Transaction
from .mining import ProofOfWork
from .merkle import merkle_root


class Block:
    """
    Blockchain Block - Container for transactions with cryptographic security
    
    Represents a single block in the blockchain containing a batch of
    transactions that have been validated and permanently recorded.
    Each block is linked to its predecessor, forming an immutable chain.
    
    Block lifecycle:
    1. Creation: Initialize with transactions and metadata
    2. Mining: Find proof of work solution (nonce)
    3. Validation: Verify proof of work and transaction integrity
    4. Storage: Serialize and save to database
    5. Propagation: Broadcast to network peers
    
    Components:
    - Header: Metadata (timestamp, prev hash, difficulty, nonce, height)
    - Body: Transaction list with Merkle tree root
    - Proof: Cryptographic proof that work was performed
    
    Example:
    Block #123: 
    - Contains 15 transactions
    - Links to block #122
    - Mined with difficulty 20
    - Hash: 00001a2b3c4d5e6f...
    """
    
    def __init__(self, transactions: List[Transaction], prev_block_hash: str = "", 
                 timestamp: int = None, nonce: int = 0, height: int = 0, difficulty: int = 4):
        
        self.timestamp = timestamp or int(time.time())
        self.transactions = transactions
        self.merkle_root = self.hash_transactions()
        self.prev_block_hash = prev_block_hash  # Hex string linking to parent
        self.height = height
        self.difficulty = difficulty
        self.nonce = nonce
        self.hash = ""  # Set after mining completes

    def hash_transactions(self) -> bytes:
        tx_hashes = []
        for tx in self.transactions:
            # Convert transaction ID (hex string) to bytes for Merkle tree
            tx_hashes.append(tx.id.encode())

        # Handle empty block case
        if not tx_hashes:
            return hashlib.sha256(b"").digest()
        
        # Build Merkle tree and return root
        return merkle_root(tx_hashes)

    def mine_block(self):
        """
        Mine the block using Proof of Work
        
        Finds a nonce value that makes the block hash meet the
        difficulty requirement. This is the computationally expensive
        process that secures the blockchain.
        
        Mining process:
        1. Create ProofOfWork instance for this block
        2. Search for valid nonce (brute force)
        3. Update block with found nonce and hash
        4. Block becomes valid and ready for blockchain
        
        Computational cost: ~2^difficulty hash operations
        Example: Difficulty 20 requires ~1 million attempts on average
        
        After mining:
        - Block has valid proof of work
        - Hash starts with required number of zeros
        - Block can be added to blockchain
        - Other nodes can quickly verify validity
        """
        pow_instance = ProofOfWork(self)
        nonce, hash_val = pow_instance.run()
        self.nonce = nonce
        self.hash = hash_val

    def serialize(self) -> bytes:
        """
        Serialize block to bytes for storage/transmission
        
        Converts the block object to a byte string that can be:
        - Stored in database
        - Transmitted over network
        - Cached in memory
        - Written to files
        
        Uses Python's pickle serialization for simplicity.
        In production, consider more efficient formats like Protocol Buffers.
        
        Returns:
        - Serialized block data as bytes
        """
        return pickle.dumps(self)

    @classmethod
    def deserialize(cls, data: bytes) -> 'Block':
        """
        Deserialize block from bytes
        
        Reconstructs a Block object from serialized byte data.
        Used when loading blocks from database or receiving from network.
        
        Args:
        - data: Serialized block bytes (from serialize() method)
        
        Returns:
        - Reconstructed Block object
        
        Error handling:
        - Raises PickleError if data is corrupted
        - Raises ValueError if data format is invalid
        """
        return pickle.loads(data)

    def to_dict(self) -> Dict:
        """
        Convert block to dictionary for JSON API responses
        
        Creates a JSON-safe representation of the block by converting
        all fields to basic Python types. Used for:
        - REST API responses
        - Web UI display
        - Database storage (as JSON)
        - Network communication
        - Debug/logging output
        
        Returns:
        - Dictionary with all block data in JSON-compatible format
        
        Structure:
        {
            "timestamp": 1640995200,
            "prev_block_hash": "00001a2b...",
            "hash": "00002c3d...",
            "nonce": 1234567,
            "height": 42,
            "difficulty": 20,
            "transactions": [
                { "id": "tx1...", "vin": [...], "vout": [...] },
                { "id": "tx2...", "vin": [...], "vout": [...] }
            ]
        }
        """
        return {
            'timestamp': self.timestamp,
            'prev_block_hash': self.prev_block_hash,
            'hash': self.hash,
            'nonce': self.nonce,
            'height': self.height,
            'difficulty': self.difficulty,
            'transactions': [tx.to_dict() for tx in self.transactions]
        }