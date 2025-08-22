#!/usr/bin/env python3
"""
Mining Module - Handles Proof of Work consensus mechanism
======================================================

This module implements the Proof of Work consensus algorithm used to:
- Secure the blockchain against attacks
- Control the rate of new block creation
- Provide a fair way to select who creates the next block
- Incentivize network participation through mining rewards

Key Concepts:
- Proof of Work: Computational puzzle that's hard to solve, easy to verify
- Mining: Process of finding a valid proof of work for a block
- Difficulty: How hard the puzzle is (adjusts based on block times)
- Nonce: Random number that miners change to find valid proof
- Target: Threshold that hash must be below to be valid

Mining Process:
1. Take block data (transactions, previous hash, timestamp)
2. Add a nonce (number used once)
3. Hash all the data together
4. Check if hash is below difficulty target
5. If yes: valid proof found, if no: increment nonce and try again

Security Properties:
- Takes significant computational work to find valid proof
- Easy for others to verify the proof is valid
- Miners must commit resources, making attacks expensive
- Longest chain rule: most computational work wins
"""

import hashlib
import time
from typing import Tuple, TYPE_CHECKING
from .config import DIFFICULTY

if TYPE_CHECKING:
    from .block import Block

class ProofOfWork:
    """
    Proof of Work Implementation - Secures blocks through computational work
    
    Implements the consensus mechanism that makes blockchain secure by
    requiring miners to solve computational puzzles. This ensures:
    - Network agreement on valid blocks
    - Protection against spam and attacks
    - Controlled block creation rate
    - Decentralized block selection
    
    Algorithm:
    1. Combine block data with nonce
    2. Calculate SHA256 hash
    3. Check if hash meets difficulty requirement
    4. If not, increment nonce and repeat
    
    Difficulty target: Hash must be smaller than 2^(256-difficulty)
    Higher difficulty = more leading zeros required = more computation
    """
    
    def __init__(self, block: 'Block'):
        """
        Initialize Proof of Work for a block
        
        Args:
        - block: Block to create proof of work for
        
        Sets up the difficulty target based on current network difficulty.
        Target is calculated as: 2^(256 - difficulty)
        """
        self.block = block
        self.target = 1 << (256 - DIFFICULTY)

    def prepare_data(self, nonce: int) -> bytes:
        """
        Prepare block data for hashing
        
        Combines all block components into a single byte string
        that can be hashed. The data includes:
        - Previous block hash (links to parent)
        - Merkle root of transactions (commits to all transactions)
        - Block timestamp (when block was created)
        - Block difficulty (current network difficulty)
        - Block height (position in chain)
        - Nonce (variable that miners change)
        
        Args:
        - nonce: Current nonce value being tested
        
        Returns:
        - Concatenated byte string ready for hashing
        
        Note: Order matters! All nodes must use identical data preparation
        for consensus to work correctly.
        """
        # Convert previous hash to bytes if it's a string
        prev_hash = (self.block.prev_block_hash.encode()
                     if isinstance(self.block.prev_block_hash, str)
                     else self.block.prev_block_hash)

        # Get merkle root of transactions (already returns bytes)
        tx_root = self.block.hash_transactions()

        # Combine all block data for hashing
        return b"".join([
            prev_hash,
            tx_root,
            str(self.block.timestamp).encode(),
            str(self.block.difficulty).encode(),
            str(self.block.height).encode(),
            str(nonce).encode(),
        ])

    def run(self) -> Tuple[int, str]:
        """
        Run proof of work mining algorithm
        
        Searches for a nonce value that makes the block hash
        meet the difficulty requirement. This is the core mining process:
        
        Mining loop:
        1. Prepare block data with current nonce
        2. Calculate SHA256 hash
        3. Check if hash < target (meets difficulty)
        4. If yes: return nonce and hash (success!)
        5. If no: increment nonce and try again
        
        Returns:
        - Tuple of (nonce, hash) when valid proof is found
        
        Computational cost: Expected ~2^difficulty hash attempts
        Example: Difficulty 4 requires ~16 attempts on average
                Difficulty 20 requires ~1 million attempts on average
        
        Note: This is a brute-force search. In practice, miners use
        specialized hardware (ASICs) to perform millions of hashes per second.
        """
        max_nonce = 2**63  # Maximum nonce value to prevent infinite loops
        nonce = 0
        hash_val = ""

        print(f"Mining block with {len(self.block.transactions)} transactions...")

        # Brute force search for valid nonce
        while nonce < max_nonce:
            # Prepare data with current nonce
            data = self.prepare_data(nonce)
            
            # Calculate hash
            hash_val = hashlib.sha256(data).hexdigest()
            hash_int = int(hash_val, 16)

            # Check if hash meets difficulty target
            if hash_int < self.target:
                print(f"Block mined: {hash_val}")
                break  # Found valid proof!
            else:
                nonce += 1  # Try next nonce

        return nonce, hash_val

    def validate(self) -> bool:
        """
        Validate existing proof of work
        
        Verifies that a block's nonce creates a hash that meets
        the difficulty requirement. Used for:
        - Validating received blocks from other nodes
        - Checking blockchain integrity
        - Verifying imported blockchain data
        
        Process:
        1. Prepare block data with stored nonce
        2. Calculate hash using same algorithm as mining
        3. Check if hash meets difficulty target
        
        Returns:
        - True if proof of work is valid, False otherwise
        
        This is much faster than mining because we only need to
        calculate one hash instead of searching for a valid nonce.
        """
        data = self.prepare_data(self.block.nonce)
        hash_val = hashlib.sha256(data).hexdigest()
        hash_int = int(hash_val, 16)
        return hash_int < self.target