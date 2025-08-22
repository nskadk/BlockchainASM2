#!/usr/bin/env python3
"""
Blockchain Module - Core blockchain implementation and management
===============================================================

This module contains the main Blockchain class that manages the entire
blockchain system. It handles:
- Block creation, mining, and validation
- Chain integrity and consensus
- Transaction mempool management
- Database persistence with SQLite
- Difficulty adjustment algorithm
- Security validation and tampering simulation

Key Features:
- Proof of Work consensus mechanism
- Dynamic difficulty adjustment based on block timing
- Mempool for pending transactions awaiting mining
- Chain validation with comprehensive error reporting
- Tamper detection and security demonstration
- SQLite database for persistent storage
- Genesis block creation for new chains

Architecture:
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│   Mempool   │───▶│  Blockchain  │───▶│  Database   │
│ (Pending TX)│    │   (Chain)    │    │  (SQLite)   │
└─────────────┘    └──────────────┘    └─────────────┘
       │                  │                    │
       ▼                  ▼                    ▼
  Transaction         Block Mining        Persistent
   Validation         & Validation          Storage

The Blockchain class serves as the central coordinator for all
blockchain operations, ensuring data integrity and consistency.
"""

import hashlib
import sqlite3
import time
from typing import List, Dict, Optional, Tuple, Any

from .utxo import UTXOSet
from .config import *
from .exceptions import *
from .block import Block
from .transaction import Transaction
from .mining import ProofOfWork


class Blockchain:
    """
    Core Blockchain Implementation - Manages the distributed ledger
    
    The Blockchain class is the heart of the cryptocurrency system,
    responsible for maintaining an immutable chain of blocks containing
    validated transactions. It provides:
    
    Chain Management:
    - Genesis block creation for new chains
    - Block mining with Proof of Work
    - Chain validation and integrity checking
    - Difficulty adjustment for consistent block times
    
    Transaction Processing:
    - Mempool management for pending transactions
    - Transaction validation and verification
    - Digital signature verification
    - UTXO (Unspent Transaction Output) tracking
    
    Persistence:
    - SQLite database for reliable storage
    - Block serialization and deserialization
    - Metadata management (chain tip, configuration)
    - Atomic database operations
    
    Security Features:
    - Cryptographic chain linking
    - Proof of Work validation
    - Transaction signature verification
    - Tamper detection and demonstration
    
    Example Usage:
    blockchain = Blockchain("my_chain.db", genesis_address)
    tx = Transaction.new_utxo_transaction(alice, bob, 10, utxo_set)
    blockchain.add_to_mempool(tx)
    block = blockchain.mine_pending_transactions(miner_address)
    """
    
    def __init__(self, db_file: str = "blockchain.db", genesis_address: str = ""):
        self.db_file = db_file
        self.tip: str = ""
        self.mempool: Dict[str, Transaction] = {}
        self._init_db()

        # Create genesis block if blockchain is empty
        if not self._exists():
            self._create_genesis_block(genesis_address)

    # -------------------- Database --------------------
    def _init_db(self):
        """Initialize SQLite database and load tip."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        # Blocks table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocks (
                hash TEXT PRIMARY KEY,
                data BLOB NOT NULL
            )
        """)
        # Metadata table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        conn.commit()
        # Load tip
        cursor.execute("SELECT value FROM metadata WHERE key = 'tip'")
        row = cursor.fetchone()
        if row:
            self.tip = row[0]
        conn.close()

    def _exists(self) -> bool:
        """Check if blockchain exists by checking tip."""
        return bool(self.tip)

    def _create_genesis_block(self, address: str):
        """Create the first block in the blockchain."""
        coinbase_tx = Transaction.new_coinbase_tx(address, GENESIS_COINBASE_DATA)
        genesis = Block(
            transactions=[coinbase_tx],
            prev_block_hash="",
            timestamp=int(time.time()),
            height=0,
            difficulty=DIFFICULTY
        )
        genesis.mine_block()
        genesis.merkle_root = genesis.hash_transactions()
        self._add_block(genesis)

    def next_difficulty(self) -> int:
        """Calculate next mining difficulty based on adjustment rules."""
        height = self.get_best_height()
        
        # Genesis block keeps default difficulty
        if height == 0:
            return DIFFICULTY
        
        # Only adjust at specific intervals
        if height % ADJUST_INTERVAL != 0:
            tip_block = self.get_block(self.tip)
            return tip_block.difficulty if tip_block else DIFFICULTY

        # Get blocks for time comparison
        hashes = self.get_block_hashes()
        if len(hashes) < ADJUST_INTERVAL + 1:
            return DIFFICULTY
        
        # Calculate actual time vs expected time
        tip = self.get_block(hashes[-1])
        anchor = self.get_block(hashes[-1 - ADJUST_INTERVAL])
        
        if not tip or not anchor:
            return DIFFICULTY
            
        elapsed = tip.timestamp - anchor.timestamp
        expected = ADJUST_INTERVAL * TARGET_BLOCK_TIME

        # Adjust difficulty based on timing
        new_diff = tip.difficulty
        if elapsed < expected * 0.8:  # Too fast
            new_diff += 1
        elif elapsed > expected * 1.2:  # Too slow
            new_diff -= 1
        
        return max(MIN_DIFFICULTY, min(MAX_DIFFICULTY, new_diff))

    def _add_block(self, block: Block):
        """Store block in DB and update chain tip."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR REPLACE INTO blocks (hash, data) VALUES (?, ?)",
            (block.hash, block.serialize())
        )
        cursor.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            ("tip", block.hash)
        )
        conn.commit()
        conn.close()
        self.tip = block.hash

    def mine_block(self, transactions: List[Transaction], utxo_set: 'UTXOSet') -> Block:
        """
        Mine new block with provided transactions.
        """

        # Verify all transactions against UTXO set + mempool
        mempool = transactions[:]  # pending txs for this block
        for tx in transactions:
            if not self.verify_transaction(tx, utxo_set, mempool):
                raise InvalidTransactionError(f"Invalid transaction: {tx.id}")

        # Create block with proper metadata
        current_height = self.get_best_height()
        next_difficulty = self.next_difficulty()
        
        block = Block(
            transactions=transactions, 
            prev_block_hash=self.tip,
            height=current_height + 1,
            difficulty=next_difficulty
        )
        
        block.mine_block()
        
        # Add block to chain
        self._add_block(block)

        # Update UTXO set with the new block's transactions
        utxo_set.update(block.transactions)

        return block

    def get_block(self, block_hash: str) -> Optional[Block]:
        """Retrieve a block by its hash."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT data FROM blocks WHERE hash = ?", (block_hash,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return Block.deserialize(row[0])
        return None

    def get_best_height(self) -> int:
        """Return height of the current chain tip."""
        if not self.tip:
            return -1
        
        tip_block = self.get_block(self.tip)
        if tip_block and hasattr(tip_block, 'height'):
            return tip_block.height
        
        # Fallback: count blocks manually
        height = -1
        current_hash = self.tip
        
        while current_hash:
            block = self.get_block(current_hash)
            if not block:
                break
            height += 1
            current_hash = block.prev_block_hash
            
        return height

    def get_block_hashes(self) -> List[str]:
        """Return all block hashes from newest to oldest."""
        hashes = []
        current_hash = self.tip
        while current_hash:
            hashes.append(current_hash)
            block = self.get_block(current_hash)
            if not block:
                break
            current_hash = block.prev_block_hash
        return hashes
    
    def add_to_mempool(self, tx: Transaction, utxo_set: UTXOSet) -> bool:
        """
        Add transaction to mempool if valid
        
        Validates a transaction and adds it to the mempool
        (pending transaction pool) for future mining.
        
        Args:
        - transaction: Transaction to add to mempool
        
        Returns:
        - True if added successfully, False if invalid or duplicate
        """
        if tx.id in self.mempool:
            return False
        
        if self.verify_transaction(tx, utxo_set, list(self.mempool.values())):
            self.mempool[tx.id] = tx
            return True
        return False
    
    def remove_from_mempool(self, tx_id: str):
        """Remove a transaction from mempool by ID."""
        self.mempool.pop(tx_id, None)
    
    def get_mempool_transactions(self) -> List[Transaction]:
        """Return all pending transactions in mempool."""
        return list(self.mempool.values())
    
    def mine_pending_transactions(self, mining_reward_address: str) -> Optional[Block]:
        """
        Mine new block with all pending mempool transactions
        
        Takes all transactions from mempool, adds mining reward,
        and mines a new block. Successful mining clears the
        mempool of included transactions.
        
        Args:
        - mining_reward_address: Address to receive mining reward
        
        Returns:
        - Newly mined block, or None if no transactions to mine
        
        Mining process:
        1. Collect all mempool transactions
        2. Add coinbase transaction with mining reward
        3. Mine block with proper difficulty and height
        4. Add block to blockchain
        5. Remove mined transactions from mempool
        """
        transactions = self.get_mempool_transactions()
        
        if not transactions:
            print("No transactions in mempool to mine.")
            return None
        
        # Add mining reward coinbase transaction
        reward_tx = Transaction.new_coinbase_tx(mining_reward_address, "Mining reward")
        transactions.append(reward_tx)
        
        utxo_set = self.find_utxo_set()
        # Verify all transactions before mining
        for tx in transactions:
            if not self.verify_transaction(tx, utxo_set, transactions[:-1]):
                print(f"Transaction {tx.id[:16]}... invalid, skipping block")
                return None
        
        block = Block(
            transactions=transactions,
            prev_block_hash=self.tip,
            height=self.get_best_height() + 1,
            difficulty=self.next_difficulty()
        )
        block.mine_block()
        block.merkle_root = block.hash_transactions()
        
        # Add to blockchain
        self._add_block(block)
        
        # Clear mined transactions from mempool (exclude reward tx)
        for tx in transactions[:-1]:
            self.remove_from_mempool(tx.id)
        
        print(f"Block #{block.height} mined with {len(block.transactions)} transactions")
        return block

    def validate_chain(self) -> Tuple[bool, List[str]]:
        """
        Validate entire blockchain integrity
        
        Performs comprehensive validation of the entire blockchain
        to detect any corruption, tampering, or inconsistencies.
        
        Validation checks:
        - Block hash integrity
        - Chain linking (previous block hashes)
        - Proof of Work validation
        - Block height consistency
        - Transaction validation
        - Merkle root integrity
        
        Returns:
        - Tuple of (is_valid, list_of_errors)
        
        Used for:
        - Security auditing
        - Corruption detection
        - Tamper evidence
        - Chain synchronization validation
        """
        errors = []
        prev_block = None
        utxo_set = UTXOSet({}) # type: ignore

        for block_hash in reversed(self.get_block_hashes()):
            block = self.get_block(block_hash)
            if not block:
                errors.append(f"Block {block_hash} not found")
                continue
            
            # Validate block hash
            expected_hash = self.calculate_hash_for_block(block)
            if block.hash != expected_hash:
                errors.append(f"Block {block.hash[:16]}... has invalid hash")
            
            # Validate chain linking
            if prev_block and block.prev_block_hash != prev_block.hash:
                errors.append(f"Block {block.hash[:16]}... has invalid previous block hash")
            
            # Validate Proof of Work
            pow_validator = ProofOfWork(block)
            if not pow_validator.validate():
                errors.append(f"Block {block.hash[:16]}... has invalid proof of work")
            
            # Validate block height
            expected_height = 0 if not prev_block else prev_block.height + 1
            if hasattr(block, 'height') and block.height != expected_height:
                errors.append(f"Block {block.hash[:16]}... has invalid height: {block.height}, expected {expected_height}")
            
            # Validate all transactions in block
            for tx in block.transactions:
                if not self.verify_transaction(tx, utxo_set):
                    errors.append(f"Block {block.hash[:16]}... contains invalid transaction {tx.id[:16]}...")
            
            # Validate Merkle root (if block has merkle_root field)
            expected_merkle = block.hash_transactions()
            if hasattr(block, 'merkle_root') and block.merkle_root != expected_merkle:
                errors.append(f"Block {block.hash[:16]}... has invalid Merkle root")
            
            utxo_set.update(block.transactions)
            prev_block = block
        return len(errors) == 0, errors
    
    def calculate_hash_for_block(self, block: Block) -> str:
        """
        Calculate hash for block validation
        
        Recalculates a block's hash using the same process as
        mining to verify the block hasn't been tampered with.
        
        Args:
        - block: Block to calculate hash for
        
        Returns:
        - Calculated hash string
        """
        pow_validator = ProofOfWork(block)
        data = pow_validator.prepare_data(block.nonce)
        return hashlib.sha256(data).hexdigest()
    
    def simulate_tampering(self, block_hash: str, tamper_type: str = "transaction") -> Dict:
        """
        Simulate blockchain tampering for security demonstration
        
        Demonstrates blockchain security by showing how tampering
        with any block invalidates the chain. Used for educational
        purposes and security testing.
        
        Tamper types:
        - "transaction": Modify transaction data
        - "nonce": Change proof of work nonce
        - "timestamp": Alter block timestamp
        
        Args:
        - block_hash: Hash of block to tamper with
        - tamper_type: Type of tampering to simulate
        
        Returns:
        - Dictionary with tampering results and affected blocks
        
        Process:
        1. Validate original chain
        2. Perform specified tampering
        3. Validate tampered chain
        4. Identify all affected blocks
        5. Restore original data
        
        Security insight: Any tampering invalidates the entire
        chain from the tampered block onward, demonstrating
        blockchain's tamper-evident properties.
        """
        result = {
            "original_valid": False,
            "tampered_valid": False,
            "tamper_details": "",
            "affected_blocks": []
        }
        
        # Check original chain validity
        original_valid, _ = self.validate_chain()
        result["original_valid"] = original_valid
        
        # Get target block
        target_block = self.get_block(block_hash)
        if not target_block:
            result["tamper_details"] = "Block not found"
            return result
        
        # Perform tampering with backup
        original_data = None
        
        try:
            if tamper_type == "transaction":
                if target_block.transactions:
                    tx = target_block.transactions[0]
                    original_data = tx.id
                    tx.id = "tampered_" + tx.id[:40]  # Modify transaction ID
                    result["tamper_details"] = f"Modified transaction ID in block {block_hash[:16]}..."
                else:
                    result["tamper_details"] = "No transactions to tamper with"
                    return result
            
            elif tamper_type == "nonce":
                original_data = target_block.nonce
                target_block.nonce = 999999  # Invalid nonce
                result["tamper_details"] = f"Modified nonce from {original_data} to {target_block.nonce}"
            
            elif tamper_type == "timestamp":
                original_data = target_block.timestamp
                target_block.timestamp = 1234567890  # Arbitrary timestamp
                result["tamper_details"] = f"Modified timestamp from {original_data} to {target_block.timestamp}"
            
            # Update tampered block in database
            self.update_block(target_block)
            
            # Validate tampered chain
            tampered_valid, errors = self.validate_chain()
            result["tampered_valid"] = tampered_valid
            
            # Identify affected blocks (tampering cascades through chain)
            block_hashes = self.get_block_hashes()
            tampered_block_found = False
            
            for block_hash_iter in block_hashes:
                block = self.get_block(block_hash_iter)
                if not block:
                    continue
                
                is_tampered_block = block.hash == block_hash
                if is_tampered_block:
                    tampered_block_found = True
                
                # All blocks after tampered block are affected
                if tampered_block_found:
                    result["affected_blocks"].append({
                        "hash": block.hash,
                        "height": getattr(block, 'height', 0),
                        "is_tampered_block": is_tampered_block
                    })
            
        finally:
            # Always restore original data
            if original_data is not None:
                if tamper_type == "transaction" and target_block.transactions:
                    target_block.transactions[0].id = original_data # type: ignore
                elif tamper_type == "nonce":
                    target_block.nonce = original_data # type: ignore
                elif tamper_type == "timestamp":
                    target_block.timestamp = original_data # type: ignore
                
                # Restore block in database
                self.update_block(target_block)
        
        return result
    
    def update_block(self, block: Block):
        """
        Update block in database (for tampering simulation)
        
        Args:
        - block: Modified block to update
        """
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute("UPDATE blocks SET data = ? WHERE hash = ?", 
                      (block.serialize(), block.hash))
        conn.commit()
        conn.close()
    
    def get_current_difficulty(self) -> int:
        """
        Get current mining difficulty
        
        Returns:
        - Current difficulty level for mining
        """
        return self.next_difficulty()

    def find_transaction(self, tx_id: str) -> Optional[Transaction]:
        """
        Find transaction by ID across all blocks
        
        Searches the entire blockchain for a transaction with
        the specified ID.
        
        Args:
        - tx_id: Transaction ID to search for
        
        Returns:
        - Transaction object if found, None otherwise
        """
        for block_hash in self.get_block_hashes():
            block = self.get_block(block_hash)
            if block:
                for tx in block.transactions:
                    if tx.id == tx_id:
                        return tx
        return None

    def sign_transaction(self, tx: Transaction, private_key):
        """
        Sign transaction with private key
        
        Finds all referenced transactions and signs the new
        transaction to prove ownership of inputs.
        
        Args:
        - tx: Transaction to sign
        - private_key: ECDSA private key for signing
        """
        prev_txs = {}
        for vin in tx.vin:
            prev_tx = self.find_transaction(vin.txid)
            if prev_tx:
                prev_txs[prev_tx.id] = prev_tx
        tx.sign(private_key, prev_txs)

    def verify_transaction(self, tx: Transaction, utxo_set: 'UTXOSet', mempool: List[Transaction] = None) -> bool:
        """
        Verify transaction signatures and validity
        
        Validates a transaction by checking:
        - Digital signatures on all inputs
        - Referenced transactions exist
        - Input/output amounts balance
        
        Args:
        - tx: Transaction to verify
        
        Returns:
        - True if transaction is valid, False otherwise
        """
        if tx.is_coinbase():
            return True  # Coinbase transactions are always valid

        # Find all referenced transactions
        prev_txs = {}
        input_sum = 0
        output_sum = sum(vout.value for vout in tx.vout)

        for vin in tx.vin:
            # Check if referenced UTXO exists in UTXO set
            if not utxo_set.contains(vin.txid, vin.vout):
                print("Invalid tx: UTXO not found or already spent")
                return False
            
            prev_tx = self.find_transaction(vin.txid)
            if not prev_tx:
                print("Invalid tx: referenced transaction not found")
                return False
            prev_txs[prev_tx.id] = prev_tx

            # Accumulate input value
            input_sum += prev_tx.vout[vin.vout].value

        if not tx.verify(prev_txs):
            print("Invalid tx: signature verification failed")
            return False

        if mempool:
            seen_inputs = set()
            for other_tx in mempool:
                for other_in in other_tx.vin:
                    seen_inputs.add((other_in.txid, other_in.vout))
            for vin in tx.vin:
                if (vin.txid, vin.vout) in seen_inputs:
                    print("Invalid tx: double spend detected in block")
                    return False
                
        if input_sum < output_sum:
            print("Invalid tx: input sum < output sum (creating money)")
            return False
        
        return True

    def find_utxo_set(self) -> UTXOSet:
        """
        Build UTXO set from the entire blockchain.

        Returns:
            UTXOSet: Object tracking all unspent transaction outputs.
        """
        from .transaction import TXOutput

        utxo = {}
        spent_txos = {}

        for block_hash in reversed(self.get_block_hashes()):
            block = self.get_block(block_hash)
            if not block:
                continue

            for tx in block.transactions:
                tx_id = tx.id

                # Collect unspent outputs
                for idx, out in enumerate(tx.vout):
                    if tx_id in spent_txos and idx in spent_txos[tx_id]:
                        continue
                    if tx_id not in utxo:
                        utxo[tx_id] = []
                    utxo[tx_id].append(out)

                # Mark inputs as spent
                if not tx.is_coinbase():
                    for vin in tx.vin:
                        spent_txos.setdefault(vin.txid, []).append(vin.vout)

        return UTXOSet(utxo) # type: ignore