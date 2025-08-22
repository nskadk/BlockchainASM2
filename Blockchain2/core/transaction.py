#!/usr/bin/env python3
"""
Transaction Module - Handles all transaction-related functionality
============================================================

This module contains the core transaction system for the blockchain:
- TXInput: Represents coins being spent (references to previous outputs)
- TXOutput: Represents coins being sent (new spendable outputs) 
- Transaction: Complete transaction with inputs, outputs, and signatures

Key Features:
- UTXO (Unspent Transaction Output) model prevents double-spending
- ECDSA digital signatures for transaction authorization
- Coinbase transactions for mining rewards (create new coins)
- Transaction verification using cryptographic signatures
- Merkle tree integration for block validation

Transaction Types:
1. Regular Transaction: Transfers coins between users
   - Has inputs (coins being spent) and outputs (coins being sent)
   - Requires valid signatures from coin owners
   - Must balance: total inputs >= total outputs

2. Coinbase Transaction: Mining reward
   - Has no inputs (creates new coins from nothing)
   - Has one output (reward to miner)
   - Only miners can create these when finding blocks

Security Model:
- Each input must be signed with private key of coin owner
- Signatures prevent unauthorized spending of others' coins
- Transaction hash prevents tampering after creation
- UTXO tracking prevents double-spending attacks
"""

import hashlib
import pickle
import ecdsa
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict

@dataclass
class TXInput:
    """
    Transaction Input - Represents coins being spent
    
    Points to a specific output from a previous transaction that
    is being spent in this transaction. Contains cryptographic
    proof that the spender owns these coins.
    
    Fields:
    - txid: Hash of transaction containing the output being spent
    - vout: Index of output being spent (0=first output, 1=second, etc.)
    - signature: Digital signature proving ownership of the coins
    - pub_key: Public key for signature verification
    
    Example:
    To spend the first output of transaction "abc123...", create:
    TXInput(txid="abc123...", vout=0, signature=sig_bytes, pub_key=pubkey_bytes)
    """
    txid: str       # Transaction ID being referenced  
    vout: int       # Output index in the referenced transaction
    signature: bytes # Digital signature proving ownership
    pub_key: bytes   # Public key for verification

    def uses_key(self, pub_key_hash: bytes) -> bool:
        """
        Check if this input uses a specific public key hash
        
        Determines if a wallet owns this input by comparing
        the hash of the public key with the provided hash.
        Used for balance calculations and ownership verification.
        
        Args:
        - pub_key_hash: Hash to check against
        
        Returns:
        - True if this input belongs to the given public key hash
        """
        from .crypto import hash_pub_key
        locking_hash = hash_pub_key(self.pub_key)
        return locking_hash == pub_key_hash

@dataclass  
class TXOutput:
    """
    Transaction Output - Represents coins being sent
    
    Creates new spendable coins that can be used as inputs
    in future transactions. Each output:
    - Contains a specific amount of coins
    - Is "locked" to a specific address (public key hash)
    - Can only be spent by owner of corresponding private key
    
    Fields:
    - value: Amount of coins in this output (must be positive)
    - pub_key_hash: Hash of recipient's public key (their address)
    
    Example:
    To send 10 coins to address "1ABC...", create:
    TXOutput(value=10, pub_key_hash=decode_address("1ABC..."))
    """
    value: int           # Amount of coins (must be positive)
    pub_key_hash: bytes  # Public key hash (recipient address)

    def lock(self, address: str):
        """
        Lock output to a specific address
        
        Converts a human-readable address to its underlying public key hash
        and locks the output so only that address can spend it.
        
        Args:
        - address: Base58-encoded address string
        
        Process:
        1. Decode address to get public key hash
        2. Store hash in pub_key_hash field
        3. Output now belongs to address owner
        """
        from .crypto import decode_address
        pub_key_hash = decode_address(address)
        self.pub_key_hash = pub_key_hash

    def is_locked_with_key(self, pub_key_hash: bytes) -> bool:
        """
        Check if output is locked with specific public key hash
        
        Determines if a wallet can spend this output by comparing
        public key hashes. Used for:
        - Finding spendable outputs for transactions
        - Calculating wallet balances
        - UTXO set management
        
        Args:
        - pub_key_hash: Hash to check against
        
        Returns:
        - True if output can be spent by given public key hash
        """
        return self.pub_key_hash == pub_key_hash

class Transaction:
    """
    Blockchain Transaction - Transfers coins between addresses
    
    Implements the UTXO (Unspent Transaction Output) model where:
    - Inputs reference previous outputs being spent
    - Outputs create new spendable coins
    - Digital signatures prove ownership
    - Transaction balance must be maintained (inputs >= outputs)
    
    Transaction lifecycle:
    1. Creation: Specify sender, recipient, amount
    2. Input selection: Find unspent outputs to cover amount
    3. Output creation: Create outputs for recipient and change
    4. Signing: Sign inputs with sender's private key
    5. Verification: Validate signatures and references
    6. Broadcasting: Add to mempool for mining
    7. Mining: Include in block and add to blockchain
    
    Security guarantees:
    - Only coin owners can spend their coins (signature verification)
    - Coins cannot be double-spent (UTXO tracking)
    - Transaction cannot be modified after signing (hash integrity)
    """
    
    def __init__(self, id: str = "", vin: List[TXInput] = None, vout: List[TXOutput] = None):
        """
        Initialize transaction
        
        Args:
        - id: Transaction hash (calculated automatically if empty)
        - vin: List of transaction inputs (coins being spent)
        - vout: List of transaction outputs (coins being sent)
        """
        self.id = id
        self.vin = vin or []
        self.vout = vout or []

    def hash(self) -> str:
        """
        Calculate transaction hash using SHA256
        
        Creates a unique identifier for this transaction by hashing
        all transaction data. The hash serves multiple purposes:
        - Unique transaction ID for references
        - Integrity verification (detects tampering)
        - Merkle tree construction for blocks
        - Blockchain validation
        
        Process:
        1. Create trimmed copy (without signatures)
        2. Serialize transaction data
        3. Calculate SHA256 hash
        4. Return hex-encoded hash string
        
        Returns:
        - 64-character hex string (SHA256 hash)
        """
        tx_copy = self.trimmed_copy()
        data = pickle.dumps(tx_copy)
        return hashlib.sha256(data).hexdigest()

    def set_id(self):
        """Set transaction ID by calculating hash"""
        self.id = self.hash()

    def sign(self, private_key: ecdsa.SigningKey, prev_txs: Dict[str, 'Transaction']):
        """
        Sign transaction inputs with private key
        
        Creates digital signatures proving that the transaction sender
        owns the coins being spent. Each input is signed separately.
        
        Signing process for each input:
        1. Verify referenced transaction exists
        2. Create transaction copy with empty signatures
        3. Replace signature field with referenced output's pub_key_hash
        4. Serialize and hash the modified transaction
        5. Sign the hash with private key
        6. Store signature in original transaction
        
        Args:
        - private_key: ECDSA private key for signing
        - prev_txs: Dictionary of previous transactions being referenced
        
        Raises:
        - InvalidTransactionError: If referenced transaction not found
        
        Security: Only the owner of the private key can create valid signatures.
        """
        if self.is_coinbase():
            return  # Coinbase transactions don't need signing

        # Verify all inputs reference valid transactions
        for vin in self.vin:
            if vin.txid not in prev_txs:
                from .exceptions import InvalidTransactionError
                raise InvalidTransactionError(f"Previous transaction {vin.txid} not found")

        tx_copy = self.trimmed_copy()

        # Sign each input
        for i, vin in enumerate(tx_copy.vin):
            prev_tx = prev_txs[vin.txid]
            tx_copy.vin[i].signature = b''
            tx_copy.vin[i].pub_key = prev_tx.vout[vin.vout].pub_key_hash
            
            data_to_sign = pickle.dumps(tx_copy)
            signature = private_key.sign(data_to_sign, hashfunc=hashlib.sha256)
            self.vin[i].signature = signature

    def verify(self, prev_txs: Dict[str, 'Transaction']) -> bool:
        """
        Verify transaction signatures
        
        Validates that all transaction inputs are properly signed
        by the owners of the coins being spent. This prevents
        unauthorized spending and ensures transaction integrity.
        
        Verification process for each input:
        1. Check referenced transaction exists
        2. Recreate signing data (same as signing process)
        3. Use public key to verify signature
        4. Ensure signature matches transaction data
        
        Args:
        - prev_txs: Dictionary of previous transactions
        
        Returns:
        - True if all signatures valid, False otherwise
        
        Security: Invalid signatures indicate:
        - Attempted unauthorized spending
        - Transaction tampering
        - Corrupted transaction data
        """
        if self.is_coinbase():
            return True  # Coinbase transactions are always valid

        # Check all referenced transactions exist
        for vin in self.vin:
            if vin.txid not in prev_txs:
                return False

        tx_copy = self.trimmed_copy()

        # Verify each input signature
        for i, vin in enumerate(self.vin):
            prev_tx = prev_txs[vin.txid]
            tx_copy.vin[i].signature = b''
            tx_copy.vin[i].pub_key = prev_tx.vout[vin.vout].pub_key_hash

            try:
                data_to_verify = pickle.dumps(tx_copy)
                pub_key = ecdsa.VerifyingKey.from_string(vin.pub_key, curve=ecdsa.SECP256k1)
                pub_key.verify(vin.signature, data_to_verify, hashfunc=hashlib.sha256)
            except (ecdsa.BadSignatureError, ValueError):
                return False

        return True

    def trimmed_copy(self) -> 'Transaction':
        """
        Create a copy of transaction without signatures
        
        Used during signing/verification process. Creates a clean copy
        with empty signatures and public keys for consistent hashing.
        
        Returns:
        - Transaction copy with cleared signature fields
        
        Purpose: Ensures signature is calculated on transaction content
        only, not including the signature itself (prevents circular dependency).
        """
        inputs = []
        outputs = []

        for vin in self.vin:
            inputs.append(TXInput(vin.txid, vin.vout, b'', b''))

        for vout in self.vout:
            outputs.append(TXOutput(vout.value, vout.pub_key_hash))

        return Transaction(self.id, inputs, outputs)

    def is_coinbase(self) -> bool:
        """
        Check if transaction is a coinbase (mining reward) transaction
        
        Coinbase transactions are special transactions that:
        - Create new coins from nothing (mining reward)
        - Have exactly one input with empty txid and vout=-1
        - Don't require signatures (no previous coins being spent)
        - Only created by miners when finding blocks
        
        Returns:
        - True if this is a coinbase transaction
        """
        return len(self.vin) == 1 and len(self.vin[0].txid) == 0 and self.vin[0].vout == -1

    @staticmethod
    def new_coinbase_tx(to: str, data: str = "") -> 'Transaction':
        """
        Create new coinbase transaction (mining reward)
        
        Coinbase transactions are how new coins enter the system.
        They are created by miners as a reward for finding blocks.
        
        Characteristics:
        - No inputs (coins created from nothing)
        - One output (reward to miner)
        - Arbitrary data allowed in input field
        - No signature required
        
        Args:
        - to: Address to receive mining reward
        - data: Optional message/data for the coinbase
        
        Returns:
        - New coinbase transaction with mining reward
        
        Economic purpose: Incentivizes miners to secure the network
        by providing rewards for computational work.
        """
        from .config import SUBSIDY
        
        if not data:
            data = f"Reward to '{to}'"

        # Coinbase input: empty txid, vout=-1, arbitrary data
        txin = TXInput("", -1, b'', data.encode())
        
        # Output: mining reward to miner's address
        txout = TXOutput(SUBSIDY, b'')
        
        # Lock output to miner's address if valid
        if to:
            try:
                txout.lock(to)
            except Exception:
                # If address invalid, leave pub_key_hash empty
                txout.pub_key_hash = b''

        tx = Transaction(vin=[txin], vout=[txout])
        tx.set_id()
        return tx

    @staticmethod
    def new_utxo_transaction(from_addr: str, to_addr: str, amount: int, utxo_set) -> 'Transaction':
        """
        Create new UTXO transaction between addresses
        
        Implements the UTXO model by finding unspent outputs owned by
        the sender and creating a new transaction that spends them.
        
        UTXO Process:
        1. Find sender's unspent outputs (UTXOs)
        2. Select enough outputs to cover amount + fees
        3. Create inputs referencing selected outputs
        4. Create output for recipient
        5. Create change output back to sender (if needed)
        6. Sign all inputs with sender's private key
        
        Args:
        - from_addr: Sender's address
        - to_addr: Recipient's address
        - amount: Amount to send (must be positive)
        - utxo_set: UTXO set for finding spendable outputs
        
        Returns:
        - New signed transaction ready for blockchain
        
        Raises:
        - BlockchainError: If sender wallet not found
        - InsufficientFundsError: If sender has insufficient funds
        
        Example:
        Alice has 15 coins in two outputs: 10 + 5 coins
        Alice sends 12 coins to Bob
        Result: Input 10+5=15, Output 12 to Bob + 3 change to Alice
        """
        from .wallet import Wallet
        from .exceptions import BlockchainError, InsufficientFundsError
        from .crypto import hash_pub_key
        
        # Load sender's wallet
        wallet = Wallet.load_from_file(from_addr)
        if not wallet:
            raise BlockchainError(f"Wallet for address {from_addr} not found")

        # Find spendable outputs for this amount
        pub_key_hash = hash_pub_key(wallet.public_key)
        acc, valid_outputs = utxo_set.find_spendable_outputs(pub_key_hash, amount)

        if acc < amount:
            raise InsufficientFundsError(f"Not enough funds: {acc} < {amount}")

        # Create inputs from spendable outputs
        inputs = []
        for txid, outs in valid_outputs.items():
            for out in outs:
                input_tx = TXInput(txid, out, b'', wallet.public_key)
                inputs.append(input_tx)

        # Create outputs
        outputs = []
        
        # Output to recipient
        recipient_output = TXOutput(amount, b'')
        recipient_output.lock(to_addr)
        outputs.append(recipient_output)

        # Change output back to sender (if any leftover)
        if acc > amount:
            change_output = TXOutput(acc - amount, b'')
            change_output.lock(from_addr)
            outputs.append(change_output)

        # Create and sign transaction
        tx = Transaction(vin=inputs, vout=outputs)
        tx.set_id()
        utxo_set.blockchain.sign_transaction(tx, wallet.private_key)

        return tx

    def to_dict(self) -> Dict:
        """
        Convert transaction to dictionary for JSON serialization
        
        Creates a JSON-safe representation of the transaction
        by converting all fields to basic Python types.
        
        Returns:
        - Dictionary representation suitable for:
          * JSON API responses
          * Database storage
          * Network transmission
          * Web UI display
        
        Note: Bytes fields are converted to hex strings for JSON compatibility.
        """
        return {
            'id': self.id,
            'vin': [asdict(inp) for inp in self.vin],
            'vout': [asdict(out) for out in self.vout]
        }