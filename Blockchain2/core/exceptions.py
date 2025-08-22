#!/usr/bin/env python3
"""
Exception Module - Custom blockchain exceptions
==============================================

This module defines all custom exceptions used throughout the blockchain system.
Using specific exceptions helps with error handling and debugging by providing
clear error types for different failure scenarios.

Exception hierarchy:
- BlockchainError: Base exception for all blockchain operations
- InsufficientFundsError: When wallet doesn't have enough coins
- InvalidTransactionError: When transaction fails validation
- NetworkError: When network operations fail
- ValidationError: When blockchain validation fails
"""

class BlockchainError(Exception):
    """
    Base exception for blockchain operations
    
    Parent class for all blockchain-related errors. Use this for
    general blockchain failures that don't fit other categories.
    
    Examples:
    - Database connection failures
    - File I/O errors
    - General system errors
    """
    pass

class InsufficientFundsError(BlockchainError):
    """
    Raised when wallet has insufficient funds for transaction
    
    Occurs when trying to create a transaction but the sender's
    wallet doesn't have enough unspent outputs to cover the amount.
    
    Example:
    - Wallet has 5 coins but trying to send 10 coins
    - All UTXOs are already spent
    """
    pass

class InvalidTransactionError(BlockchainError):
    """
    Raised when transaction fails validation
    
    Occurs when a transaction is malformed or fails verification:
    - Invalid signatures
    - Missing referenced transactions
    - Negative amounts
    - Invalid addresses
    
    Example:
    - Transaction signed with wrong private key
    - Input references non-existent transaction
    - Output amount exceeds input amount
    """
    pass

class NetworkError(BlockchainError):
    """
    Raised when network operations fail
    
    Occurs during P2P networking operations:
    - Connection failures
    - Message serialization errors
    - Peer synchronization issues
    
    Example:
    - Cannot connect to peer node
    - Invalid network message format
    - Peer sends malformed blockchain data
    """
    pass

class ValidationError(BlockchainError):
    """
    Raised when blockchain validation fails
    
    Occurs when blockchain integrity checks fail:
    - Invalid block hashes
    - Broken chain links
    - Invalid proof of work
    - Merkle root mismatches
    
    Example:
    - Block hash doesn't match calculated hash
    - Previous block hash is incorrect
    - Proof of work doesn't meet difficulty target
    """
    pass