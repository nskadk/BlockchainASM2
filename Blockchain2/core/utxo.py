#!/usr/bin/env python3
from typing import List, Dict, Tuple, TYPE_CHECKING
from .transaction import TXOutput

if TYPE_CHECKING:
    from .blockchain import Blockchain
    from .block import Block
    from .transaction import Transaction


class UTXOSet:
    """
    Complete UTXOSet class with proper UTXO management.
    Tracks unspent transaction outputs, supports verification,
    incremental update, and double-spend prevention.
    """

    def __init__(self, blockchain: 'Blockchain'):
        self.blockchain = blockchain
        self._cache: Dict[str, List[TXOutput]] = {}
        self._cache_valid = False

    def reindex(self):
        """Rebuild full UTXO cache from blockchain"""
        new_utxo = self.blockchain.find_utxo_set()
        self._cache = new_utxo._cache  # txid -> list(TXOutput)
        self._cache_valid = True
        print(f"UTXO set reindexed. Total transactions: {len(self._cache)}")

    def invalidate_cache(self):
        """Invalidate UTXO cache (force full rebuild on next use)"""
        self._cache_valid = False
        self._cache = {}

    def contains(self, txid: str, vout_index: int) -> bool:
        """Check if a specific UTXO exists (not spent)"""
        if not self._cache_valid:
            self.reindex()
        outputs = self._cache.get(txid)
        return (
            outputs is not None and
            0 <= vout_index < len(outputs) and
            outputs[vout_index] is not None
        )
    def spend_output(self, txid: str, out_index: int):
        """Mark a specific output as spent"""
        if not self._cache_valid:
            self.reindex()
        if txid in self._cache and 0 <= out_index < len(self._cache[txid]):
            outputs = self._cache[txid]
            # Remove the spent output
            self._cache[txid] = [o for i, o in enumerate(outputs) if i != out_index]
            if not self._cache[txid]:
                del self._cache[txid]

    def update_utxo_incremental(self, block: 'Block'):
        """
        Update UTXO set after a new block is mined
        Safely remove spent outputs and add new outputs
        """
        if not self._cache_valid:
            self.reindex()
            return

        # Remove spent outputs first
        for tx in block.transactions:
            if not tx.is_coinbase():
                for vin in tx.vin:
                    self.spend_output(vin.txid, vin.vout)

        # Add all new outputs to UTXO set
        for tx in block.transactions:
            if tx.vout:
                self._cache[tx.id] = tx.vout.copy()

    def find_spendable_outputs(self, pub_key_hash: bytes, amount: int) -> Tuple[int, Dict[str, List[int]]]:
        """Find outputs belonging to pub_key_hash sufficient to cover amount"""
        if not self._cache_valid:
            self.reindex()

        accumulated = 0
        unspent_outputs: Dict[str, List[int]] = {}

        for tx_id, outputs in self._cache.items():
            for idx, out in enumerate(outputs):
                if out.is_locked_with_key(pub_key_hash) and accumulated < amount:
                    accumulated += out.value
                    if tx_id not in unspent_outputs:
                        unspent_outputs[tx_id] = []
                    unspent_outputs[tx_id].append(idx)
                    if accumulated >= amount:
                        break
            if accumulated >= amount:
                break

        return accumulated, unspent_outputs

    def find_utxo(self, pub_key_hash: bytes) -> List[TXOutput]:
        """Return all UTXOs belonging to a pub_key_hash"""
        if not self._cache_valid:
            self.reindex()
        utxos = []
        for outputs in self._cache.values():
            for out in outputs:
                if out.is_locked_with_key(pub_key_hash):
                    utxos.append(out)
        return utxos

    def get_balance(self, pub_key_hash: bytes) -> int:
        """Calculate total balance for a public key hash"""
        utxos = self.find_utxo(pub_key_hash)
        return sum(out.value for out in utxos)

    def count_utxos(self) -> int:
        """Count total unspent outputs"""
        if not self._cache_valid:
            self.reindex()
        return sum(len(outputs) for outputs in self._cache.values())

    def get_cache_stats(self) -> Dict:
        """Get stats about the UTXO cache"""
        if not self._cache_valid:
            return {"valid": False, "transactions": 0, "total_utxos": 0, "estimated_memory_kb": 0}
        total_utxos = self.count_utxos()
        return {
            "valid": self._cache_valid,
            "transactions": len(self._cache),
            "total_utxos": total_utxos,
            "estimated_memory_kb": (total_utxos * 100) // 1024
        }
    
    def apply_transaction(self, tx: 'Transaction') -> None:
        """
        Mutate the UTXO set by spending tx inputs and adding tx outputs.
        Assumes the tx has already been validated.
        """
        if not self._cache_valid:
            self.reindex()

        # Spend inputs (skip coinbase)
        if not tx.is_coinbase():
            for vin in tx.vin:
                outs = self._cache.get(vin.txid)
                if outs is not None and 0 <= vin.vout < len(outs):
                    # Mark spent without changing indices to avoid reindex problems
                    outs[vin.vout] = None # type: ignore
                    # Optional cleanup: if all outputs are None, drop the entry
                    if all(o is None for o in outs):
                        del self._cache[vin.txid]

        # Add new outputs
        # Store as a list; indices must match tx.vout indices
        # (no deepcopy needed for simple dataclasses, but you can copy if you prefer)
        self._cache[tx.id] = list(tx.vout)

    def update_with_transactions(self, txs: List['Transaction']) -> None:
        """
        Apply a list of transactions (e.g., a full block's transactions).
        """
        if not self._cache_valid:
            self.reindex()
        for tx in txs:
            self.apply_transaction(tx)

    def update_for_block(self, block: 'Block') -> None:
        """
        Apply a mined block to the UTXO set.
        """
        self.update_with_transactions(block.transactions)

    # Back-compat alias so your existing call works:
    def update(self, transactions: List['Transaction']) -> None:
        """
        Alias for update_with_transactions to support existing usage:
            utxo_set.update(block.transactions)
        """
        self.update_with_transactions(transactions)


