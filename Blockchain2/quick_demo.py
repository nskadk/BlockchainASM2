#!/usr/bin/env python3
"""
Quick Demo of Enhanced Features
Shows mempool, mining, validation, and tampering simulation
"""

import os
import sys
import time
import tempfile
import shutil

sys.path.append(os.path.join(os.path.dirname(__file__), 'core'))

from core.blockchain import Blockchain
from core.wallet import Wallet
from core.transaction import Transaction
from core.utxo import UTXOSet
from core.crypto import hash_pub_key

def main():
    print("🚀 QUICK DEMO: ENHANCED BLOCKCHAIN FEATURES")
    print("=" * 50)
    
    # Setup
    temp_dir = tempfile.mkdtemp()
    original_cwd = os.getcwd()
    
    try:
        os.chdir(temp_dir)
        
        print("\n1️⃣ CREATING WALLETS AND BLOCKCHAIN")
        print("-" * 30)
        
        # Create wallets
        wallet1 = Wallet()
        wallet2 = Wallet()
        addr1 = wallet1.get_address()
        addr2 = wallet2.get_address()
        
        wallet1.save_to_file()
        wallet2.save_to_file()
        
        print(f"✓ Wallet 1: {addr1}")
        print(f"✓ Wallet 2: {addr2}")
        
        # Create blockchain
        blockchain = Blockchain("demo.db", addr1)
        utxo_set = UTXOSet(blockchain)
        utxo_set.reindex()
        
        print(f"✓ Blockchain initialized with genesis block")
        print(f"  Genesis height: {blockchain.get_best_height()}")
        print(f"  Current difficulty: {blockchain.get_current_difficulty()}")
        
        print("\n2️⃣ MEMPOOL AND TRANSACTION MANAGEMENT")
        print("-" * 40)
        
        # Check initial balance
        pub_key_hash1 = hash_pub_key(wallet1.public_key)
        utxos = utxo_set.find_utxo(pub_key_hash1)
        balance = sum(utxo.value for utxo in utxos)
        print(f"✓ Initial balance for wallet 1: {balance} coins")
        
        # Add transactions to mempool
        print("✓ Adding transactions to mempool...")
        
        try:
            # Create a transaction
            tx1 = Transaction.new_utxo_transaction(addr1, addr2, 5, utxo_set)
            if blockchain.add_to_mempool(tx1, utxo_set):
                print(f"  - Transaction 1 added: {tx1.id[:16]}...")
            
            # Add another transaction
            tx2 = Transaction.new_utxo_transaction(addr1, addr2, 3, utxo_set)  
            if blockchain.add_to_mempool(tx2, utxo_set):
                print(f"  - Transaction 2 added: {tx2.id[:16]}...")
                
        except Exception as e:
            print(f"  - Note: {e}")
        
        mempool_txs = blockchain.get_mempool_transactions()
        print(f"✓ Mempool now contains {len(mempool_txs)} transactions")
        
        print("\n3️⃣ MINING DEMONSTRATION")
        print("-" * 30)
        
        print("✓ Mining block with pending transactions...")
        start_time = time.time()
        
        # Mine block with mempool transactions
        block = blockchain.mine_pending_transactions(addr1)
        
        if block:
            end_time = time.time()
            print(f"✓ Block #{block.height} mined successfully!")
            print(f"  Hash: {block.hash}")
            print(f"  Difficulty: {block.difficulty}")
            print(f"  Nonce: {block.nonce}")
            print(f"  Transactions: {len(block.transactions)}")
            print(f"  Mining time: {end_time - start_time:.2f} seconds")
            
            # Update UTXO cache
            utxo_set.update_utxo_incremental(block)
            
            # Check mempool after mining
            remaining_txs = blockchain.get_mempool_transactions()
            print(f"✓ Mempool now contains {len(remaining_txs)} transactions")
        else:
            print("✗ No transactions to mine")
        
        print("\n4️⃣ BLOCKCHAIN VALIDATION")
        print("-" * 30)
        
        print("✓ Validating blockchain integrity...")
        valid, errors = blockchain.validate_chain()
        
        if valid:
            print("✅ Blockchain validation: PASSED")
        else:
            print("❌ Blockchain validation: FAILED")
            for error in errors[:3]:
                print(f"   - {error}")
        
        print(f"✓ Current blockchain height: {blockchain.get_best_height()}")
        print(f"✓ Total blocks: {len(blockchain.get_block_hashes())}")
        
        print("\n5️⃣ SECURITY: TAMPERING SIMULATION")
        print("-" * 40)
        
        # Get a block to tamper with
        block_hashes = blockchain.get_block_hashes()
        if len(block_hashes) > 1:
            target_hash = block_hashes[1]  # Second block
            print(f"✓ Simulating tampering with block: {target_hash[:16]}...")
            
            result = blockchain.simulate_tampering(target_hash, "transaction")
            
            print(f"  Original chain valid: {'✅' if result['original_valid'] else '❌'}")
            print(f"  Tampered chain valid: {'✅' if result['tampered_valid'] else '❌'}")
            print(f"  Tamper details: {result.get('tamper_details', 'N/A')}")
            
            if result['affected_blocks']:
                print(f"  Affected blocks: {len(result['affected_blocks'])}")
                for block_info in result['affected_blocks'][:2]:
                    marker = "🎯" if block_info['is_tampered_block'] else "💥" 
                    print(f"    {marker} Block #{block_info['height']}: {block_info['hash'][:16]}...")
            
            if result['tampered_valid']:
                print("  ⚠️  WARNING: Tampering was not detected!")
            else:
                print("  ✅ SUCCESS: Tampering was successfully detected!")
        
        print("\n6️⃣ FINAL BLOCKCHAIN STATE")
        print("-" * 30)
        
        # Show final state
        final_hashes = blockchain.get_block_hashes()
        print(f"✓ Final blockchain overview:")
        print(f"  Height: {blockchain.get_best_height()}")
        print(f"  Total blocks: {len(final_hashes)}")
        print(f"  Current difficulty: {blockchain.get_current_difficulty()}")
        
        # Check final balances
        utxos1 = utxo_set.find_utxo(pub_key_hash1)
        balance1 = sum(utxo.value for utxo in utxos1)
        
        pub_key_hash2 = hash_pub_key(wallet2.public_key)
        utxos2 = utxo_set.find_utxo(pub_key_hash2)
        balance2 = sum(utxo.value for utxo in utxos2)
        
        print(f"  Wallet 1 balance: {balance1} coins")
        print(f"  Wallet 2 balance: {balance2} coins")
        
        print("\n🎉 ENHANCED FEATURES DEMONSTRATION COMPLETE!")
        print("\n📋 Features Demonstrated:")
        print("  ✅ Block structure with height + difficulty")
        print("  ✅ Dynamic difficulty adjustment")
        print("  ✅ Mempool transaction management")
        print("  ✅ Interactive mining with pending transactions")
        print("  ✅ Complete blockchain validation")
        print("  ✅ Security tampering simulation")
        print("  ✅ Incremental UTXO updates")
        print("  ✅ Enhanced error handling")
        
    finally:
        os.chdir(original_cwd)
        shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == '__main__':
    main()