#!/usr/bin/env python3
"""
Quick validation script for blockchain implementation
Verifies all requirements are met
"""

import os
import sys
import tempfile
import shutil

# Add core directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'core'))

def validate_block_structure():
    """Validate Requirement 1: Block Structure"""
    try:
        from core.block import Block
        from core.transaction import Transaction
        
        # Test block creation with all required fields
        tx = Transaction.new_coinbase_tx("test", "test")
        block = Block([tx], "prev_hash", 1234567890, 42, 1)
        
        # Check all required fields exist
        assert hasattr(block, 'timestamp'), "Missing timestamp"
        assert hasattr(block, 'transactions'), "Missing transactions" 
        assert hasattr(block, 'prev_block_hash'), "Missing prev_block_hash"
        assert hasattr(block, 'hash'), "Missing hash"
        assert hasattr(block, 'nonce'), "Missing nonce"
        assert hasattr(block, 'height'), "Missing height (unique identifier)"
        
        # Test block serialization
        serialized = block.serialize()
        deserialized = Block.deserialize(serialized)
        assert deserialized.height == block.height
        
        return True, "Block structure complete with all required fields"
    except Exception as e:
        return False, f"Block structure validation failed: {e}"

def validate_cryptographic_hashing():
    """Validate Requirement 2: Cryptographic Hashing & Chain Integrity"""
    try:
        from core.blockchain import Blockchain
        from core.transaction import Transaction
        
        temp_dir = tempfile.mkdtemp()
        try:
            blockchain = Blockchain(os.path.join(temp_dir, "test.db"), "test")
            
            # Test chain linkage
            from core.utxo import UTXOSet
            utxo_set = UTXOSet(blockchain)
            tx = Transaction.new_coinbase_tx("test", "test")
            block = blockchain.mine_block([tx], utxo_set)
            blockchain.add_block(block)
            
            # Verify block is linked to previous
            assert block.prev_block_hash == blockchain.get_block_hashes()[1]  # Previous tip
            
            # Test hash calculation
            assert len(block.hash) == 64, "Hash should be 64 hex characters"
            assert block.hash != block.prev_block_hash, "Hashes should be different"
            
            return True, "Cryptographic hashing and chain integrity working"
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception as e:
        return False, f"Cryptographic hashing validation failed: {e}"

def validate_transaction_handling():
    """Validate Requirement 3: Transaction Handling"""
    try:
        from core.transaction import Transaction
        from core.block import Block
        from core.merkle import merkle_root
        
        # Test transaction creation
        tx = Transaction.new_coinbase_tx("test", "test")
        assert tx.id is not None, "Transaction should have ID"
        assert tx.is_coinbase(), "Coinbase transaction detection failed"
        
        # Test Merkle tree integration
        block = Block([tx])
        merkle_result = block.hash_transactions()
        assert isinstance(merkle_result, bytes), "Merkle root should be bytes"
        assert len(merkle_result) == 32, "Merkle root should be 32 bytes"
        
        return True, "Transaction handling with Merkle tree integration working"
    except Exception as e:
        return False, f"Transaction handling validation failed: {e}"

def validate_consensus_mechanism():
    """Validate Requirement 4: Consensus Mechanism"""
    try:
        from core.block import Block
        from core.transaction import Transaction
        from core.mining import ProofOfWork
        
        # Test PoW implementation
        tx = Transaction.new_coinbase_tx("test", "test")
        block = Block([tx], "prev", 1234567890, 0, 1)
        
        # Test mining with standard difficulty
        pow_instance = ProofOfWork(block)
        nonce, hash_val = pow_instance.run()
        
        assert isinstance(nonce, int), "Nonce should be integer"
        assert isinstance(hash_val, str), "Hash should be string"
        
        # Test validation
        block.nonce = nonce
        assert pow_instance.validate(), "PoW validation should pass"
        
        # Test difficulty adjustment mechanism exists
        from core.blockchain import Blockchain
        temp_dir = tempfile.mkdtemp()
        try:
            blockchain = Blockchain(os.path.join(temp_dir, "test.db"), "test")
            difficulty = blockchain.get_current_difficulty()
            assert isinstance(difficulty, int), "Difficulty should be integer"
            
            return True, "Consensus mechanism (PoW + difficulty adjustment) implemented"
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            
    except Exception as e:
        return False, f"Consensus mechanism validation failed: {e}"

def validate_double_spend_prevention():
    """Validate Requirement 5: Double-Spend Prevention"""
    try:
        from core.blockchain import Blockchain
        from core.utxo import UTXOSet
        
        temp_dir = tempfile.mkdtemp()
        try:
            blockchain = Blockchain(os.path.join(temp_dir, "test.db"), "test")
            utxo_set = UTXOSet(blockchain)
            
            # Test UTXO finding
            utxos = blockchain.find_utxo()
            assert isinstance(utxos, dict), "UTXO should be dictionary"
            
            # Test spendable output finding
            pub_key_hash = b"test_hash"
            balance, outputs = utxo_set.find_spendable_outputs(pub_key_hash, 10)
            assert isinstance(balance, int), "Balance should be integer"
            assert isinstance(outputs, dict), "Outputs should be dictionary"
            
            return True, "Double-spend prevention (UTXO model) implemented"
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            
    except Exception as e:
        return False, f"Double-spend prevention validation failed: {e}"

def validate_global_ordering():
    """Validate Requirement 6: Global Ordering of Blocks"""
    try:
        from core.blockchain import Blockchain
        from core.transaction import Transaction
        
        temp_dir = tempfile.mkdtemp()
        try:
            blockchain = Blockchain(os.path.join(temp_dir, "test.db"), "test")
            
            # Test height ordering
            initial_height = blockchain.get_best_height()
            
            tx = Transaction.new_coinbase_tx("test", "test")
            block = blockchain.mine_block([tx])
            
            assert block.height == initial_height + 1, "Block height should increment"
            assert block.timestamp > 0, "Block should have timestamp"
            
            return True, "Global ordering of blocks maintained"
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            
    except Exception as e:
        return False, f"Global ordering validation failed: {e}"

def validate_data_persistence():
    """Validate Requirement 7: Data Persistence"""
    try:
        from core.blockchain import Blockchain
        from core.transaction import Transaction
        
        temp_dir = tempfile.mkdtemp()
        db_file = os.path.join(temp_dir, "persistence_test.db")
        
        try:
            # Create blockchain and add data
            blockchain1 = Blockchain(db_file, "test")
            tx = Transaction.new_coinbase_tx("test", "test")
            block = blockchain1.mine_block([tx])
            
            original_tip = blockchain1.tip
            original_height = blockchain1.get_best_height()
            
            del blockchain1  # Destroy object
            
            # Reload from disk
            blockchain2 = Blockchain(db_file)
            
            assert blockchain2.tip == original_tip, "Tip should be preserved"
            assert blockchain2.get_best_height() == original_height, "Height should be preserved"
            assert os.path.exists(db_file), "Database file should exist"
            
            return True, "Data persistence (SQLite) working correctly"
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            
    except Exception as e:
        return False, f"Data persistence validation failed: {e}"

def validate_user_interface():
    """Validate Requirement 8: Basic User Interface"""
    try:
        # CLI is not part of core modules - skip this test
        pass  # from core.cli import CLI
        
        # Test CLI exists and has required methods
        cli = CLI()
        
        required_methods = [
            'create_blockchain', 'create_wallet', 'list_addresses',
            'get_balance', 'send', 'print_chain'
        ]
        
        for method in required_methods:
            assert hasattr(cli, method), f"CLI missing method: {method}"
        
        return True, "CLI interface with all required commands implemented"
    except Exception as e:
        return False, f"User interface validation failed: {e}"

def validate_networking():
    """Validate Requirement 9: P2P Networking (Optional)"""
    try:
        from network import NetworkNode, NetworkMessage, MessageType
        from core.blockchain import Blockchain
        
        # Test network components exist
        temp_dir = tempfile.mkdtemp()
        try:
            blockchain = Blockchain(os.path.join(temp_dir, "test.db"), "test")
            node = NetworkNode(blockchain, 3001)
            
            assert hasattr(node, 'peers'), "Node should have peers"
            assert hasattr(node, 'mempool'), "Node should have mempool"
            
            # Test message creation
            msg = node.create_version_message()
            assert msg.command == MessageType.VERSION.value
            
            return True, "P2P Networking implemented (+4 bonus points)"
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            
    except ImportError:
        return False, "P2P Networking not implemented (optional)"
    except Exception as e:
        return False, f"P2P Networking validation failed: {e}"

def validate_wallet_functionality():
    """Validate Requirement 10: Wallet Functionality (Optional)"""
    try:
        from core.wallet import Wallet
        from core.crypto import validate_address
        
        # Test wallet creation
        wallet = Wallet()
        assert hasattr(wallet, 'private_key'), "Wallet should have private key"
        assert hasattr(wallet, 'public_key'), "Wallet should have public key"
        
        # Test address generation
        address = wallet.get_address()
        assert isinstance(address, str), "Address should be string"
        assert validate_address(address), "Address should be valid"
        
        # Test wallet persistence
        temp_dir = tempfile.mkdtemp()
        original_cwd = os.getcwd()
        
        try:
            os.chdir(temp_dir)
            wallet.save_to_file()
            
            loaded_wallet = Wallet.load_from_file(address)
            assert loaded_wallet is not None, "Wallet should load from file"
            assert loaded_wallet.get_address() == address, "Loaded address should match"
            
            return True, "Wallet functionality implemented (+4 bonus points)"
        finally:
            os.chdir(original_cwd)
            shutil.rmtree(temp_dir, ignore_errors=True)
            
    except Exception as e:
        return False, f"Wallet functionality validation failed: {e}"

def main():
    """Main validation function"""
    print("🔍 BLOCKCHAIN IMPLEMENTATION VALIDATOR")
    print("Checking all requirements from INTE264 Assignment 2\n")
    
    validators = [
        ("1. Block Structure [10 pts]", validate_block_structure),
        ("2. Cryptographic Hashing & Chain Integrity [10 pts]", validate_cryptographic_hashing),
        ("3. Transaction Handling [6 pts]", validate_transaction_handling),  
        ("4. Consensus Mechanism [6 pts]", validate_consensus_mechanism),
        ("5. Double-Spend Prevention [6 pts]", validate_double_spend_prevention),
        ("6. Global Ordering of Blocks [6 pts]", validate_global_ordering),
        ("7. Data Persistence [3 pts]", validate_data_persistence),
        ("8. Basic User Interface [3 pts]", validate_user_interface),
        ("9. P2P Networking [+4 pts] (Optional)", validate_networking),
        ("10. Wallet Functionality [+4 pts] (Optional)", validate_wallet_functionality)
    ]
    
    total_points = 0
    max_points = 50  # Base points
    results = []
    
    for requirement, validator in validators:
        try:
            passed, message = validator()
            if passed:
                print(f"✅ {requirement}")
                print(f"   {message}")
                
                # Calculate points
                if "10 pts" in requirement:
                    total_points += 10
                elif "6 pts" in requirement:
                    total_points += 6
                elif "3 pts" in requirement:
                    total_points += 3
                elif "+4 pts" in requirement:
                    total_points += 4
                    
                results.append((requirement, True, message))
            else:
                print(f"❌ {requirement}")
                print(f"   {message}")
                results.append((requirement, False, message))
                
        except Exception as e:
            print(f"❌ {requirement}")
            print(f"   Validation error: {e}")
            results.append((requirement, False, f"Validation error: {e}"))
            
        print()
    
    # Summary
    print("=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    
    passed_count = sum(1 for _, passed, _ in results if passed)
    total_count = len(results)
    
    print(f"Requirements passed: {passed_count}/{total_count}")
    print(f"Points earned: {total_points}/{max_points}")
    print(f"Grade: {(total_points/max_points)*100:.1f}%")
    
    if total_points >= 50:
        print("\n🎉 EXCELLENT! All requirements implemented including bonuses!")
    elif total_points >= 42:
        print("\n✅ VERY GOOD! All core requirements met with some bonuses.")
    elif total_points >= 35:
        print("\n✅ GOOD! Most requirements implemented.")
    else:
        print("\n⚠️  Some requirements need attention.")
    
    print("\nDetailed Results:")
    for requirement, passed, message in results:
        status = "PASS" if passed else "FAIL"
        print(f"  {status}: {requirement}")
        if not passed:
            print(f"    Issue: {message}")
    
    return total_points >= 35  # Pass threshold

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)