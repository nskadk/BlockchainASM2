#!/usr/bin/env python3
"""
Dynamic Web UI for Blockchain
Modern web interface to replace CLI commands
"""

import os
import sys
import json
import base64
from datetime import datetime
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import threading

# Add core directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'core'))

from core.blockchain import Blockchain
from core.wallet import Wallet, Wallets
from core.transaction import Transaction
from core.utxo import UTXOSet
from core.crypto import validate_address, hash_pub_key

app = Flask(__name__)
app.config['SECRET_KEY'] = 'blockchain_secret_key_2023'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global blockchain instance
blockchain = None
utxo_set = None
wallets = None

def init_blockchain():
    """Initialize blockchain instance"""
    global blockchain, utxo_set, wallets
    try:
        # Try to load existing blockchain
        blockchain = Blockchain("web_blockchain.db")
        utxo_set = UTXOSet(blockchain)
        utxo_set.reindex()
        wallets = Wallets()
        return True
    except:
        blockchain = None
        utxo_set = None
        wallets = None
        return False

def serialize_for_json(obj):
    """Convert bytes to base64 for JSON serialization"""
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode('utf-8')
    elif isinstance(obj, dict):
        return {k: serialize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [serialize_for_json(item) for item in obj]
    else:
        return obj

def emit_update(event, data):
    """Emit update to all connected clients"""
    socketio.emit(event, data, broadcast=True) # type: ignore

@app.route('/')
def index():
    """Main dashboard"""
    return app.send_static_file('index.html')

@app.route('/api/blockchain/info')
def blockchain_info():
    """Get blockchain information"""
    if not blockchain:
        return jsonify({'error': 'Blockchain not initialized'}), 400
    
    try:
        block_hashes = blockchain.get_block_hashes()
        mempool_txs = blockchain.get_mempool_transactions()
        
        # Get latest block info
        latest_block = None
        if block_hashes:
            latest_block_data = blockchain.get_block(block_hashes[0])
            if latest_block_data:
                latest_block = {
                    'hash': latest_block_data.hash,
                    'height': getattr(latest_block_data, 'height', 0),
                    'timestamp': latest_block_data.timestamp,
                    'timestamp_str': datetime.fromtimestamp(latest_block_data.timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                    'transactions': [{'id': tx.id, 'vin_count': len(tx.vin), 'vout_count': len(tx.vout)} for tx in latest_block_data.transactions]
                }
        
        return jsonify({
            'height': blockchain.get_best_height(),
            'blocks_count': len(block_hashes),
            'mempool_size': len(mempool_txs),
            'difficulty': blockchain.get_current_difficulty(),
            'latest_block': latest_block
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/blocks')
def get_blocks():
    """Get all blocks"""
    if not blockchain:
        return jsonify({'error': 'Blockchain not initialized'}), 400
    
    try:
        block_hashes = blockchain.get_block_hashes()
        blocks = []
        
        for i, block_hash in enumerate(block_hashes):
            block = blockchain.get_block(block_hash)
            if block:
                block_data = {
                    'hash': block.hash,
                    'prev_block_hash': block.prev_block_hash,
                    'height': getattr(block, 'height', len(block_hashes) - i - 1),
                    'difficulty': getattr(block, 'difficulty', 4),
                    'nonce': block.nonce,
                    'timestamp': block.timestamp,
                    'timestamp_str': datetime.fromtimestamp(block.timestamp).strftime('%Y-%m-%d %H:%M:%S'),
                    'transactions': [{'id': tx.id, 'vin': len(tx.vin), 'vout': len(tx.vout)} for tx in block.transactions]
                }
                blocks.append(block_data)
        
        return jsonify(blocks)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/mempool')
def get_mempool():
    """Get mempool transactions"""
    if not blockchain:
        return jsonify({'error': 'Blockchain not initialized'}), 400
    
    try:
        mempool_txs = blockchain.get_mempool_transactions()
        transactions = []
        
        for tx in mempool_txs:
            transactions.append({
                'id': tx.id,
                'vin': len(tx.vin),
                'vout': len(tx.vout)
            })
        
        return jsonify(transactions)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/wallets')
def get_wallets():
    """Get all wallets"""
    try:
        if not wallets:
            return jsonify([])
        
        wallet_list = []
        for address in wallets.get_addresses():
            if utxo_set:
                pub_key_hash = hash_pub_key(wallets.get_wallet(address).public_key) # type: ignore
                utxos = utxo_set.find_utxo(pub_key_hash)
                balance = sum(utxo.value for utxo in utxos)
            else:
                balance = 0
            
            wallet_list.append({
                'address': address,
                'balance': balance
            })
        
        return jsonify(wallet_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/wallets', methods=['POST'])
def create_wallet():
    """Create new wallet"""
    try:
        global wallets
        if not wallets:
            wallets = Wallets()
        
        address = wallets.create_wallet()
        emit_update('wallet_created', {'address': address})
        
        return jsonify({
            'success': True,
            'address': address
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/wallets/<address>/balance')
def get_wallet_balance(address):
    """Get wallet balance"""
    try:
        if not validate_address(address):
            return jsonify({'error': 'Invalid address'}), 400
        
        if not utxo_set:
            return jsonify({'error': 'UTXO set not initialized'}), 400
        
        wallet = Wallet.load_from_file(address)
        if not wallet:
            return jsonify({'error': 'Wallet not found'}), 404
        
        pub_key_hash = hash_pub_key(wallet.public_key)
        utxos = utxo_set.find_utxo(pub_key_hash)
        balance = sum(utxo.value for utxo in utxos)
        
        return jsonify({'balance': balance})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/transactions', methods=['POST'])
def send_transaction():
    """Send transaction"""
    try:
        data = request.get_json()
        from_addr = data.get('from')
        to_addr = data.get('to')
        amount = int(data.get('amount', 0))
        
        if not all([from_addr, to_addr, amount]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        if not validate_address(from_addr) or not validate_address(to_addr):
            return jsonify({'error': 'Invalid address'}), 400
        
        # Create transaction
        tx = Transaction.new_utxo_transaction(from_addr, to_addr, amount, utxo_set)
        
        # Add to mempool
        if blockchain.add_to_mempool(tx, utxo_set): # type: ignore
            emit_update('transaction_added', {'transaction_id': tx.id, 'amount': amount})
            return jsonify({
                'success': True,
                'transaction_id': tx.id
            })
        else:
            return jsonify({'error': 'Failed to add transaction to mempool'}), 400
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/mining/start', methods=['POST'])
def start_mining():
    """Start mining"""
    try:
        data = request.get_json()
        mining_address = data.get('address')
        
        if not mining_address:
            return jsonify({'error': 'Mining address required'}), 400
        
        if not validate_address(mining_address):
            return jsonify({'error': 'Invalid mining address'}), 400
        
        # Mine block
        block = blockchain.mine_pending_transactions(mining_address) # type: ignore
        
        if block:
            # Update UTXO set
            utxo_set.update_utxo_incremental(block) # type: ignore
            emit_update('mining_complete', {'height': block.height})
            
            return jsonify({
                'success': True,
                'block': {
                    'hash': block.hash,
                    'height': block.height,
                    'transactions': len(block.transactions)
                }
            })
        else:
            return jsonify({
                'success': True,
                'message': 'No transactions to mine'
            })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/blockchain/validate')
def validate_blockchain():
    """Validate blockchain"""
    try:
        if not blockchain:
            return jsonify({'error': 'Blockchain not initialized'}), 400
        
        valid, errors = blockchain.validate_chain()
        
        return jsonify({
            'valid': valid,
            'errors': errors
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/blockchain/tamper', methods=['POST'])
def tamper_blockchain():
    """Simulate tampering"""
    try:
        data = request.get_json()
        block_hash = data.get('blockHash')
        tamper_type = data.get('type', 'transaction')
        
        if not block_hash:
            return jsonify({'error': 'Block hash required'}), 400
        
        result = blockchain.simulate_tampering(block_hash, tamper_type) # type: ignore
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Initialize blockchain on startup
print("🚀 Starting Blockchain Web UI...")
if init_blockchain():
    print("✅ Blockchain loaded successfully")
else:
    print("⚠️  No existing blockchain found - create a wallet to start")

if __name__ == '__main__':
    print("🌐 Starting web server on http://localhost:5000")
    print("📱 Access the dynamic UI in your web browser")
    print("🔗 Features: Wallet management, transactions, mining, tampering simulation, networking")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)