#!/usr/bin/env python3
"""
Blockchain Networking Module
Handles peer-to-peer communication and network synchronization

Key improvements over Go implementation:
1. Asyncio-based networking for better concurrency
2. JSON-based message protocol (more readable than binary)
3. Automatic peer discovery and connection management
4. Built-in message validation and error handling
5. WebSocket support for real-time communication
"""

import asyncio
import json
import socket
import threading
import time
import base64
import pickle
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import websockets
import logging

# Import blockchain components
from .blockchain import Blockchain
from .block import Block
from .transaction import Transaction
from .utxo import UTXOSet

# Network configuration
DEFAULT_PORT = 3000
PROTOCOL_VERSION = 1
COMMAND_LENGTH = 12
NODE_VERSION = 1

# Message types
class MessageType(Enum):
    VERSION = "version"
    GET_BLOCKS = "getblocks"
    GET_DATA = "getdata"
    INVENTORY = "inventory"
    BLOCK = "block"
    TRANSACTION = "transaction"
    ADDR = "addr"
    PING = "ping"
    PONG = "pong"

@dataclass
class NetworkMessage:
    """Network message structure"""
    command: str
    payload: dict
    node_address: str = ""
    timestamp: int = 0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = int(time.time())

    def serialize(self) -> bytes:
        """Serialize message to bytes"""
        data = {
            'command': self.command,
            'payload': self.payload,
            'node_address': self.node_address,
            'timestamp': self.timestamp
        }
        return json.dumps(data).encode()

    @classmethod
    def deserialize(cls, data: bytes) -> 'NetworkMessage':
        """Deserialize message from bytes"""
        json_data = json.loads(data.decode())
        return cls(
            command=json_data['command'],
            payload=json_data['payload'],
            node_address=json_data.get('node_address', ''),
            timestamp=json_data.get('timestamp', int(time.time()))
        )

@dataclass
class Peer:
    """Represents a network peer"""
    address: str
    port: int
    last_seen: int = 0
    version: int = 0
    connected: bool = False

    def __post_init__(self):
        if not self.last_seen:
            self.last_seen = int(time.time())

    @property
    def full_address(self) -> str:
        return f"{self.address}:{self.port}"

class NetworkNode:
    """Network node for blockchain P2P communication"""

    def __init__(self, blockchain: Blockchain, port: int = DEFAULT_PORT, 
                 node_address: str = "localhost"):
        self.blockchain = blockchain
        self.port = port
        self.node_address = node_address
        self.peers: Dict[str, Peer] = {}
        self.known_nodes: Set[str] = set()
        self.blocks_in_transit: List[str] = []
        self.mempool: Dict[str, Transaction] = {}
        self.server = None
        self.running = False
        
        # Logging setup
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(f"Node-{port}")

    async def start_server(self):
        """Start the network server"""
        self.running = True
        self.server = await websockets.serve(
            self.handle_client,  # type: ignore
            "localhost", 
            self.port
        )
        self.logger.info(f"Node started on port {self.port}")

    async def stop_server(self):
        """Stop the network server"""
        self.running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def handle_client(self, websocket, path):
        """Handle incoming client connections"""
        peer_address = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
        self.logger.info(f"New connection from {peer_address}")
        
        try:
            async for message in websocket:
                await self.handle_message(websocket, message, peer_address)
        except websockets.exceptions.ConnectionClosed:
            self.logger.info(f"Connection closed: {peer_address}")
        except Exception as e:
            self.logger.error(f"Error handling client {peer_address}: {e}")

    async def handle_message(self, websocket, message: str, peer_address: str):
        """Handle incoming network messages"""
        try:
            msg = NetworkMessage.deserialize(message.encode())
            self.logger.info(f"Received {msg.command} from {peer_address}")

            if msg.command == MessageType.VERSION.value:
                await self.handle_version(websocket, msg)
            elif msg.command == MessageType.GET_BLOCKS.value:
                await self.handle_get_blocks(websocket, msg)
            elif msg.command == MessageType.GET_DATA.value:
                await self.handle_get_data(websocket, msg)
            elif msg.command == MessageType.INVENTORY.value:
                await self.handle_inventory(websocket, msg)
            elif msg.command == MessageType.BLOCK.value:
                await self.handle_block(websocket, msg)
            elif msg.command == MessageType.TRANSACTION.value:
                await self.handle_transaction(websocket, msg)
            elif msg.command == MessageType.ADDR.value:
                await self.handle_addr(websocket, msg)
            elif msg.command == MessageType.PING.value:
                await self.handle_ping(websocket, msg)
            else:
                self.logger.warning(f"Unknown command: {msg.command}")

        except Exception as e:
            self.logger.error(f"Error processing message: {e}")

    async def handle_version(self, websocket, msg: NetworkMessage):
        """Handle version message"""
        payload = msg.payload
        peer = Peer(
            address=payload.get('addr_from', 'unknown'),
            port=payload.get('port', 0),
            version=payload.get('version', 0),
            connected=True
        )
        
        self.peers[msg.node_address] = peer
        
        # Send version back
        version_msg = self.create_version_message()
        await websocket.send(version_msg.serialize().decode())
        
        # Send addr message with known nodes
        if self.known_nodes:
            addr_msg = self.create_addr_message()
            await websocket.send(addr_msg.serialize().decode())
        # If peer has longer chain, request blocks for sync
        try:
            foreign_height = payload.get('best_height', 0)
            if foreign_height > self.blockchain.get_best_height():
                get_blocks = self.create_get_blocks_message()
                await websocket.send(get_blocks.serialize().decode())
        except Exception:
            pass

    async def handle_get_blocks(self, websocket, msg: NetworkMessage):
        """Handle get blocks request"""
        block_hashes = self.blockchain.get_block_hashes()
        
        # Send inventory of available blocks
        inv_msg = self.create_inventory_message("block", block_hashes)
        await websocket.send(inv_msg.serialize().decode())

    async def handle_get_data(self, websocket, msg: NetworkMessage):
        """Handle get data request"""
        payload = msg.payload
        data_type = payload.get('type')
        item_id = payload.get('id')

        if data_type == "block":
            block = self.blockchain.get_block(item_id) # type: ignore
            if block:
                # send serialized block (pickle -> base64) to keep structure
                data_bytes = block.serialize()
                payload = {'data': base64.b64encode(data_bytes).decode(), 'hash': block.hash}
                block_msg = NetworkMessage(command=MessageType.BLOCK.value, payload=payload, node_address=self.full_address)
                await websocket.send(block_msg.serialize().decode())
        elif data_type == "transaction":
            tx = self.mempool.get(item_id) # type: ignore
            if tx:
                data_bytes = pickle.dumps(tx)
                payload = {'data': base64.b64encode(data_bytes).decode(), 'id': tx.id}
                tx_msg = NetworkMessage(command=MessageType.TRANSACTION.value, payload=payload, node_address=self.full_address)
                await websocket.send(tx_msg.serialize().decode())

    async def handle_inventory(self, websocket, msg: NetworkMessage):
        """Handle inventory message"""
        payload = msg.payload
        data_type = payload.get('type')
        items = payload.get('items', [])

        if data_type == "block":
            for block_hash in items:
                if not self.blockchain.get_block(block_hash):
                    # Request unknown blocks
                    get_data_msg = self.create_get_data_message("block", block_hash)
                    await websocket.send(get_data_msg.serialize().decode())
        elif data_type == "transaction":
            for tx_id in items:
                if tx_id not in self.mempool:
                    # Request unknown transactions
                    get_data_msg = self.create_get_data_message("transaction", tx_id)
                    await websocket.send(get_data_msg.serialize().decode())

    async def handle_block(self, websocket, msg: NetworkMessage):
        """Handle block message"""
        try:
            payload = msg.payload
            # Expect payload['data'] to be base64-encoded serialized block
            if 'data' not in payload:
                self.logger.warning('Block payload missing serialized data')
                return

            block_bytes = base64.b64decode(payload['data'].encode())
            block = Block.deserialize(block_bytes)

            utxo_set = UTXOSet(self.blockchain)

            # Validate block transactions and PoW
            valid = True
            for tx in block.transactions:
                if not self.blockchain.verify_transaction(tx, utxo_set, list(self.mempool.values())):
                    valid = False
                    break

            if valid and self.validate_block(block):
                # Add block to local chain
                self.blockchain._add_block(block)
                self.logger.info(f"Added new block: {block.hash}")

                # Remove transactions from mempool
                for tx in block.transactions:
                    tx_id = tx.id.hex() if isinstance(tx.id, (bytes, bytearray)) else tx.id
                    self.mempool.pop(tx_id, None)

                # Update UTXO set (now reflecting new block)
                try:
                    utxo_set.reindex()
                except Exception as e:
                    self.logger.error(f"UTXO reindex failed: {e}")

                # Broadcast to other peers
                await self.broadcast_block(block, exclude=[msg.node_address])
            else:
                self.logger.warning(f"Invalid block received or bad transactions: {getattr(block,'hash', None)}")

        except Exception as e:
            self.logger.error(f"Error processing block: {e}")

    async def handle_transaction(self, websocket, msg: NetworkMessage):
        """Handle transaction message"""
        try:
            payload = msg.payload
            if 'data' not in payload:
                self.logger.warning('Transaction payload missing serialized data')
                return

            tx_bytes = base64.b64decode(payload['data'].encode())
            tx = pickle.loads(tx_bytes)

            # Ensure tx.id exists (may be bytes or hex)
            tx_id = tx.id.hex() if isinstance(tx.id, (bytes, bytearray)) else tx.id

            utxo_set = UTXOSet(self.blockchain)

            # Validate transaction
            if self.blockchain.verify_transaction(tx, utxo_set, list(self.mempool.values())):
                self.mempool[tx_id] = tx
                self.logger.info(f"Added transaction to mempool: {tx_id}")
                # Broadcast to other peers
                await self.broadcast_transaction(tx, exclude=[msg.node_address])
            else:
                self.logger.warning(f"Invalid transaction: {tx_id}")

        except Exception as e:
            self.logger.error(f"Error processing transaction: {e}")

    async def handle_addr(self, websocket, msg: NetworkMessage):
        """Handle address message"""
        payload = msg.payload
        addresses = payload.get('addresses', [])
        
        for addr in addresses:
            if addr not in self.known_nodes and addr != self.full_address:
                self.known_nodes.add(addr)
                asyncio.create_task(self.connect_to_peer(addr))

    async def handle_ping(self, websocket, msg: NetworkMessage):
        """Handle ping message"""
        pong_msg = NetworkMessage(
            command=MessageType.PONG.value,
            payload={'timestamp': int(time.time())},
            node_address=self.full_address
        )
        await websocket.send(pong_msg.serialize().decode())

    def validate_block(self, block: Block) -> bool:
        """Validate a received block"""
        # Check if previous block exists
        if block.prev_block_hash != "" and not self.blockchain.get_block(block.prev_block_hash):
            return False
        
        # Validate proof of work
        from blockchain import ProofOfWork
        pow_instance = ProofOfWork(block)
        return pow_instance.validate()

    async def connect_to_peer(self, address: str):
        """Connect to a peer"""
        try:
            uri = f"ws://{address}"
            async with websockets.connect(uri) as websocket:
                self.logger.info(f"Connected to peer: {address}")
                
                # Send version message
                version_msg = self.create_version_message()
                await websocket.send(version_msg.serialize().decode())
                
                # Handle messages from this peer
                async for message in websocket:
                    await self.handle_message(websocket, message, address) # type: ignore
                    
        except Exception as e:
            self.logger.error(f"Failed to connect to peer {address}: {e}")

    async def broadcast_block(self, block: Block, exclude: List[str] = None):
        """Broadcast block to all peers"""
        exclude = exclude or []
        block_msg = self.create_block_message(block)
        
        for peer_addr, peer in self.peers.items():
            if peer_addr not in exclude and peer.connected:
                try:
                    uri = f"ws://{peer_addr}"
                    async with websockets.connect(uri, timeout=5) as websocket:
                        await websocket.send(block_msg.serialize().decode())
                except Exception as e:
                    self.logger.error(f"Failed to broadcast block to {peer_addr}: {e}")

    async def broadcast_transaction(self, tx: Transaction, exclude: List[str] = None):
        """Broadcast transaction to all peers"""
        exclude = exclude or []
        tx_msg = self.create_transaction_message(tx)
        
        for peer_addr, peer in self.peers.items():
            if peer_addr not in exclude and peer.connected:
                try:
                    uri = f"ws://{peer_addr}"
                    async with websockets.connect(uri, timeout=5) as websocket:
                        await websocket.send(tx_msg.serialize().decode())
                except Exception as e:
                    self.logger.error(f"Failed to broadcast transaction to {peer_addr}: {e}")

    def create_version_message(self) -> NetworkMessage:
        """Create version message"""
        return NetworkMessage(
            command=MessageType.VERSION.value,
            payload={
                'version': NODE_VERSION,
                'best_height': self.blockchain.get_best_height(),
                'addr_from': self.node_address,
                'port': self.port
            },
            node_address=self.full_address
        )

    def create_get_blocks_message(self) -> NetworkMessage:
        """Create get blocks message"""
        return NetworkMessage(
            command=MessageType.GET_BLOCKS.value,
            payload={
                'addr_from': self.full_address
            },
            node_address=self.full_address
        )

    def create_inventory_message(self, data_type: str, items: List[str]) -> NetworkMessage:
        """Create inventory message"""
        return NetworkMessage(
            command=MessageType.INVENTORY.value,
            payload={
                'type': data_type,
                'items': items
            },
            node_address=self.full_address
        )

    def create_get_data_message(self, data_type: str, item_id: str) -> NetworkMessage:
        """Create get data message"""
        return NetworkMessage(
            command=MessageType.GET_DATA.value,
            payload={
                'type': data_type,
                'id': item_id
            },
            node_address=self.full_address
        )

    def create_block_message(self, block: Block) -> NetworkMessage:
        """Create block message"""
        # send serialized block (pickle -> base64) to preserve structure
        data_bytes = block.serialize()
        payload = {'data': base64.b64encode(data_bytes).decode(), 'hash': block.hash}
        return NetworkMessage(command=MessageType.BLOCK.value, payload=payload, node_address=self.full_address)

    def create_transaction_message(self, tx: Transaction) -> NetworkMessage:
        """Create transaction message"""
        data_bytes = pickle.dumps(tx)
        payload = {'data': base64.b64encode(data_bytes).decode(), 'id': tx.id}
        return NetworkMessage(command=MessageType.TRANSACTION.value, payload=payload, node_address=self.full_address)

    def create_addr_message(self) -> NetworkMessage:
        """Create address message"""
        return NetworkMessage(
            command=MessageType.ADDR.value,
            payload={
                'addresses': list(self.known_nodes)
            },
            node_address=self.full_address
        )

    @property
    def full_address(self) -> str:
        """Get full node address"""
        return f"{self.node_address}:{self.port}"

    async def sync_blockchain(self):
        """Synchronize blockchain with network"""
        if not self.peers:
            self.logger.info("No peers available for sync")
            return

        for peer_addr, peer in self.peers.items():
            if peer.connected:
                try:
                    uri = f"ws://{peer_addr}"
                    async with websockets.connect(uri, timeout=10) as websocket:
                        # Request blocks
                        get_blocks_msg = self.create_get_blocks_message()
                        await websocket.send(get_blocks_msg.serialize().decode())
                        self.logger.info(f"Requested blocks from {peer_addr}")
                        break
                except Exception as e:
                    self.logger.error(f"Failed to sync with {peer_addr}: {e}")

    def add_known_node(self, address: str):
        """Add a known node"""
        if address != self.full_address:
            self.known_nodes.add(address)

    def get_mempool_transactions(self) -> List[Transaction]:
        """Get all transactions from mempool"""
        return list(self.mempool.values())

    def remove_transaction_from_mempool(self, tx_id: str):
        """Remove transaction from mempool"""
        self.mempool.pop(tx_id, None)

# CLI extension for networking
class NetworkCLI:
    """Extended CLI with networking capabilities"""
    
    def __init__(self):
        from blockchain import Blockchain
        self.blockchain = Blockchain()
        self.node = None

    async def start_node(self, port: int = DEFAULT_PORT):
        """Start network node"""
        self.node = NetworkNode(self.blockchain, port)
        await self.node.start_server()
        print(f"Node started on port {port}")

    async def stop_node(self):
        """Stop network node"""
        if self.node:
            await self.node.stop_server()
            print("Node stopped")

    def connect_to_network(self, peer_address: str):
        """Connect to network through a peer"""
        if self.node:
            self.node.add_known_node(peer_address)
            asyncio.create_task(self.node.connect_to_peer(peer_address))
            print(f"Connecting to network via {peer_address}")
        else:
            print("Node not started. Use 'startnode' command first.")

    def show_peers(self):
        """Show connected peers"""
        if self.node:
            if self.node.peers:
                print("Connected peers:")
                for addr, peer in self.node.peers.items():
                    status = "Connected" if peer.connected else "Disconnected"
                    print(f"  {addr} - {status} (version: {peer.version})")
            else:
                print("No connected peers")
        else:
            print("Node not started")

    def show_mempool(self):
        """Show mempool transactions"""
        if self.node:
            txs = self.node.get_mempool_transactions()
            if txs:
                print(f"Mempool contains {len(txs)} transactions:")
                for tx in txs:
                    print(f"  {tx.id}")
            else:
                print("Mempool is empty")
        else:
            print("Node not started")

if __name__ == "__main__":
    import argparse
    
    async def main():
        parser = argparse.ArgumentParser(description='Blockchain Network CLI')
        parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Node port')
        parser.add_argument('--connect', help='Connect to peer (address:port)')
        
        args = parser.parse_args()
        
        cli = NetworkCLI()
        
        # Start node
        await cli.start_node(args.port)
        
        # Connect to network if specified
        if args.connect:
            cli.connect_to_network(args.connect)
        
        # Keep running
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await cli.stop_node()
    