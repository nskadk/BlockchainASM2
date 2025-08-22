#!/usr/bin/env python3
"""
Configuration Module - Global constants and settings
==================================================

This module contains all blockchain configuration constants used throughout the system.
Centralizing configuration makes it easy to adjust blockchain parameters for testing
or different network requirements.

Constants defined here:
- Mining difficulty and adjustment parameters
- Block timing and consensus rules  
- Transaction fees and rewards
- Address encoding version
- Network protocol settings
"""

# Mining Configuration
# ===================
DIFFICULTY = 4                    # Default mining difficulty (number of leading zeros required)
TARGET_BLOCK_TIME = 30           # Target time between blocks in seconds
ADJUST_INTERVAL = 10             # Adjust difficulty every N blocks  
MIN_DIFFICULTY = 1               # Minimum allowed difficulty
MAX_DIFFICULTY = 24              # Maximum allowed difficulty

# Transaction Configuration  
# ========================
SUBSIDY = 10                     # Mining reward for finding a block
MINING_REWARD = 10               # Mining reward for pending transactions
VERSION = 1                      # Address version byte for encoding

# Genesis Block Configuration
# ==========================
GENESIS_COINBASE_DATA = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"

# Network Configuration
# ===================
DEFAULT_PORT = 3000              # Default P2P network port
PROTOCOL_VERSION = 1             # Network protocol version
NODE_TIMEOUT = 30                # Node connection timeout in seconds