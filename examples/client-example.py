#!/usr/bin/env python3
"""
Python client example for Rust Verusd RPC Server

This script demonstrates how to interact with the Verus RPC server
using Python. It handles authentication, error handling, and provides
examples for common RPC methods.

Requirements:
    pip install requests
"""

import requests
import json
from typing import Optional, Dict, Any


class VerusRPCClient:
    """Simple client for Verus RPC server."""

    def __init__(
        self,
        url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        timeout: int = 30
    ):
        """
        Initialize the RPC client.

        Args:
            url: The RPC server URL
            api_key: Optional API key for authentication
            timeout: Request timeout in seconds
        """
        self.url = url
        self.api_key = api_key
        self.timeout = timeout
        self.session = requests.Session()

        # Set up authentication header if API key is provided
        if api_key:
            self.session.headers.update({
                "X-API-Key": api_key
            })

        # Always set Content-Type
        self.session.headers.update({
            "Content-Type": "application/json"
        })

    def call(self, method: str, params: list = None) -> Dict[str, Any]:
        """
        Call an RPC method.

        Args:
            method: The RPC method name
            params: List of parameters (default: empty list)

        Returns:
            The RPC response result

        Raises:
            requests.exceptions.RequestException: On network errors
            ValueError: On RPC errors
        """
        if params is None:
            params = []

        payload = {
            "method": method,
            "params": params
        }

        try:
            response = self.session.post(
                self.url,
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()

            # Check for RPC errors
            if "error" in data and data["error"] is not None:
                error = data["error"]
                raise ValueError(
                    f"RPC error {error.get('code')}: {error.get('message')}"
                )

            return data.get("result")

        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Request failed: {e}")

    def health_check(self) -> Dict[str, str]:
        """Check server health status."""
        response = self.session.get(f"{self.url}/health", timeout=10)
        response.raise_for_status()
        return response.json()

    def readiness_check(self) -> Dict[str, str]:
        """Check server readiness status."""
        response = self.session.get(f"{self.url}/ready", timeout=10)
        response.raise_for_status()
        return response.json()

    # Convenience methods for common RPC calls

    def get_info(self) -> Dict[str, Any]:
        """Get general information about the Verus daemon."""
        return self.call("getinfo")

    def get_block_count(self) -> int:
        """Get the current block count."""
        return self.call("getblockcount")

    def get_block_hash(self, height: int) -> str:
        """Get the block hash at a specific height."""
        return self.call("getblockhash", [height])

    def get_block(self, block_hash: str, verbose: int = 1) -> Dict[str, Any]:
        """Get block data."""
        return self.call("getblock", [block_hash, verbose])

    def get_transaction(self, txid: str, verbose: int = 1) -> Dict[str, Any]:
        """Get transaction data."""
        return self.call("getrawtransaction", [txid, verbose])


def main():
    """Example usage."""
    # Initialize client (update with your API key if needed)
    client = VerusRPCClient(
        url="http://localhost:8080",
        api_key="your-secret-api-key-here"  # Remove or update this
    )

    try:
        # Check server health
        print("Checking server health...")
        health = client.health_check()
        print(f"Health: {json.dumps(health, indent=2)}")
        print()

        # Get blockchain info
        print("Getting blockchain info...")
        info = client.get_info()
        print(f"Version: {info.get('version')}")
        print(f"Blocks: {info.get('blocks')}")
        print(f"Connections: {info.get('connections')}")
        print()

        # Get current block count
        print("Getting block count...")
        block_count = client.get_block_count()
        print(f"Current block count: {block_count}")
        print()

        # Get latest block hash
        print("Getting latest block hash...")
        latest_hash = client.get_block_hash(block_count)
        print(f"Latest block hash: {latest_hash}")
        print()

        # Get block details
        print("Getting block details...")
        block = client.get_block(latest_hash)
        print(f"Block height: {block.get('height')}")
        print(f"Block time: {block.get('time')}")
        print(f"Transactions: {len(block.get('tx', []))}")
        print()

    except Exception as e:
        print(f"Error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
