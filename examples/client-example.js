#!/usr/bin/env node
/**
 * JavaScript/Node.js client example for Rust Verusd RPC Server
 *
 * This script demonstrates how to interact with the Verus RPC server
 * using Node.js. It handles authentication, error handling, and provides
 * examples for common RPC methods.
 *
 * Requirements:
 *   npm install node-fetch
 *
 * For Node.js < 18, use:
 *   npm install node-fetch@2
 */

const fetch = require('node-fetch');

/**
 * Simple client for Verus RPC server
 */
class VerusRPCClient {
    /**
     * Initialize the RPC client
     * @param {string} url - The RPC server URL
     * @param {string|null} apiKey - Optional API key for authentication
     * @param {number} timeout - Request timeout in milliseconds
     */
    constructor(url = 'http://localhost:8080', apiKey = null, timeout = 30000) {
        this.url = url;
        this.apiKey = apiKey;
        this.timeout = timeout;
    }

    /**
     * Call an RPC method
     * @param {string} method - The RPC method name
     * @param {Array} params - List of parameters
     * @returns {Promise<any>} The RPC response result
     */
    async call(method, params = []) {
        const headers = {
            'Content-Type': 'application/json',
        };

        // Add API key if provided
        if (this.apiKey) {
            headers['X-API-Key'] = this.apiKey;
        }

        const payload = {
            method,
            params,
        };

        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.timeout);

            const response = await fetch(this.url, {
                method: 'POST',
                headers,
                body: JSON.stringify(payload),
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();

            // Check for RPC errors
            if (data.error) {
                throw new Error(
                    `RPC error ${data.error.code}: ${data.error.message}`
                );
            }

            return data.result;
        } catch (error) {
            if (error.name === 'AbortError') {
                throw new Error('Request timeout');
            }
            throw error;
        }
    }

    /**
     * Check server health status
     * @returns {Promise<Object>} Health status
     */
    async healthCheck() {
        const response = await fetch(`${this.url}/health`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    }

    /**
     * Check server readiness status
     * @returns {Promise<Object>} Readiness status
     */
    async readinessCheck() {
        const response = await fetch(`${this.url}/ready`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    }

    // Convenience methods for common RPC calls

    /**
     * Get general information about the Verus daemon
     * @returns {Promise<Object>}
     */
    async getInfo() {
        return this.call('getinfo');
    }

    /**
     * Get the current block count
     * @returns {Promise<number>}
     */
    async getBlockCount() {
        return this.call('getblockcount');
    }

    /**
     * Get the block hash at a specific height
     * @param {number} height - Block height
     * @returns {Promise<string>}
     */
    async getBlockHash(height) {
        return this.call('getblockhash', [height]);
    }

    /**
     * Get block data
     * @param {string} blockHash - Block hash
     * @param {number} verbose - Verbosity level (0, 1, or 2)
     * @returns {Promise<Object>}
     */
    async getBlock(blockHash, verbose = 1) {
        return this.call('getblock', [blockHash, verbose]);
    }

    /**
     * Get transaction data
     * @param {string} txid - Transaction ID
     * @param {number} verbose - Verbosity level (0 or 1)
     * @returns {Promise<Object|string>}
     */
    async getTransaction(txid, verbose = 1) {
        return this.call('getrawtransaction', [txid, verbose]);
    }
}

/**
 * Example usage
 */
async function main() {
    // Initialize client (update with your API key if needed)
    const client = new VerusRPCClient(
        'http://localhost:8080',
        'your-secret-api-key-here'  // Remove or update this
    );

    try {
        // Check server health
        console.log('Checking server health...');
        const health = await client.healthCheck();
        console.log('Health:', JSON.stringify(health, null, 2));
        console.log();

        // Get blockchain info
        console.log('Getting blockchain info...');
        const info = await client.getInfo();
        console.log(`Version: ${info.version}`);
        console.log(`Blocks: ${info.blocks}`);
        console.log(`Connections: ${info.connections}`);
        console.log();

        // Get current block count
        console.log('Getting block count...');
        const blockCount = await client.getBlockCount();
        console.log(`Current block count: ${blockCount}`);
        console.log();

        // Get latest block hash
        console.log('Getting latest block hash...');
        const latestHash = await client.getBlockHash(blockCount);
        console.log(`Latest block hash: ${latestHash}`);
        console.log();

        // Get block details
        console.log('Getting block details...');
        const block = await client.getBlock(latestHash);
        console.log(`Block height: ${block.height}`);
        console.log(`Block time: ${block.time}`);
        console.log(`Transactions: ${block.tx ? block.tx.length : 0}`);
        console.log();

    } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exit(1);
    }
}

// Run if called directly
if (require.main === module) {
    main().catch(console.error);
}

module.exports = { VerusRPCClient };
