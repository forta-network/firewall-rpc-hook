# Firewall RPC Hook

A Go-based RPC hook service that intercepts Ethereum transactions, performs trace analysis, and screens them through the Forta Firewall API before forwarding to the sequencer.

## Overview

This service acts as a middleware between Ethereum clients and the sequencer, providing an additional layer of security by:

1. Intercepting `eth_sendRawTransaction` RPC calls
2. Performing transaction trace analysis
3. Screening transactions through the Forta Firewall API
4. Forwarding approved transactions to the sequencer

## Configuration

The service is configured through environment variables or a `.env` file. The following configuration options are available:

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `PORT` | Port to listen on | No | `8080` |
| `SEQUENCER_RPC_URL` | URL of the sequencer RPC endpoint | Yes | - |
| `TRACE_RPC_URL` | URL of the RPC endpoint for trace calls | No | Uses `SEQUENCER_RPC_URL` |
| `FIREWALL_API_URL` | URL of the Forta Firewall API | Yes | - |
| `TIMEOUT` | Request timeout duration | No | `30s` |
| `LOG_LEVEL` | Logging level (debug, info, warn, error) | No | `info` |

## Usage

1. Create a `.env` file with your configuration:
```env
PORT=8080
SEQUENCER_RPC_URL=https://your-sequencer-url
TRACE_RPC_URL=https://your-trace-url
FIREWALL_API_URL=https://your-fortafirewall-url
TIMEOUT=30s
LOG_LEVEL=info
```

2. Build and run the service:
```bash
go run main.go
```

3. The service will start listening on the configured port and begin intercepting RPC calls.

## How It Works

1. When an `eth_sendRawTransaction` RPC call is received:
   - The transaction is decoded and validated
   - A trace analysis is performed using `debug_traceCall`
   - The transaction and trace data are sent to the Forta Firewall API for screening

2. If the Firewall API approves the transaction:
   - The original RPC call is forwarded to the sequencer
   - The sequencer's response is returned to the client

3. If the Firewall API rejects the transaction:
   - The transaction is blocked
   - A 403 Forbidden response is returned to the client

4. For all other RPC methods:
   - The request is forwarded directly to the sequencer
   - The sequencer's response is returned to the client
