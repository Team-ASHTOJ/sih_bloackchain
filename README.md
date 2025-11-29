# Multi-node encrypted blockchain

## Overview
- 4 Flask nodes with encrypted block data and Ed25519 signatures.
- Nodes: node1..node4, exposed on localhost ports 5001–5004.
- Each node stores its chain in `./data/nodeX:/app/db`.

## Prerequisites
- Docker and Docker Compose
- `jq` (optional) to pretty-print JSON

## Setup
- Ensure data directories exist (Compose will create on first run if needed).

## Start
- Build and start all services:
```
docker compose up --build
```

## Usage
1) Add a block via node1 (broadcasts to others):
```
curl -X POST http://localhost:5001/add_block \
  -H "Content-Type: application/json" \
  -d '{"sender":"Alice","receiver":"Bob","amount":50}'
```

2) Inspect chains on other nodes:
```
curl http://localhost:5002/chain | jq
curl http://localhost:5003/chain | jq
curl http://localhost:5004/chain | jq
```

3) Validate network consistency from node1:
```
curl http://localhost:5001/validate | jq
```

## Tamper demo (node3)
- Purpose: Show detection when block data is corrupted.
```
docker exec -it node3 sh
sqlite3 db/blockchain.db
UPDATE blocks SET data_encrypted = 'HACKED' WHERE idx = 1;
.quit
exit
```
- Then:
```
curl http://localhost:5001/validate | jq
```
- Expect `network_valid: false` and `tampered_nodes` to include node3.

## Reset (clean volumes) and rebuild
- Stop and remove containers + volumes:
```
docker compose down -v
```
- Recreate or clean local data dirs:
```
sudo rm -rf data/node1 data/node2 data/node3 data/node4
sudo mkdir -p data/node1 data/node2 data/node3 data/node4
```
- Start fresh:
```
docker compose up --build
```

## API
- POST `/add_block` — Add local block and broadcast.
- POST `/receive_block` — Receive and validate incoming block.
- GET `/chain` — Return current chain (encrypted payloads).
- GET `/validate_local` — Validate local chain only.
- GET `/validate` — Validate local chain and aggregate network validity.

## Notes
- Encryption: `data_encrypted` uses Fernet; requires shared `BLOCK_ENCRYPTION_KEY`.
- Signatures: Ed25519 over canonical payload (index, timestamp, encrypted data, previous_hash, public_key).
- Genesis: Deterministic block at `idx=0` created on first run per node.