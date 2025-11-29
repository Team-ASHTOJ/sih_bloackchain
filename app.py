import os
import json
import time
import hashlib
import sqlite3
from dataclasses import dataclass, asdict

from flask import Flask, request, jsonify
import requests

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


############################################################
# CONFIG
############################################################

NODES = {u.strip().rstrip("/") for u in os.getenv("NODES", "").split(",") if u.strip()}
MY_NODE_URL = os.getenv("NODE_URL", "").rstrip("/")

FERNET_KEY = os.getenv("BLOCK_ENCRYPTION_KEY")
if not FERNET_KEY:
    raise RuntimeError("BLOCK_ENCRYPTION_KEY env var missing")

fernet = Fernet(FERNET_KEY.encode())

os.makedirs("db", exist_ok=True)
app = Flask(__name__)


############################################################
# CRYPTO HELPERS
############################################################

def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def encrypt_data(data: dict) -> str:
    return fernet.encrypt(json.dumps(data).encode()).decode()


def decrypt_data(enc: str) -> dict:
    return json.loads(fernet.decrypt(enc.encode()).decode())


PRIVATE_KEY = Ed25519PrivateKey.generate()
PUBLIC_KEY = PRIVATE_KEY.public_key()


def public_key_hex() -> str:
    return PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def sign_payload(payload: str) -> str:
    return PRIVATE_KEY.sign(payload.encode()).hex()


def verify_signature(pubkey_hex, payload, sig_hex) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        pub.verify(bytes.fromhex(sig_hex), payload.encode())
        return True
    except:
        return False


############################################################
# BLOCK STRUCT
############################################################

@dataclass
class Block:
    index: int
    timestamp: float
    data_encrypted: str
    previous_hash: str
    hash: str
    signature: str
    public_key: str

    def payload(self) -> str:
        """
        Canonical JSON for hashing + signing.
        """
        obj = {
            "index": self.index,
            "timestamp": self.timestamp,
            "data_encrypted": self.data_encrypted,
            "previous_hash": self.previous_hash,
            "public_key": self.public_key,
        }
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))


############################################################
# DB FUNCTIONS — ALWAYS FRESH
############################################################

def get_db():
    return sqlite3.connect("db/blockchain.db", check_same_thread=False)


def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS blocks (
            idx INTEGER PRIMARY KEY,
            ts REAL,
            data_encrypted TEXT,
            previous_hash TEXT,
            hash TEXT,
            signature TEXT,
            public_key TEXT
        )
    """)
    db.commit()

    # Create deterministic genesis
    row = db.execute("SELECT idx FROM blocks WHERE idx=0").fetchone()
    if row is None:
        genesis = Block(
            index=0,
            timestamp=0.0,
            data_encrypted="GENESIS_DATA_V1",
            previous_hash="0",
            public_key="GENESIS_PUBLIC_KEY_V1",
            signature="GENESIS_SIGNATURE_V1",
            hash=""
        )
        genesis.hash = sha256(genesis.payload())
        db.execute("""
            INSERT INTO blocks (idx, ts, data_encrypted, previous_hash, hash, signature, public_key)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (0, 0.0, genesis.data_encrypted, "0", genesis.hash,
              genesis.signature, genesis.public_key))
        db.commit()


def load_chain():
    """
    Always load the chain fresh from database.
    """
    db = get_db()
    rows = db.execute("SELECT * FROM blocks ORDER BY idx").fetchall()
    chain = []
    for r in rows:
        chain.append(Block(
            index=r[0],
            timestamp=r[1],
            data_encrypted=r[2],
            previous_hash=r[3],
            hash=r[4],
            signature=r[5],
            public_key=r[6],
        ))
    return chain


def save_block(b: Block):
    db = get_db()
    db.execute("""
        INSERT INTO blocks (idx, ts, data_encrypted, previous_hash, hash, signature, public_key)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (b.index, b.timestamp, b.data_encrypted, b.previous_hash,
          b.hash, b.signature, b.public_key))
    db.commit()


############################################################
# VALIDATION — DB-DRIVEN
############################################################

def validate_chain(chain):
    """
    Always validate using current DB content.
    """
    for i in range(1, len(chain)):
        c = chain[i]
        p = chain[i - 1]

        # linkage
        if c.previous_hash != p.hash:
            return False

        # recompute hash
        if c.hash != sha256(c.payload()):
            return False

        # verify signature
        if not verify_signature(c.public_key, c.payload(), c.signature):
            return False

    return True


############################################################
# ROUTES
############################################################

@app.route("/add_block", methods=["POST"])
def add_block():
    data = request.get_json()
    chain = load_chain()
    prev = chain[-1]

    enc = encrypt_data(data)

    new_block = Block(
        index=len(chain),
        timestamp=time.time(),
        data_encrypted=enc,
        previous_hash=prev.hash,
        public_key=public_key_hex(),
        signature="",
        hash=""
    )

    payload = new_block.payload()
    new_block.hash = sha256(payload)
    new_block.signature = sign_payload(payload)

    save_block(new_block)

    # broadcast
    for node in NODES:
        if node != MY_NODE_URL:
            try:
                requests.post(f"{node}/receive_block", json=asdict(new_block), timeout=2)
            except:
                pass

    return jsonify({"message": "Block added", "block": asdict(new_block)})


@app.route("/receive_block", methods=["POST"])
def receive_block():
    d = request.get_json()
    chain = load_chain()
    prev = chain[-1]

    block = Block(
        index=d["index"],
        timestamp=d["timestamp"],
        data_encrypted=d["data_encrypted"],
        previous_hash=d["previous_hash"],
        public_key=d["public_key"],
        hash=d["hash"],
        signature=d["signature"]
    )

    # index check
    if block.index != len(chain):
        return jsonify({"message": "Rejected"}), 400

    # previous hash check
    if block.previous_hash != prev.hash:
        return jsonify({"message": "Rejected"}), 400

    # hash recomputation check
    if block.hash != sha256(block.payload()):
        return jsonify({"message": "Rejected"}), 400

    # signature check
    if not verify_signature(block.public_key, block.payload(), block.signature):
        return jsonify({"message": "Rejected"}), 400

    save_block(block)
    return jsonify({"message": "Accepted"}), 200


@app.route("/chain", methods=["GET"])
def chain_api():
    chain = load_chain()
    return jsonify([asdict(b) for b in chain])


@app.route("/validate_local", methods=["GET"])
def validate_local():
    chain = load_chain()
    return jsonify({"valid": validate_chain(chain)})


@app.route("/validate", methods=["GET"])
def validate_network():
    chain = load_chain()
    self_valid = validate_chain(chain)

    results = {}
    tampered = []

    for node in NODES:
        try:
            res = requests.get(f"{node}/validate_local", timeout=2).json()
            ok = res.get("valid", False)
            results[node] = ok
            if not ok:
                tampered.append(node)
        except:
            results[node] = False
            tampered.append(node)

    network_valid = self_valid and all(results.values())

    return jsonify({
        "self": self_valid,
        "nodes": results,
        "network_valid": network_valid,
        "tampered_nodes": tampered
    })


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
