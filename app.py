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

NODES = {
    u.strip().rstrip("/")
    for u in os.getenv("NODES", "").split(",")
    if u.strip()
}

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
    sig = PRIVATE_KEY.sign(payload.encode())
    return sig.hex()


def verify_signature(pubkey_hex: str, payload: str, sig_hex: str) -> bool:
    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        pk.verify(bytes.fromhex(sig_hex), payload.encode())
        return True
    except Exception:
        return False


############################################################
# BLOCK + CHAIN
############################################################

@dataclass
class Block:
    index: int
    timestamp: float
    data_encrypted: str
    previous_hash: str
    hash: str = ""
    signature: str = ""
    public_key: str = ""

    def as_payload(self) -> str:
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

    def compute_hash(self) -> str:
        return sha256(self.as_payload())


class Blockchain:
    def __init__(self):
        self.db = sqlite3.connect("db/blockchain.db", check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.init_db()
        self.chain = []
        self.load_chain()

    def init_db(self):
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS blocks (
                idx INTEGER PRIMARY KEY,
                ts REAL,
                data_encrypted TEXT,
                previous_hash TEXT,
                hash TEXT,
                signature TEXT,
                public_key TEXT
            )
            """
        )
        self.db.commit()

    def load_chain(self):
        rows = self.db.execute("SELECT * FROM blocks ORDER BY idx").fetchall()
        if rows:
            for r in rows:
                self.chain.append(
                    Block(
                        index=r["idx"],
                        timestamp=r["ts"],
                        data_encrypted=r["data_encrypted"],
                        previous_hash=r["previous_hash"],
                        hash=r["hash"],
                        signature=r["signature"],
                        public_key=r["public_key"],
                    )
                )
        else:
            self.create_genesis()

    def save_block(self, block: Block):
        self.db.execute(
            """
            INSERT INTO blocks (idx, ts, data_encrypted, previous_hash, hash, signature, public_key)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                block.index,
                block.timestamp,
                block.data_encrypted,
                block.previous_hash,
                block.hash,
                block.signature,
                block.public_key,
            ),
        )
        self.db.commit()

    def create_genesis(self):
        block = Block(
            index=0,
            timestamp=0.0,
            data_encrypted="GENESIS_DATA_V1",
            previous_hash="0",
            public_key="GENESIS_PUBLIC_KEY_V1",
        )
        block.hash = block.compute_hash()
        block.signature = "GENESIS_SIGNATURE_V1"

        self.chain.append(block)
        self.save_block(block)

    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, data: dict) -> Block:
        enc = encrypt_data(data)
        block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            data_encrypted=enc,
            previous_hash=self.last_block.hash,
            public_key=public_key_hex(),
        )

        payload = block.as_payload()
        block.hash = block.compute_hash()
        block.signature = sign_payload(payload)

        self.chain.append(block)
        self.save_block(block)
        return block

    def add_block_from_network(self, d: dict) -> bool:
        block = Block(
            index=d["index"],
            timestamp=d["timestamp"],
            data_encrypted=d["data_encrypted"],
            previous_hash=d["previous_hash"],
            hash=d["hash"],
            signature=d["signature"],
            public_key=d["public_key"],
        )

        if block.index != len(self.chain):
            return False
        if block.previous_hash != self.last_block.hash:
            return False

        # RECOMPUTE HASH
        if block.hash != block.compute_hash():
            return False

        # REVERIFY SIGNATURE
        if not verify_signature(block.public_key, block.as_payload(), block.signature):
            return False

        self.chain.append(block)
        self.save_block(block)
        return True

    def is_valid(self) -> bool:
        """
        FULL validation:
        - recompute hash
        - recompute signature
        - check chain linkage
        """
        for i in range(1, len(self.chain)):
            c = self.chain[i]
            p = self.chain[i - 1]

            # Check previous hash
            if c.previous_hash != p.hash:
                return False

            # Recompute hash
            if c.hash != c.compute_hash():
                return False

            # Recompute signature
            if not verify_signature(c.public_key, c.as_payload(), c.signature):
                return False

        return True

    def to_list(self):
        return [asdict(b) for b in self.chain]


blockchain = Blockchain()


############################################################
# API ROUTES
############################################################

@app.route("/add_block", methods=["POST"])
def add_block_api():
    data = request.get_json(force=True)
    b = blockchain.add_block(data)
    block_dict = asdict(b)

    # broadcast
    for node in NODES:
        if node == MY_NODE_URL:
            continue
        try:
            requests.post(f"{node}/receive_block", json=block_dict, timeout=2)
        except:
            pass

    return jsonify({"message": "Block added", "block": block_dict})


@app.route("/receive_block", methods=["POST"])
def receive_block_api():
    d = request.get_json(force=True)
    ok = blockchain.add_block_from_network(d)
    if ok:
        return jsonify({"message": "Accepted"}), 200
    return jsonify({"message": "Rejected"}), 400


@app.route("/chain", methods=["GET"])
def chain_api():
    return jsonify(blockchain.to_list())


# LOCAL VALIDATION ONLY
@app.route("/validate_local", methods=["GET"])
def validate_local():
    return jsonify({"valid": blockchain.is_valid()})


# FULL NETWORK VALIDATION
@app.route("/validate", methods=["GET"])
def validate_global():
    self_valid = blockchain.is_valid()
    results = {}
    tampered = []

    for node in NODES:
        try:
            res = requests.get(f"{node}/validate_local", timeout=2).json()
            valid = res.get("valid", False)
            results[node] = valid
            if not valid:
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
    app.run(host="0.0.0.0", port=5000)
