const crypto = require('crypto');

/**
 * Computes RFC 6962 leaf hash: SHA-256(0x00 || payload)
 */
function hashLeaf(payload) {
  const buf = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : Buffer.from(payload);
  const prefix = Buffer.from([0x00]);
  return crypto.createHash('sha256').update(Buffer.concat([prefix, buf])).digest('hex');
}

/**
 * Computes RFC 6962 interior node hash: SHA-256(0x01 || left || right)
 */
function hashInterior(leftBuf, rightBuf) {
  const prefix = Buffer.from([0x01]);
  return crypto.createHash('sha256').update(Buffer.concat([prefix, leftBuf, rightBuf])).digest();
}

/**
 * Reconstructs root hash from leaf hash and RFC 6962 audit path.
 */
function reconstructRoot(leafIndex, leafHashHex, auditPathHexList) {
  let current = Buffer.from(leafHashHex, 'hex');
  let idx = leafIndex;

  for (const siblingHex of auditPathHexList) {
    const sibling = Buffer.from(siblingHex, 'hex');
    if (idx % 2 === 1) {
      current = hashInterior(sibling, current);
    } else {
      current = hashInterior(current, sibling);
    }
    idx = Math.floor(idx / 2);
  }

  return current.toString('hex');
}

/**
 * Serializes STH according to MerkleGate canonical format:
 * [8 bytes BigEndian TreeSize][32 bytes RootHash][8 bytes BigEndian Timestamp][8 bytes BigEndian Sequence]
 */
function canonicalSTHDigest(treeSize, rootHashHex, timestamp, sequence) {
  const rootBuf = Buffer.from(rootHashHex, 'hex');
  const buf = Buffer.alloc(8 + rootBuf.length + 8 + 8);
  buf.writeBigUInt64BE(BigInt(treeSize), 0);
  rootBuf.copy(buf, 8);
  buf.writeBigInt64BE(BigInt(timestamp), 8 + rootBuf.length);
  buf.writeBigUInt64BE(BigInt(sequence), 8 + rootBuf.length + 8);
  return buf;
}

/**
 * Verifies Ed25519 STH signature using Node.js crypto module.
 */
function verifySTH(sth, expectedPubKeyHex) {
  if (!sth || !sth.signature || !sth.public_key || !sth.root_hash) {
    return { valid: false, error: 'Malformed STH structure' };
  }

  if (expectedPubKeyHex && sth.public_key.toLowerCase() !== expectedPubKeyHex.toLowerCase()) {
    return { valid: false, error: `Public key mismatch: got ${sth.public_key}, expected ${expectedPubKeyHex}` };
  }

  try {
    const digest = canonicalSTHDigest(sth.tree_size, sth.root_hash, sth.timestamp, sth.sequence);
    const rawPub = Buffer.from(sth.public_key, 'hex');
    const sig = Buffer.from(sth.signature, 'hex');

    // Wrap raw 32-byte Ed25519 public key in ASN.1 SPKI DER header
    const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
    const spkiKey = Buffer.concat([spkiPrefix, rawPub]);

    const keyObj = crypto.createPublicKey({
      key: spkiKey,
      format: 'der',
      type: 'spki'
    });

    const isSigValid = crypto.verify(null, digest, keyObj, sig);
    if (!isSigValid) {
      return { valid: false, error: 'Ed25519 signature verification failed' };
    }
    return { valid: true };
  } catch (err) {
    return { valid: false, error: `STH verification error: ${err.message}` };
  }
}

/**
 * Evaluates full client-side compliance receipt proof.
 */
function verifyReceipt(receipt, expectedPubKeyHex) {
  const errors = [];

  if (!receipt) {
    return { valid: false, errors: ['Receipt is null or undefined'] };
  }

  // 1. Verify Leaf Hash
  const computedLeafHash = hashLeaf(receipt.raw_payload);
  if (computedLeafHash.toLowerCase() !== receipt.leaf_hash.toLowerCase()) {
    errors.push(`Leaf hash mismatch: computed ${computedLeafHash}, receipt stated ${receipt.leaf_hash}`);
  }

  // 2. Verify RFC 6962 Inclusion Proof
  const targetRoot = receipt.historical_root || (receipt.signed_tree_head ? receipt.signed_tree_head.root_hash : null);
  if (!receipt.inclusion_proof || !targetRoot) {
    errors.push('Missing inclusion proof or target root');
  } else {
    const reconstructedRoot = reconstructRoot(
      receipt.leaf_index,
      computedLeafHash,
      receipt.inclusion_proof.audit_path || []
    );
    if (reconstructedRoot.toLowerCase() !== targetRoot.toLowerCase()) {
      errors.push(`Inclusion proof root mismatch: reconstructed ${reconstructedRoot}, target ${targetRoot}`);
    }
  }

  // 3. Verify STH
  if (!receipt.signed_tree_head) {
    errors.push('Missing Signed Tree Head (STH)');
  } else {
    const sthRes = verifySTH(receipt.signed_tree_head, expectedPubKeyHex);
    if (!sthRes.valid) {
      errors.push(`STH validation failed: ${sthRes.error}`);
    }

    // If tree sizes are equal (M == N) and historical_root is provided, it must match the STH root
    if (
      receipt.historical_root &&
      receipt.inclusion_proof &&
      receipt.inclusion_proof.tree_size === receipt.signed_tree_head.tree_size
    ) {
      if (receipt.historical_root.toLowerCase() !== receipt.signed_tree_head.root_hash.toLowerCase()) {
        errors.push(`Historical root does not match STH root for identical tree size ${receipt.signed_tree_head.tree_size}`);
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    leafHash: computedLeafHash,
    treeSize: receipt.signed_tree_head ? receipt.signed_tree_head.tree_size : null,
    sthSequence: receipt.signed_tree_head ? receipt.signed_tree_head.sequence : null
  };
}

module.exports = {
  hashLeaf,
  hashInterior,
  reconstructRoot,
  canonicalSTHDigest,
  verifySTH,
  verifyReceipt
};
