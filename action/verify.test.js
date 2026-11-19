const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const {
  hashLeaf,
  hashInterior,
  reconstructRoot,
  canonicalSTHDigest,
  verifySTH,
  verifyReceipt
} = require('./verify');

describe('Cryptographic Verification Engine (Node.js Action)', () => {
  test('hashLeaf matches RFC 6962 0x00 domain separator', () => {
    const payload = 'git_commit:123456';
    const expected = crypto.createHash('sha256')
      .update(Buffer.concat([Buffer.from([0x00]), Buffer.from(payload, 'utf8')]))
      .digest('hex');
    assert.equal(hashLeaf(payload), expected);
  });

  test('hashInterior matches RFC 6962 0x01 domain separator', () => {
    const left = Buffer.from('a'.repeat(32), 'hex');
    const right = Buffer.from('b'.repeat(32), 'hex');
    const expected = crypto.createHash('sha256')
      .update(Buffer.concat([Buffer.from([0x01]), left, right]))
      .digest();
    assert.deepEqual(hashInterior(left, right), expected);
  });

  test('Full Receipt Verification with Ed25519 Signed Tree Head', () => {
    // 1. Generate Ed25519 Keypair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

    // Export raw 32-byte public key
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const rawPubHex = spkiDer.subarray(spkiDer.length - 32).toString('hex');

    // 2. Construct 2 leaves
    const payload0 = '{"event_type":"git_commit","commit_sha":"abc1234"}';
    const payload1 = '{"event_type":"pr_approval","commit_sha":"abc1234","actor":"lead"}';

    const leaf0Hash = hashLeaf(payload0);
    const leaf1Hash = hashLeaf(payload1);

    const rootBuf = hashInterior(Buffer.from(leaf0Hash, 'hex'), Buffer.from(leaf1Hash, 'hex'));
    const rootHex = rootBuf.toString('hex');

    // 3. Create STH
    const treeSize = 2;
    const timestamp = Math.floor(Date.now() / 1000);
    const sequence = 1n;
    const digest = canonicalSTHDigest(treeSize, rootHex, timestamp, sequence);
    const sig = crypto.sign(null, digest, privateKey);
    const sigHex = sig.toString('hex');

    const sth = {
      tree_size: treeSize,
      root_hash: rootHex,
      timestamp,
      sequence: Number(sequence),
      signature: sigHex,
      public_key: rawPubHex
    };

    // 4. Verify STH standalone
    const sthCheck = verifySTH(sth, rawPubHex);
    assert.equal(sthCheck.valid, true);

    // 5. Build Receipt for leaf 0
    const receipt0 = {
      leaf_index: 0,
      raw_payload: payload0,
      leaf_hash: leaf0Hash,
      historical_root: rootHex,
      inclusion_proof: {
        leaf_index: 0,
        tree_size: 2,
        audit_path: [leaf1Hash]
      },
      signed_tree_head: sth
    };

    const res = verifyReceipt(receipt0, rawPubHex);
    assert.equal(res.valid, true, `Verification errors: ${res.errors}`);
    assert.equal(res.leafHash, leaf0Hash);

    // 6. Test Single-Bit Payload Tamper
    const tamperedReceipt = {
      ...receipt0,
      raw_payload: payload0.replace('abc1234', 'evil999')
    };
    const tamperRes = verifyReceipt(tamperedReceipt, rawPubHex);
    assert.equal(tamperRes.valid, false);
    assert.match(tamperRes.errors[0], /Leaf hash mismatch/);

    // 7. Test Rogue Public Key
    const roguePubKey = '0'.repeat(64);
    const rogueRes = verifyReceipt(receipt0, roguePubKey);
    assert.equal(rogueRes.valid, false);
    assert.match(rogueRes.errors[0], /Public key mismatch/);
  });
});
