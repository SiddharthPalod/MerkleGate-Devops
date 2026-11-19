const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { runGuardrail } = require('./index');
const {
  hashLeaf,
  hashInterior,
  canonicalSTHDigest
} = require('./verify');

describe('GitHub Action Guardrail In-Process Verification', () => {
  test('Action approves deployment when all required policies have valid cryptographic receipts', async () => {
    // 1. Generate Ed25519 STH Keypair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const pubKeyHex = spkiDer.subarray(spkiDer.length - 32).toString('hex');

    const commitSha = 'deadbeef1234567890abcdef1234567890abcdef';
    const payload0 = JSON.stringify({
      event_type: 'git_commit',
      commit_sha: commitSha,
      actor: 'dev-lead',
      timestamp: 1700000000
    });
    const payload1 = JSON.stringify({
      event_type: 'pr_approval',
      commit_sha: commitSha,
      actor: 'security-admin',
      pr_number: 10
    });

    const leaf0Hash = hashLeaf(payload0);
    const leaf1Hash = hashLeaf(payload1);
    const rootBuf = hashInterior(Buffer.from(leaf0Hash, 'hex'), Buffer.from(leaf1Hash, 'hex'));
    const rootHex = rootBuf.toString('hex');

    const timestamp = Math.floor(Date.now() / 1000);
    const digest = canonicalSTHDigest(2, rootHex, timestamp, 1n);
    const sigHex = crypto.sign(null, digest, privateKey).toString('hex');

    const sth = {
      tree_size: 2,
      root_hash: rootHex,
      timestamp,
      sequence: 1,
      signature: sigHex,
      public_key: pubKeyHex
    };

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

    const receipt1 = {
      leaf_index: 1,
      raw_payload: payload1,
      leaf_hash: leaf1Hash,
      historical_root: rootHex,
      inclusion_proof: {
        leaf_index: 1,
        tree_size: 2,
        audit_path: [leaf0Hash]
      },
      signed_tree_head: sth
    };

    // In-memory mock fetcher
    const mockFetcher = async (url) => {
      if (url.includes(`/api/v1/events/commit/${commitSha}`)) {
        return { commit_sha: commitSha, leaf_indices: [0, 1] };
      }
      if (url.includes('/api/v1/receipt/0')) {
        return receipt0;
      }
      if (url.includes('/api/v1/receipt/1')) {
        return receipt1;
      }
      if (url.includes('/api/v1/receipt/verify')) {
        return { all_passed: true, valid: true };
      }
      throw new Error(`404: Not Found (${url})`);
    };

    // 2. Test Success Flow (Approval)
    const successResult = await runGuardrail({
      endpoint: 'http://localhost:8083',
      commitSha: commitSha,
      pubKey: pubKeyHex,
      requiredPolicies: 'git_commit,pr_approval',
      failClosed: true,
      fetcher: mockFetcher
    });

    assert.equal(successResult.approved, true);
    assert.equal(successResult.verifiedCount, 2);

    // 3. Test Policy Failure (Missing snyk_scan)
    await assert.rejects(
      async () => {
        await runGuardrail({
          endpoint: 'http://localhost:8083',
          commitSha: commitSha,
          pubKey: pubKeyHex,
          requiredPolicies: 'git_commit,pr_approval,snyk_scan',
          failClosed: true,
          fetcher: mockFetcher
        });
      },
      (err) => {
        assert.match(err.message, /Missing policies: snyk_scan/);
        assert.equal(err.exitCode, 1);
        return true;
      }
    );

    // 4. Test Cryptographic Tampering Failure
    const tamperedFetcher = async (url) => {
      if (url.includes('/api/v1/receipt/0')) {
        return {
          ...receipt0,
          raw_payload: payload0.replace('dev-lead', 'rogue-hacker')
        };
      }
      return mockFetcher(url);
    };

    await assert.rejects(
      async () => {
        await runGuardrail({
          endpoint: 'http://localhost:8083',
          commitSha: commitSha,
          pubKey: pubKeyHex,
          requiredPolicies: 'git_commit,pr_approval',
          failClosed: true,
          fetcher: tamperedFetcher
        });
      },
      (err) => {
        assert.match(err.message, /Crypto failure/);
        return true;
      }
    );
  });
});
