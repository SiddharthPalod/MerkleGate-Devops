const http = require('http');
const https = require('https');
const fs = require('fs');
const { verifyReceipt } = require('./verify');

function getInput(name, def = '') {
  const norm = name.replace(/-/g, '_').toUpperCase();
  const val = process.env[`INPUT_${norm}`] ||
              process.env[`INPUT_${name.toUpperCase()}`] ||
              process.env[name];
  return (val !== undefined && val !== '') ? val.trim() : def;
}

function fetchJSON(url, options = {}) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.request(url, options, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        if (res.statusCode < 200 || res.statusCode >= 300) {
          return reject(new Error(`HTTP ${res.statusCode}: ${data || res.statusMessage}`));
        }
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error(`Failed to parse JSON from ${url}: ${e.message}`));
        }
      });
    });
    req.on('error', reject);
    if (options.body) {
      req.write(typeof options.body === 'string' ? options.body : JSON.stringify(options.body));
    }
    req.end();
  });
}

function writeSummary(text) {
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile) {
    try {
      fs.appendFileSync(summaryFile, text + '\n');
    } catch (_) {}
  }
}

async function runGuardrail(opts = {}) {
  const endpoint = (opts.endpoint || getInput('merkle-endpoint', 'http://localhost:8083')).replace(/\/+$/, '');
  const commitSha = opts.commitSha || getInput('commit-sha', process.env.GITHUB_SHA || '');
  const pubKey = opts.pubKey !== undefined ? opts.pubKey : getInput('public-key', '');
  const requiredPoliciesStr = opts.requiredPolicies || getInput('required-policies', 'git_commit,pr_approval');
  const failClosed = opts.failClosed !== undefined ? opts.failClosed : (getInput('fail-closed', 'true').toLowerCase() !== 'false');
  const fetcher = opts.fetcher || fetchJSON;

  console.log('\n===============================================================');
  console.log('       🛡️  MerkleGate Verifiable Compliance Guardrail          ');
  console.log('===============================================================\n');

  const requiredPolicies = requiredPoliciesStr.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

  console.log(`• Ledger Endpoint:    ${endpoint}`);
  console.log(`• Target Commit SHA:  ${commitSha}`);
  console.log(`• Required Policies:  [${requiredPolicies.join(', ')}]`);
  console.log(`• Fail Closed Mode:   ${failClosed}`);
  if (pubKey) {
    console.log(`• Pinned STH PubKey:  ${pubKey.slice(0, 16)}...`);
  }

  if (!commitSha) {
    throw new Error('commit-sha must be provided.');
  }

  // 1. Query Redis / Daemon for leaf indices corresponding to this commit
  console.log(`\n[Step 1/3] Querying ledger for leaves associated with commit ${commitSha}...`);
  let leafIndices = [];
  try {
    const res = await fetcher(`${endpoint}/api/v1/events/commit/${commitSha}`);
    leafIndices = res.leaf_indices || [];
  } catch (err) {
    console.warn(`Warning: Could not fetch commit index directly: ${err.message}`);
  }

  if (leafIndices.length === 0) {
    const errMsg = `No compliance leaves registered in MerkleGate for commit ${commitSha}`;
    console.error(`❌ Verification Failed: ${errMsg}`);
    writeSummary(`### ❌ MerkleGate Guardrail Failure\n\n${errMsg}`);
    if (failClosed) {
      const err = new Error(errMsg);
      err.exitCode = 1;
      throw err;
    }
    return { approved: false, reason: errMsg };
  }

  console.log(`✓ Found ${leafIndices.length} compliance leaf record(s): [${leafIndices.join(', ')}]`);

  // 2. Fetch and cryptographically verify each receipt
  console.log('\n[Step 2/3] Executing Dual-Path Cryptographic Verification...');
  const verifiedLeaves = [];
  const foundPolicies = new Set();
  let allCryptoValid = true;

  for (const leafIdx of leafIndices) {
    console.log(`\n--- Auditing Leaf Index #${leafIdx} ---`);
    let receipt;
    try {
      receipt = await fetcher(`${endpoint}/api/v1/receipt/${leafIdx}`);
    } catch (err) {
      console.error(`  ✗ Failed to fetch receipt for leaf ${leafIdx}: ${err.message}`);
      allCryptoValid = false;
      continue;
    }

    // A. Client-side cryptographic verification (zero server trust)
    const clientResult = verifyReceipt(receipt, pubKey);
    if (!clientResult.valid) {
      console.error(`  ✗ Client Crypto Check Failed:`);
      clientResult.errors.forEach(e => console.error(`    - ${e}`));
      allCryptoValid = false;
      continue;
    }
    console.log(`  ✓ Client Math Verified: Leaf Hash = ${clientResult.leafHash.slice(0, 16)}... (RFC 6962 + Ed25519)`);

    // B. Server-side Gateway confirmation (Dual-Path)
    try {
      const serverResult = await fetcher(`${endpoint}/api/v1/receipt/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: receipt
      });
      if (serverResult.all_passed) {
        console.log(`  ✓ Gateway Dual-Verification Confirmed (Root = ${receipt.signed_tree_head.root_hash.slice(0, 16)}...)`);
      }
    } catch (err) {
      console.log(`  ℹ Gateway endpoint check skipped/offline (${err.message}); client proof holds independently.`);
    }

    // Parse event type from raw payload
    let eventType = 'unknown';
    try {
      const payloadObj = JSON.parse(receipt.raw_payload);
      eventType = (payloadObj.event_type || payloadObj.type || '').toLowerCase();
    } catch (_) {}

    foundPolicies.add(eventType);
    verifiedLeaves.push({
      leafIndex: leafIdx,
      eventType,
      leafHash: clientResult.leafHash,
      treeSize: clientResult.treeSize,
      sequence: clientResult.sthSequence
    });
  }

  // 3. Evaluate Compliance Policies
  console.log('\n[Step 3/3] Evaluating Enterprise Compliance Guardrail Policies...');
  const missingPolicies = [];
  for (const req of requiredPolicies) {
    if (!foundPolicies.has(req)) {
      missingPolicies.push(req);
    }
  }

  let summaryMd = `### 🛡️ MerkleGate Deployment Guardrail Report\n\n`;
  summaryMd += `**Commit SHA:** \`${commitSha}\`  \n`;
  summaryMd += `**Total Verified Leaves:** ${verifiedLeaves.length}  \n\n`;
  summaryMd += `| Leaf # | Event Type | Leaf Digest | Tree Size | STH Seq |\n`;
  summaryMd += `| :--- | :--- | :--- | :--- | :--- |\n`;
  for (const l of verifiedLeaves) {
    summaryMd += `| ${l.leafIndex} | \`${l.eventType}\` | \`${l.leafHash.slice(0, 12)}...\` | ${l.treeSize} | #${l.sequence} |\n`;
  }
  summaryMd += `\n`;

  if (!allCryptoValid || missingPolicies.length > 0) {
    console.error('\n❌ DEPLOYMENT BLOCKED: Compliance Policy Violations Detected!');
    let failReason = '';
    if (missingPolicies.length > 0) {
      console.error(`  Missing required policy leaves: [${missingPolicies.join(', ')}]`);
      summaryMd += `> [!CAUTION]\n> **Missing Required Compliance Policies:** \`${missingPolicies.join(', ')}\`\n`;
      failReason = `Missing policies: ${missingPolicies.join(', ')}`;
    }
    if (!allCryptoValid) {
      console.error(`  One or more cryptographic proofs failed verification.`);
      summaryMd += `> [!CAUTION]\n> **Cryptographic Integrity Failure:** One or more Merkle or STH proofs failed verification.\n`;
      failReason = failReason ? failReason + '; Crypto failure' : 'Crypto failure';
    }
    writeSummary(summaryMd);
    if (failClosed) {
      const err = new Error(failReason);
      err.exitCode = 1;
      throw err;
    }
    return { approved: false, reason: failReason };
  }

  console.log('\n===============================================================');
  console.log('  ✅ ALL POLICIES SATISFIED: DEPLOYMENT CRYPTOGRAPHICALLY APPROVED');
  console.log('===============================================================\n');
  summaryMd += `> [!NOTE]\n> **Verdict: APPROVED.** All required compliance policies verified against immutable Signed Tree Head.\n`;
  writeSummary(summaryMd);

  return { approved: true, verifiedCount: verifiedLeaves.length };
}

if (require.main === module) {
  runGuardrail().catch(err => {
    console.error(`\n❌ Fatal Unhandled Error: ${err.message}`);
    process.exit(err.exitCode || 1);
  });
}

module.exports = {
  runGuardrail,
  fetchJSON
};
