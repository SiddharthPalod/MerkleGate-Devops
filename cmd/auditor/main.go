package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"merklegate/pkg/receipt"
	"merklegate/pkg/signer"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "verify":
		runVerify(os.Args[2:])
	case "pubkey":
		runPubkey(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`MerkleGate Independent Auditor CLI

Usage:
  auditor verify <receipt.json> --pubkey <pubkey-hex-or-file>
  auditor pubkey <ed25519.key> [--out ed25519.pub]

Commands:
  verify   Independently verifies a compliance receipt offline using RFC 6962, RFC 9162, and Ed25519
  pubkey   Extracts the hex-encoded Ed25519 public key from a private key file`)
}

func runVerify(args []string) {
	var pubkeyVal string
	var receiptFile string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--pubkey" || arg == "-pubkey" {
			if i+1 < len(args) {
				pubkeyVal = args[i+1]
				i++
			}
		} else if strings.HasPrefix(arg, "--pubkey=") {
			pubkeyVal = strings.TrimPrefix(arg, "--pubkey=")
		} else if strings.HasPrefix(arg, "-pubkey=") {
			pubkeyVal = strings.TrimPrefix(arg, "-pubkey=")
		} else if !strings.HasPrefix(arg, "-") && receiptFile == "" {
			receiptFile = arg
		}
	}

	if receiptFile == "" || pubkeyVal == "" {
		fmt.Fprintln(os.Stderr, "Usage: auditor verify <receipt.json> --pubkey <pubkey-hex-or-file>")
		os.Exit(1)
	}

	// 1. Read and parse compliance receipt
	receiptBytes, err := os.ReadFile(receiptFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading receipt file %s: %v\n", receiptFile, err)
		os.Exit(1)
	}

	var r receipt.ComplianceReceipt
	if err := json.Unmarshal(receiptBytes, &r); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing receipt JSON: %v\n", err)
		os.Exit(1)
	}

	// 2. Resolve trusted public key
	pubKey, err := resolvePublicKey(pubkeyVal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving public key: %v\n", err)
		os.Exit(1)
	}

	// 3. Run complete verification chain
	report := receipt.Verify(pubKey, &r)

	// 4. Output human-readable audit report
	fmt.Println("============================================================")
	fmt.Println("         MERKLEGATE INDEPENDENT AUDITOR VERIFIER           ")
	fmt.Println("============================================================")
	fmt.Printf("Receipt File    : %s\n", receiptFile)
	fmt.Printf("Receipt Version : %s\n", r.Version)
	fmt.Printf("Target Leaf     : %d\n", r.LeafIndex)
	fmt.Printf("Tree Size       : %d\n", report.TreeSize)
	if r.SignedTreeHead.Timestamp > 0 {
		fmt.Printf("STH Timestamp   : %s\n", time.Unix(r.SignedTreeHead.Timestamp, 0).UTC().Format(time.RFC3339))
	}
	fmt.Println("------------------------------------------------------------")

	for _, step := range report.Steps {
		if step.Passed {
			fmt.Printf("[✓] %s\n    %s\n", step.Name, step.Details)
		} else {
			fmt.Printf("[❌] %s\n    ERROR: %s\n", step.Name, step.Details)
		}
	}

	fmt.Println("------------------------------------------------------------")
	if report.Valid {
		fmt.Println("FINAL VERDICT: CRYPTOGRAPHICALLY VALID & COMPLIANT ✓")
		fmt.Println("All proofs match RFC 6962 / RFC 9162 invariants and Ed25519 signature.")
		os.Exit(0)
	} else {
		fmt.Println("FINAL VERDICT: VERIFICATION FAILED (TAMPER DETECTED) ❌")
		fmt.Fprintf(os.Stderr, "Failure Cause: %s\n", report.Error)
		os.Exit(2)
	}
}

func runPubkey(args []string) {
	fs := flag.NewFlagSet("pubkey", flag.ExitOnError)
	outFlag := fs.String("out", "", "Optional output file path to write public key hex")

	if err := fs.Parse(args); err != nil || fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: auditor pubkey <ed25519.key> [--out ed25519.pub]")
		os.Exit(1)
	}

	keyFile := fs.Arg(0)
	privKey, err := signer.LoadPrivateKey(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading private key: %v\n", err)
		os.Exit(1)
	}

	pubKey := privKey.Public().(ed25519.PublicKey)
	pubHex := hex.EncodeToString(pubKey)

	if *outFlag != "" {
		if err := os.WriteFile(*outFlag, []byte(pubHex), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing public key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Public key written to %s: %s\n", *outFlag, pubHex)
	} else {
		fmt.Printf("Public Key (Hex): %s\n", pubHex)
	}
}

func resolvePublicKey(input string) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(input)

	// Check if input is a readable file
	if data, err := os.ReadFile(trimmed); err == nil {
		trimmed = strings.TrimSpace(string(data))
	}

	// Try decoding as hex
	bytes, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("public key must be 64-char hex string: %w", err)
	}
	if len(bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: expected %d bytes, got %d", ed25519.PublicKeySize, len(bytes))
	}

	return ed25519.PublicKey(bytes), nil
}
