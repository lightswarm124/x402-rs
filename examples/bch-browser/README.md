# Browser BCH exact payment

This page signs a Chipnet-shaped exact payment with the same Rust client used
by native callers. The page supplies a JavaScript Fulcrum transport. The Rust
client selects the UTXO, builds the transaction, checks the serialized fee and
dust, and verifies the signature before returning.

The mnemonic is the public BIP39 test vector. The merchant address is the
chipnet CashAddr for the same 20-byte hash used by the native tests. The
transport returns one local UTXO and rejects every other method, including
broadcast.

An omitted CashToken `value` uses the same size-aware default as
the native client: at least 1,000 satoshis, the policy dust threshold, and
the output's standard relay dust. A 128-byte NFT commitment can require more
than 1,000 satoshis. An explicit value is preserved. Native outputs keep the
546-satoshi dust floor.

`BchBrowserClient` signs with the mnemonic helper. `BchBrowserWalletClient`
calls the wallet-backed Rust client: the page returns a signed transaction,
and Rust verifies it. `build_signed_payment` is that callback's path into the
existing Rust builder. Wallet UTXO token amounts are decimal strings, so a
CashToken amount above 2^53-1 stays exact through JavaScript.

`offline-check.mjs` runs these cases in a browser and compares the transaction
bytes with the native offline tests. It does not broadcast or contact a live
network. The ignored Fulcrum tests remain the live-network checks.

Build the package from the repository root, with Clang available:

```bash
wasm-pack build crates/chains/x402-chain-bch --target web --out-dir ../../../examples/bch-browser/pkg
```

Serve this directory over HTTP and open `index.html`. A successful page sets
`document.documentElement.dataset.status` to `ok`.
