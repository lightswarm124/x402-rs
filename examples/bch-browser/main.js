import init, { BchBrowserClient, JsFulcrumTransport } from "./pkg/x402_chain_bch.js";

const BIP39_TEST_MNEMONIC =
  "legal winner thank year wave sausage worth useful legal winner thank yellow";
// Chipnet CashAddr for hash160 0x11 repeated. The checksum covers the prefix.
const MERCHANT = "bchtest:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyarjfagm9";
const RESOURCE = "https://merchant.example/item";

function fail(message) {
  document.documentElement.dataset.status = "fail";
  document.getElementById("result").textContent = message;
}

try {
  await init();

  const transport = new JsFulcrumTransport(async (method) => {
    if (method !== "blockchain.scripthash.listunspent") {
      throw new Error(`this example does not call ${method}`);
    }
    return JSON.stringify([
      {
        tx_hash: "11".repeat(32),
        tx_pos: 0,
        value: 100000,
        height: 10,
      },
    ]);
  });

  const client = new BchBrowserClient(BIP39_TEST_MNEMONIC, "chipnet", transport);
  const summary = JSON.parse(
    await client.sign_exact(
      JSON.stringify({
        scheme: "exact",
        network: "bch:bchtest",
        amount: "1000",
        payTo: MERCHANT,
        maxTimeoutSeconds: 300,
        asset: "BCH",
        extra: { assetTransferMethod: "native", paymentFlow: "upfront" },
      }),
      RESOURCE,
    ),
  );

  if (summary.merchantValue !== 1000 || summary.inputCount < 1 || summary.byteLength < 100) {
    fail(
      `unexpected payment summary ${JSON.stringify({
        merchantValue: summary.merchantValue,
        inputCount: summary.inputCount,
        outputCount: summary.outputCount,
        byteLength: summary.byteLength,
      })}`,
    );
  } else {
    document.documentElement.dataset.status = "ok";
    document.getElementById("result").textContent = JSON.stringify(
      {
        address: client.address,
        merchantValue: summary.merchantValue,
        inputCount: summary.inputCount,
        outputCount: summary.outputCount,
        byteLength: summary.byteLength,
      },
      null,
      2,
    );
  }
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}
