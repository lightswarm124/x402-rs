import init, {
  BchBrowserClient,
  BchBrowserWalletClient,
  JsFulcrumTransport,
  build_signed_payment,
} from "./pkg/x402_chain_bch.js";

function offlineTransport(testCase) {
  return new JsFulcrumTransport(async (method, paramsJson) => {
    const params = JSON.parse(paramsJson);
    if (method === "blockchain.scripthash.listunspent") {
      return JSON.stringify(testCase.listunspent);
    }
    if (method === "blockchain.transaction.get") {
      const transaction = testCase.transactions[params[0]];
      if (!transaction) {
        throw new Error(`offline fixture has no transaction ${params[0]}`);
      }
      return JSON.stringify(transaction);
    }
    throw new Error(`offline test does not call ${method}`);
  });
}

async function signCase(vectors, testCase) {
  const transport = offlineTransport(testCase);
  const requirements = JSON.stringify(testCase.requirements);
  if (testCase.mode === "mnemonic") {
    const client = new BchBrowserClient(vectors.mnemonic, "mainnet", transport);
    return client.sign_exact(requirements, vectors.resource);
  }
  if (testCase.mode === "wallet") {
    const client = new BchBrowserWalletClient(
      async (requestJson) =>
        build_signed_payment(
          vectors.mnemonic,
          "mainnet",
          requestJson,
          JSON.stringify(testCase.walletUtxos),
        ),
      "mainnet",
      transport,
    );
    return client.sign_exact(requirements, vectors.resource);
  }
  throw new Error(`unknown offline mode ${testCase.mode}`);
}

export async function runOfflineVectors(vectors) {
  if (vectors.offline !== true) {
    throw new Error("refusing vectors that are not marked offline");
  }
  await init();
  const results = [];
  for (const testCase of vectors.cases) {
    try {
      const summary = JSON.parse(await signCase(vectors, testCase));
      results.push({ id: testCase.id, ok: true, transactionHex: summary.transactionHex });
    } catch (error) {
      results.push({
        id: testCase.id,
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }
  return results;
}

window.runOfflineVectors = runOfflineVectors;
