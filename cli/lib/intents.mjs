// Pay from any chain: a NEAR Intents 1Click quote that turns the payer's
// asset (USDC on Base, SOL, ETH on Arbitrum, ...) into NEAR delivered to the
// payer's NEAR account, ready to attach to request_run.
// Docs: https://docs.near-intents.org/ ; base https://1click.chaindefuser.com
// No testnet exists for Intents (mainnet only): quotes default to dry.
const BASE = 'https://1click.chaindefuser.com';
export const WNEAR = 'nep141:wrap.near';

export async function tokens() {
  const r = await fetch(`${BASE}/v0/tokens`);
  if (!r.ok) throw new Error(`1Click tokens: HTTP ${r.status}`);
  return r.json();
}

export async function quote({ originAsset, amount, recipient, refundTo, dry = true, slippageBps = 100 }) {
  const body = {
    dry,
    swapType: 'EXACT_INPUT',
    slippageTolerance: slippageBps,
    originAsset,
    depositType: 'ORIGIN_CHAIN',
    destinationAsset: WNEAR,
    amount: String(amount),
    refundTo,
    refundType: 'ORIGIN_CHAIN',
    recipient,
    recipientType: 'DESTINATION_CHAIN',
    deadline: new Date(Date.now() + 30 * 60 * 1000).toISOString(),
  };
  const r = await fetch(`${BASE}/v0/quote`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(process.env.ONECLICK_JWT ? { Authorization: `Bearer ${process.env.ONECLICK_JWT}` } : {}) },
    body: JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`1Click quote: HTTP ${r.status} ${JSON.stringify(j).slice(0, 300)}`);
  return j;
}
