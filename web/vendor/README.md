# Vendored browser libraries

- `ethers.min.js`: ethers 6.17.0 (MIT), used for EIP-191 signature recovery when verifying evidence in the browser.
- `near-connect.min.js`: `@hot-labs/near-connect` 0.12.0 (MIT), the NEAR wallet connector, bundled with
  esbuild 0.25.10: `echo "export { NearConnector } from '@hot-labs/near-connect';" > entry.mjs &&
  npx esbuild entry.mjs --bundle --format=esm --platform=browser --minify --outfile=near-connect.min.js`.
- `wallets.json`: the wallet list the connector is given on the hosted page, so the list is not
  fetched from another host at run time. It is the near-connect manifest (version 1.1.0, copied
  2026-11-10) cut down to the wallets that work on testnet without a WalletConnect project id.
  Each entry names where that wallet's connector code is loaded from when a visitor picks it;
  the code runs in a sandboxed frame. Where the code is published on GitHub the address names
  an exact commit, so it cannot change under the page. Two wallets (Intear, Ethereum Wallets)
  serve theirs from their own sites and are not pinned. To refresh: copy the entries again from
  `https://raw.githubusercontent.com/hot-dao/near-selector/refs/heads/main/repository/manifest.json`
  and replace each branch name in a `raw.githubusercontent.com` address with that branch's
  current commit (`git ls-remote <repository> <branch>`).

SHA-256 of the two libraries (checked by `cli/test/web-hardening.test.mjs`):

    b016b0c3898c78fd8156466eb1ff1f42c9df951c2f0d64c9bdf799fe745b0a6c  ethers.min.js
    75c628556bd59026a64915207464bdd1838ccb5a68b607ae8fb8e40b3db04916  near-connect.min.js

`near-connect.min.js` differs from the esbuild output above in one place: the frame a wallet's
code runs in is created with `sandbox="allow-scripts allow-modals"` instead of
`sandbox="allow-scripts"`. Without `allow-modals` the browser silently answers "no" to a
wallet's own "Close this window?" question, and Meteor's box could not be closed once a phone
had scanned its code. The unpatched build has SHA-256
`ba4a14519c69391e2b3664e9d26345842331567e5b08aefeb1d29d07c530cfbd`.

Upstream copyright and licence notices for both files are in `LICENSES.md`.
