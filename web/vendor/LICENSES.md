# Licences of the vendored libraries

The two files in this folder are other projects' code, redistributed under their own licences.
Their copyright notices are kept here because the minified bundles do not carry them.

## ethers 6.17.0 (`ethers.min.js`)

The file is `dist/ethers.min.js` from the `ethers` 6.17.0 npm package, unchanged. MIT licence:

> Copyright (c) 2016-2025 Richard Moore

That build includes these libraries, each under the MIT licence:

| Library | Version | Copyright |
|---|---|---|
| `@noble/hashes` | 1.3.2 | Copyright (c) 2022 Paul Miller (https://paulmillr.com) |
| `@noble/curves` | 1.2.0 | Copyright (c) 2022 Paul Miller (https://paulmillr.com) |
| `@adraffy/ens-normalize` | 1.11.1 | Copyright (c) 2021 Andrew Raffensperger |
| `aes-js` | 4.0.0-beta.5 | Copyright (c) 2022 Richard Moore |

The versions are the ones `ethers` 6.17.0 declares as dependencies.

## @hot-labs/near-connect 0.12.0 (`near-connect.min.js`)

Bundled from the `@hot-labs/near-connect` 0.12.0 npm package (source: https://github.com/hot-dao/near-selector)
with the esbuild command in `README.md`. Its `package.json` declares the MIT licence and names
HOT Labs as the author; the package ships no separate licence file and declares no runtime dependencies.

> Copyright (c) HOT Labs

## The MIT licence

The text below applies to each library above, with that library's copyright line.

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
