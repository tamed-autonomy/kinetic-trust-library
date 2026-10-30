# Native runtime isolation for the eventual public 3.0 cutover

The candidate native modules used neutral base64url, signature-shape and URI
helpers through legacy `proofs`/`models` import paths. Python loaded those legacy
packages and their claim-model/parser dependencies before the new helpers could
be used. This was an import coupling, not a v2 wire fallback; it would complicate
removing the old public root at the final release.

Move the unchanged provider-neutral signature checks and strict base64url
decoder to root-private shared modules, and move the same value-preserving URI
algorithm to a root-private neutral module. Native code imports those modules
directly. Legacy private locations delegate to the same implementation; legacy
URI parsing retains its existing injected-parser/error behavior and public
validator identity/signature. This is reuse of neutral primitives, not reuse of
the 2.1 proof parser, models or runtime contract.

The root public API, package version and normative pin remain 2.1.0 until the
deliberate final adoption. A fresh subprocess instead supplies only a minimal
package root, blocks legacy models/proofs/Core imports, and loads the native
evaluation, person claims, software issuance and typed stop graph. A static
dependency guard also rejects deferred/relative legacy imports. These checks
pass without optional dependencies (`python -S`), demonstrating the native tree
can stand independently when the root API is switched. Existing 2.1 behavior
continues through its public root and is verified by its regression suite.
