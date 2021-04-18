This is an unofficial C++ library for calling v2 Algorand APIs.
Inspired by Algoduino, but needed an implementation that was not tied
to Arduino, and could use v2 APIs, which required msgpack of
transactions, key handling, etc.

# Getting started

 1. Install dependencies.  Use `make brew-deps` if you use `brew` on a
    Mac.  Otherwise, check that rule in the Makefile for hints on what
    your system might require.  Feel free to send PRs for `make
    ubuntu-deps` or similar.

 2. Build.  `make` should be sufficient

 3. Obtain access to an algod (and perhaps indexer) to make your API
    calls to.  For testing, the [Agorand
    Sandbox](https://github.com/algorand/sandbox) is excellent.  After
    bringing up a sandbox using the defaults, the variables in
    `.env.sandbox` will allow testing algod and indexer APIs.  The
    mnemonics and addresses in `.env.sandbox` are automatically setup
    by `sandbox` with plenty of algos.

 4. You can use `./example` as a very simple exercise harness.


# Complete
 1. algod APIs
 2. mnemonic/address/key handling
 3. All transaction types (provided as static functions on a unified
    Transaction class)
 4. Simple (single account) signatures
 5. Logicsigs, including delegated logisigs.

# TODO
 1. multisig
 2. indexer APIs
 3. kmd APIs
 4. msgpack responses (currently always uses JSON)
