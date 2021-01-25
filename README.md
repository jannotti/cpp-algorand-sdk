This is an unofficial C++ library for calling v2 Algorand APIs.
Inspired by Algoduino, but needed an implementation that was not tied
to Arduino, and could use v2 APIs, which required msgpack of
transactions, key handling, etc.

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
