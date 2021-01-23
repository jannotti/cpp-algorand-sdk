This is an unofficial C++ library for calling v2 Algorand APIs.
Inspired by Algoduino, but needed an implementation that was not tied
to Arduino, and could use v2 APIs, which required msgpack of
transactions, key handling, etc.

# Complete
 1. algod APIs
 2. mnemonic/address/key handling

# In progress
 1. Transaction types (payments, key reg, asset config/xfer/freeze)
 1. Signing (basic single signature is done, need logicsigs, multisigs)

# TODO
 2. indexer APIs
 3. kmd APIs
