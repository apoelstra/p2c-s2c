# Pay-to-Contract / Sign-to-Contract

This library provides support for tweaking secp256k1 signing keys such that they
become a cryptographic commitment to some data; it also provides support for
tweaking ECDSA and BIP-340 signatures so that *they* become a commitment to some
data.

These constructions together can be used together, for example to implement
[smart contracts unchained](https://zmnscpxj.github.io/bitcoin/unchained.html) in
which a user tweaks a service's public key with some program, provides a witness
for that program's acceptance to the service, and the services signs a Bitcoin
transaction with a signature committing to the witness. The key, signature,
program and witness together provide a transferrable proof of the service's
correct operation.

## MSRV

This library should compile with any combination of feature flags on **Rust 1.74.0**.

## Contributing

This library is licensed under the LGPL 3.0 license, which means that any derivative
works or modifications to the library (though not projects that merely *use* the
library without modifying it) must also be licensed under LGPL 3.0 and its source
code must be made freely available.

Contributions are welcome under this license. However, bear in mind that this is a
cryptographic library with few maintainers, and has a stringent, slow-moving review
process.

## Pay-to-Contract (P2C)

[Pay-to-contract](https://bitcoinops.org/en/topics/pay-to-contract-outputs/) is a
mechanism by which a public key *P* is relaced by *P* + H(*P* || *x*) where H is
a cryptographic hash function and *x* is some auxiliary data. The resulting
commitment is [post-quantum secure](https://eprint.iacr.org/2025/1307) even though
the key itself (considered as a signing key) is not.

These commitments can be used to produce transferrable proofs that a public key
was intended for a specific purpose. (By using Merkle trees or repeating the P2C
construction it is possible to commit to multiple values, but it is impossible
to do this "surreptitiously," i.e. in a way that a single key can open as multiple
commitments that all have the same structure.)

Pay-to-contract is the basis of Taproot commitments in Bitcoin as well as the pegin
mechanism used in the [Elements](https://github.com/ElementsProject/elements/)
project. **p2c-s2c currently prescribes a specific hash format** which makes it
unusable for those commitments; patches are welcome to add this functionality.

[BIP-0372](https://github.com/bitcoin/bips/blob/master/bip-0372.mediawiki) specifies
a PSBT field for pay-to-contract tweaks. This library can be used to produce values
for this field, but it does not directly support PSBT or any other application.

## Sign-to-Contract (S2C)

Sign-to-contract is less well-known; essentially, it uses the pay-to-contract
construction on the *nonce* point of an elliptic curve signature. This has a number
of use cases:

* Committing an audit log of a signing wallet's state, signing timestamp, etc.
* Committing audit logs of auxliary data, e.g. the set of signers that participated
  in a threshold signature.
* [Timestamping data in an ordinary Bitcoin transaction](https://github.com/opentimestamps/python-opentimestamps/pull/14)
* Committing to witness data in a "smart contracts unchained" setting.

