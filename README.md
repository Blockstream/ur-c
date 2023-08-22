# ur-c
An (incomplete) C library for parsing BCR UR types.
At the moment the following Uniform resources are supported:
- [crypto-seed](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md#cryptographic-seed-crypto-seed)
- [crypto-psbt](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-006-urtypes.md#partially-signed-bitcoin-transaction-psbt-crypto-psbt)
- [crypto-eckey](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-008-eckey.md)
- [crypto-eckey](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-007-hdkey.md)


### how to build and run tests
#### the easy way
It requires cmake support for ``--preset`` option, which is included only on versions ``>=3.20``
```bash
$ cmake --preset dev
$ cmake --build --preset dev
$ ctest --preset dev --output-on-failure
```
