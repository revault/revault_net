# Revault net

[Revault](https://github.com/revault/practical-revault/blob/master/revault.pdf) is a
Bitcoin vault architecture for multi-party situations.

This library implements the protocol messages of the [version 0 specification](https://github.com/revault/practical-revault/blob/master/messages.md),
as well as the [transport over which these messages are exchanged](https://github.com/revault/practical-revault/blob/master/transport.md).

# Minimum Supported Rust Version

This library should always compile with any combination of features on **Rust 1.48**.

Since dependencies are breaking backward compatibility in minor versions, you'll unfortunately have
to pin some of them to be able to build with 1.48:
```
cargo update -p ed25519 --precise "1.3.0"
cargo +1.48 build
```


# Contributing

Contributions are very welcome. For general guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).

Discussions happen either here in issues or at [`#revault` on Libera](https://web.libera.chat/?channels=#revault).


# Licence

Released under the BSD 3-Clause Licence. See the [LICENSE](LICENSE) file.
