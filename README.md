# Vaxelium: common

The wire protocol shared by the Vaxelium auth service, chat servers and clients.

Every message is one JSON object per line (newline-delimited JSON) over TCP. This crate
holds the message types (`AuthRequest`, `AuthReply`, `ClientMsg`, `ServerMsg`), the default
ports, the size limits, the permission bits, and the TLS helpers both sides use.

This crate is a library. It has no program of its own.

## Part of Vaxelium

This repository is one part of the Vaxelium project. The rest are linked from the main
repository:

- [Vaxelium](https://github.com/Vaxelium/Vaxelium): the workspace, build scripts and docs
- [auth](https://github.com/Vaxelium/auth): the auth service that owns every account
- [server](https://github.com/Vaxelium/server): the chat server and its web client host
- [client](https://github.com/Vaxelium/client): the desktop and web client

## Building

This crate builds on its own. Clone it and run:

```
cargo test
```

The other crates fetch it from this repository's main branch.

## Licence

GNU GPL v3. See [LICENSE](LICENSE).
