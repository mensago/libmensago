# libmensago

A library written in Rust for implementing [Mensago](https://mensago.org) client software released under the Mozilla Public License 2.0.

## Description

This library will provide all the necessary business logic to implement a Mensago client, from client-side storage, to client-server communications, to identity management. Once stable, a C interface will be created so that languages that support the C FFI will be able to easily create bindings.

## Development Status

libmensago is pre-alpha and active development is paused for the moment because of a change in development plans. Mensago Connect requires a GUI toolkit which is more mature than is available in the Rust ecosystem at this time. As such, Connect is being written in Kotlin for the JVM and the current Rust-based support libraries (eznacl, libkeycard, libmensago) are being ported to Kotlin. Development resource constraints do not permit working on both in parallel at this time, but because many future Mensago-related applications will depend on a C-compatible API, this library is not being abandoned, and development will resume at a future time. As of 1/2023 code for account registration, profile management, and other identity-related tasks are functionally complete.

## Usage

libmensago has not yet been published to crates.io because of its early development status. Please add it to your Cargo.toml as a Git repository if you wish to use it in your own projects. Documentation for the module can be accessed by checking out the repository and running `cargo doc --open` in the repository root.

## Building

Building libmensago requires the Rust toolchain. Check out the repository and run `cargo build`.

## Contributing

Although a mirror repository can be found on GitHub for historical reasons, the official repository for this project is on [GitLab](https://gitlab.com/mensago/libmensago). Please submit issues and pull requests there.

Mensago itself is a very young, very ambitious project that needs help in all sorts of areas -- not just writing code. Find out more information at https://mensago.org/develop.
