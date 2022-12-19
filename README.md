# libmensago

A library written in Rust for implementing [Mensago](https://mensago.org) client software released under the Mozilla Public License 2.0.

## Description

This library will provide all the necessary business logic to implement a Mensago client, from client-side storage, to client-server communications, to identity management. Once stable, a C interface will be created so that languages that support the C FFI will be able to easily create bindings.

## Development Status

libmensago is pre-alpha and under active development. As of 12/2022 code for account registration, profile management, and other identity-related tasks are functionally complete and current development focus is on note and contact management in parallel with development of [Mensago Connect](https://gitlab.com/mensago/connect). Once the client has reached a corresponding feature goal, the messaging backend will be written and a release made afterward.

## Usage

libmensago has not yet been published to crates.io because of its early development status. Please add it to your Cargo.toml as a Git repository if you wish to use it in your own projects. Documentation for the module can be accessed by checking out the repository and running `cargo doc --open` in the repository root.

## Building

Building libmensago requires the Rust toolchain. Check out the repository and run `cargo build`.

## Contributing

Although a mirror repository can be found on GitHub for historical reasons, the official repository for this project is on [GitLab](https://gitlab.com/mensago/libmensago). Please submit issues and pull requests there.

Mensago itself is a very young, very ambitious project that needs help in all sorts of areas -- not just writing code. Find out more information at https://mensago.org/develop.
