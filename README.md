### mojang-api
![Documentation](https://docs.rs/mojang-api/badge.svg)
[![crates.io](https://meritbadge.herokuapp.com/mojang-api)](https://crates.io/crates/mojang-api)

This crate offers a simple interface for utilizing the Mojang API. It utilizes
experimental async/await syntax, allowing for clean, asynchronous requests.

Currently, the following mechanisms are supported:
* Obtaining the "server hash" required for authenticating with Mojang.
* Running server-side authentication of a client.

In the future, additional functionality will be added.