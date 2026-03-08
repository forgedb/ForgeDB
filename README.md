<div align="center">
  <img src="https://github.com/forgedb/ForgeDB/blob/main/forge.png?raw=true" alt="ForgeDB Logo" width="200">
  
  <h1>ForgeDB</h1>
  
  [<img alt="github" src="https://img.shields.io/badge/github-forgedb/ForgeDB-8da0cb?style=for-the-badge&labelColor=555555&logo=github" height="20">](https://github.com/forgedb/ForgeDB)
  [<img alt="build status" src="https://img.shields.io/github/actions/workflow/status/forgedb/ForgeDB/rust.yml?branch=main&style=for-the-badge" height="20">](https://github.com/forgedb/ForgeDB/actions)
</div>

<div align="center">
  <strong>Fast, Secure, Simple database.</strong>
</div>

## Installation

Build from source:

```bash
git clone https://github.com/jonathanmagambo/ForgeDB.git
cd ForgeDB
cargo build --release
```

## Quick Start

Initialize the database:

```bash
./target/release/forgedb init --data-dir ./data
```

Start the server:

```bash
./target/release/forgedb serve --data-dir ./data --with-tui
```

<h1 align="center">Contributing And License</h1>

> [!IMPORTANT]  
> The project is in active development. **If you plan to contribute to the project, now is the time to provide a helping hand**. We're continuously improving performance and adding new features.
>
> In addition, the project uses the **[Business Source License 1.1](LICENSE)**, which allows you to:
> - Copy, modify, create derivative works, redistribute, and make non-production use of the software
> - Eventually see the code transition to an Open Source License (Apache 2.0) after the Change Date
> - The only requirement is to include the license and copyright notice

When it comes to contributing and forking, ForgeDB is free to use for non-production purposes, released under the <strong>Business Source License 1.1</strong>. 
Contributions are welcome with wide open arms as ForgeDB is looking to foster a community. 