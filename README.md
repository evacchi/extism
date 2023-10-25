### _Welcome!_

**Please note:** This project still under active development and APIs are changing as we hit 1.0. Currently, the main branch has many breaking changes. Our current release is 0.5.x. Until we release 1.0, we are cutting these releases from the [stable](https://github.com/extism/extism/tree/stable) branch.

If you're interested in working on or building with Extism, please join our [Discord](https://discord.gg/cx3usBCWnc) and let us know - we are happy to help get you started.

[![Discord](https://img.shields.io/discord/1011124058408112148?color=%23404eed&label=Community%20Chat&logo=Discord&logoColor=%23404eed)](https://discord.gg/cx3usBCWnc)

# [Extism](https://extism.org)

The universal plug-in system. Run WebAssembly extensions inside your app. Use idiomatic Host SDKs for [Go](https://github.com/extism/go-sdk#readme),
[Ruby](https://github.com/extism/ruby-sdk#readme),
[Python](https://github.com/extism/python-sdk#readme),
[JavaScript](https://github.com/extism/js-sdk#readme),
[Rust](/runtime/#readme),
[C](libextism/#readme),
[C++](https://github.com/extism/cpp-sdk/#readme),
[OCaml](https://github.com/extism/ocaml-sdk#readme),
[Haskell](https://github.com/extism/haskell-sdk#readme),
[PHP](https://github.com/extism/php-sdk#readme),
[Elixir](https://github.com/extism/elixir-sdk#readme),
[.NET](https://github.com/extism/dotnet-sdk#readme),
[Java](https://github.com/extism/java-sdk#readme),
[Zig](https://github.com/extism/zig-sdk#readme),
[D](https://github.com/extism/d-sdk#readme),
&amp; more (others coming soon).

Plug-in development kits (PDK) for plug-in authors supported in [Rust](https://github.com/extism/rust-pdk#readme), [AssemblyScript](https://github.com/extism/assemblyscript-pdk#readme), [Go](https://github.com/extism/go-pdk#readme), [C/C++](https://github.com/extism/c-pdk#readme), [Haskell](https://github.com/extism/haskell-pdk#readme), [JavaScript](https://github.com/extism/js-pdk#readme), [C#](https://github.com/extism/dotnet-pdk#readme), [F#](https://github.com/extism/dotnet-pdk#readme) and [Zig](https://github.com/extism/zig-pdk#readme).

<p align="center">
  <img style="width: 70%;" src="https://user-images.githubusercontent.com/7517515/210286900-39b144fd-1b26-4dd0-b7a9-2b5755bc174d.png" alt="Extism embedded SDK language support"/>
</p>


Add a flexible, secure, and _bLaZiNg FaSt_ plug-in system to your project. Server, desktop, mobile, web, database -- you name it. Enable users to write and execute safe extensions to your software in **3 easy steps:**

### 1. Import

Import an Extism Host SDK into your code as a library dependency.

### 2. Integrate 

Identify the place(s) in your code where some arbitrary logic should run (the plug-in!), returning your code some results.

### 3. Execute

Load WebAssembly modules at any time in your app's lifetime and Extism will execute them in a secure sandbox, fully isolated from your program's memory.

--- 

## Usage

Head to the [project website](https://extism.org) for more information and docs. Also, consider reading an [overview](https://extism.org/docs/overview) of Extism and its goals & approach.

## Contribution

Thank you for considering a contribution to Extism, we are happy to help you make a PR or find something to work on! 

The easiest way to start would be to join the [Discord](https://discord.gg/cx3usBCWnc) or open an issue on the [`extism/proposals`](https://github.com/extism/proposals) issue tracker, which can eventually become an Extism Improvement Proposal (EIP).

---

## Who's behind this?

Extism is an open-source product from the team at:

<p align="left">
  <a href="https://dylib.so" _target="blanks"><img width="200px" src="https://user-images.githubusercontent.com/7517515/198204119-5afdebb9-a5d8-4322-bd2a-46179c8d7b24.svg"/></a>
</p>


_Reach out and tell us what you're building! We'd love to help._
