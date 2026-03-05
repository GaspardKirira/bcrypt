# bcrypt

Minimal bcrypt password hashing utilities for C++.

`bcrypt` provides a small deterministic toolkit for hashing and verifying
passwords using the bcrypt algorithm.

Header-only wrapper. Uses the system crypt backend.

## Download

https://vixcpp.com/registry/pkg/gk/bcrypt

## Why bcrypt?

Modern applications must store passwords securely.

Plain-text passwords or simple hashes such as MD5 or SHA1 are unsafe.

`bcrypt` is one of the most widely used password hashing algorithms because it:

- includes a random salt
- is computationally expensive
- protects against brute-force attacks
- allows configurable cost factors

Many bcrypt libraries require large frameworks or complicated dependencies.

`bcrypt` provides a minimal alternative.

It focuses strictly on:

- password hashing
- password verification
- bcrypt salt generation

You plug it into your authentication system.

No framework required.

Just simple bcrypt helpers.

## Features

- Generate bcrypt salts
- Hash passwords
- Verify passwords
- Configurable cost factor
- Constant-time comparison helper
- Deterministic API
- Header-only wrapper

## Installation

### Using Vix Registry

```bash
vix add @gk/bcrypt
vix deps
```

### Manual

```bash
git clone https://github.com/Gaspardkirira/bcrypt.git
```

Add the `include/` directory to your project.

## Dependency

Requires C++17 or newer.

The library is header-only but relies on the system crypt backend.

On Linux systems this usually requires linking with:

- `-lcrypt`

Example build:

```bash
g++ example.cpp -lcrypt
```

The wrapper uses:

- `crypt()`
- or `crypt_r()` when available

If your platform does not provide `crypt`, you can implement a custom backend
by defining:

- `BCRYPT_CUSTOM_BACKEND`

and providing your own hashing functions.

## Quick examples

### Hash a password

```cpp
#define BCRYPT_USE_CRYPT
#include <bcrypt/bcrypt.hpp>

int main()
{
    auto hash = bcrypt::hash_password("my_password");

    if (!hash.ok)
        return 1;

    std::string stored = hash.value;
}
```

### Verify a password

```cpp
#define BCRYPT_USE_CRYPT
#include <bcrypt/bcrypt.hpp>

int main()
{
    std::string stored_hash = "$2b$12$.................";

    auto result =
        bcrypt::verify_password("my_password", stored_hash);

    if (result.ok)
    {
        // password is valid
    }
}
```

### Choose bcrypt cost

```cpp
#define BCRYPT_USE_CRYPT
#include <bcrypt/bcrypt.hpp>

int main()
{
    bcrypt::HashOptions opt;

    opt.cost = 12;

    auto hash =
        bcrypt::hash_password("password", opt);
}
```

## API overview

Main structures:

- `bcrypt::HashOptions`
- `bcrypt::Result`

Main helpers:

- `bcrypt::generate_salt()`
- `bcrypt::hash_password()`
- `bcrypt::hash_password_with_salt()`
- `bcrypt::verify_password()`

Throwing variants:

- `bcrypt::generate_salt_or_throw()`
- `bcrypt::hash_password_or_throw()`
- `bcrypt::verify_password_or_throw()`

## Password hashing workflow

Typical password storage workflow:

1. User provides password
2. Generate bcrypt hash
3. Store hash in database

When user logs in:

1. Verify password against stored hash

Example stored hash:

`$2b$12$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOQRSTUVWX`

The hash includes:

- algorithm
- cost factor
- salt
- hashed password

## Complexity

| Operation | Time complexity |
|----------|-----------------|
| Salt generation | O(1) |
| Password hashing | O(2^cost) |
| Password verification | O(2^cost) |

Higher cost values increase security but also increase computation time.

Typical production values:

- cost 10-12 for web applications
- cost 12-14 for high-security environments

## Design principles

- Deterministic behavior
- Minimal implementation
- Header-only simplicity
- System crypt backend
- Predictable API

This library focuses strictly on bcrypt password hashing.

If you need:

- full authentication frameworks
- user management
- OAuth2
- OpenID Connect

Build them on top of this layer.

## Tests

Run:

```bash
vix build
vix test
```

Tests verify:

- salt generation
- password hashing
- password verification
- cost validation

## License

MIT License\
Copyright (c) Gaspard Kirira

