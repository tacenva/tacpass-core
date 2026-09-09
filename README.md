# tacpass-core

Core services and domain logic for the Tacenva Password Manager ecosystem.

`tacpass-core` provides the core application services, entities, authentication, authorization, vault management, and access control used by Tacenva Password Manager applications.

It is not a standalone application. It is designed to be used by applications such as [`tacpass-tui`](https://github.com/tacenva/tacpass-tui) and [`tacpassd`](https://github.com/tacenva/tacpassd).

## Features

* Authentication
* User management
* Permission management
* Access control
* Vault management
* Vault access management
* Source of Truth management
* Password record management
* Core domain entities
* Application services
* Local and server-side service integration

## Architecture

`tacpass-core` provides the application and domain layer between the user-facing applications and the database layer.

```text
                    Applications
                         │
              ┌──────────┴──────────┐
              │                     │
       tacpass-tui              tacpassd
              │                     │
              └──────────┬──────────┘
                         │
                         ▼
                 ┌───────────────┐
                 │  tacpass-core │
                 │ Core Services │
                 └───────┬───────┘
                         │
                         ▼
                 ┌───────────────┐
                 │    database   │
                 │ Encrypted DB  │
                 └───────────────┘
```

The terminal application can use `tacpass-core` directly for local operations, while `tacpassd` uses it as the server-side application layer.

## Core Services

The core package provides services for the main password manager functionality.

### Authentication

Handles user authentication and authentication-related operations.

### User Management

Provides operations for managing users and their access within the system.

### Permission Management

Manages permissions and privilege levels used by the access control system.

### Access Control

Provides authorization and permission checks for protected operations.

### Vault Management

Handles creation and management of password vaults and their records.

### Vault Access

Manages access between users, permissions, and password vaults.

## Usage

Add `tacpass-core` as a Go module dependency:

```bash
go get github.com/tacenva/tacpass-core@latest
```

Then import the required packages from your application.

```go
import (
    "github.com/tacenva/tacpass-core/app"
)
```

The exact service dependencies depend on how the consuming application is structured.

## Development

The project requires Go 1.26.5 or later.

Run tests:

```bash
go test ./...
```

Format the source:

```bash
go fmt ./...
```

Update dependencies:

```bash
go mod tidy
```

## Ecosystem

* [`tacpass-tui`](https://github.com/tacenva/tacpass-tui) - Standalone terminal application
* [`tacpassd`](https://github.com/tacenva/tacpassd) - Daemon for online functionality
* [`tacpass-core`](https://github.com/tacenva/tacpass-core) - Core services and domain logic
* [`database`](https://github.com/tacenva/database) - Encrypted database layer

## License

This project is free to use.

See the repository license for details.
