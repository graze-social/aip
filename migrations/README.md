# Migrations

This directory contains database migrations for AIP's storage implementations.

## Structure

- `sqlite/` - SQLite database migrations
- `postgres/` - PostgreSQL database migrations

## Usage

Migrations are managed using SQLx's migration system. Each migration file should follow the naming convention:

```
YYYYMMDDHHMMSS_description.sql
```

Example:
```
20241216120000_create_users_table.sql
```

## Running Migrations

### SQLite
```bash
sqlx migrate run --database-url sqlite://path/to/database.db --source migrations/sqlite
```

### PostgreSQL
```bash
sqlx migrate run --database-url postgres://user:password@localhost/database --source migrations/postgres
```