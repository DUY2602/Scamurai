"""Small script to verify the Railway database connection and inspect schema."""

from __future__ import annotations

from sqlalchemy import inspect
from sqlalchemy.exc import SQLAlchemyError

from database import check_database_connection, get_database_url, get_engine


def _format_column(column: dict) -> str:
    """Format one reflected column for console output."""
    name = column.get("name", "unknown")
    column_type = str(column.get("type", "unknown"))
    nullable = "NULL" if column.get("nullable", True) else "NOT NULL"
    default = column.get("default")
    default_label = f", default={default}" if default is not None else ""
    return f"    - {name}: {column_type} ({nullable}{default_label})"


def _print_schema() -> None:
    """Print tables and columns currently available in the connected database."""
    inspector = inspect(get_engine())
    tables = inspector.get_table_names()

    if not tables:
        print("No tables found in the current database.")
        return

    print(f"Found {len(tables)} table(s):")
    for table_name in tables:
        print(f"\nTable: {table_name}")
        columns = inspector.get_columns(table_name)
        if not columns:
            print("    - No columns found.")
            continue

        for column in columns:
            print(_format_column(column))


def main() -> int:
    """Run a connection test and print database schema details."""
    try:
        database_url = get_database_url()
        print("Database URL detected.")
        print(f"Driver URL: {database_url}")

        if check_database_connection():
            print("Database connection successful.")
            _print_schema()
            return 0

        print("Database connection check returned False.")
        return 1
    except RuntimeError as exc:
        print(f"Configuration error: {exc}")
        return 1
    except SQLAlchemyError as exc:
        print(f"Database connection failed: {exc}")
        return 1
    except Exception as exc:
        print(f"Unexpected error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
