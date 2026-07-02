"""User-space dev Postgres for machines without Docker.

Downloads the zonky embedded-postgres binaries (official PostgreSQL build,
plain tarball from Maven Central), then manages a local cluster with
initdb/pg_ctl over a unix socket. No root required.

Usage:
    uv run python scripts/devdb.py start   # download if needed, init, start, print URLs
    uv run python scripts/devdb.py stop
    uv run python scripts/devdb.py url     # print SQLAlchemy URL for hyproxy_DB_URL
    uv run python scripts/devdb.py status
"""

import asyncio
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

import asyncpg

PG_VERSION = "17.5.0"
JAR_URL = (
    "https://repo1.maven.org/maven2/io/zonky/test/postgres/"
    f"embedded-postgres-binaries-linux-amd64/{PG_VERSION}/"
    f"embedded-postgres-binaries-linux-amd64-{PG_VERSION}.jar"
)

DEV_DIR = Path(__file__).resolve().parent.parent / ".dev"
PG_HOME = DEV_DIR / f"pg-{PG_VERSION}"
DATA_DIR = DEV_DIR / "pgdata"
SOCKET_DIR = DEV_DIR / "pgsocket"
LOG_FILE = DEV_DIR / "postgres.log"
DATABASES = ("hyproxy", "hyproxy_test")


def bin_path(name: str) -> str:
    return str(PG_HOME / "bin" / name)


def ensure_binaries() -> None:
    if (PG_HOME / "bin" / "postgres").exists():
        return
    DEV_DIR.mkdir(parents=True, exist_ok=True)
    jar = DEV_DIR / "pg.jar"
    print(f"downloading postgres {PG_VERSION} binaries...", file=sys.stderr)
    urllib.request.urlretrieve(JAR_URL, jar)  # noqa: S310 (fixed https URL)
    with zipfile.ZipFile(jar) as zf:
        txz_name = next(n for n in zf.namelist() if n.endswith(".txz"))
        zf.extract(txz_name, DEV_DIR)
    PG_HOME.mkdir(parents=True, exist_ok=True)
    with tarfile.open(DEV_DIR / txz_name) as tf:
        tf.extractall(PG_HOME, filter="data")
    jar.unlink()
    (DEV_DIR / txz_name).unlink()


def ensure_cluster() -> None:
    if (DATA_DIR / "PG_VERSION").exists():
        return
    subprocess.run(
        [bin_path("initdb"), "-D", str(DATA_DIR), "-U", "postgres", "-A", "trust", "-E", "UTF8"],
        check=True,
        capture_output=True,
    )


def is_running() -> bool:
    res = subprocess.run([bin_path("pg_ctl"), "status", "-D", str(DATA_DIR)], capture_output=True)
    return res.returncode == 0


def start() -> None:
    SOCKET_DIR.mkdir(parents=True, exist_ok=True)
    if not is_running():
        opts = f"-c listen_addresses='' -c unix_socket_directories={SOCKET_DIR}"
        subprocess.run(
            [
                bin_path("pg_ctl"),
                "start",
                "-D",
                str(DATA_DIR),
                "-l",
                str(LOG_FILE),
                "-w",
                "-o",
                opts,
            ],
            check=True,
        )
    asyncio.run(ensure_databases())


async def ensure_databases() -> None:
    # The zonky distribution ships no psql; use asyncpg over the unix socket.
    conn = await asyncpg.connect(host=str(SOCKET_DIR), user="postgres", database="postgres")
    try:
        for name in DATABASES:
            row = await conn.fetchval("SELECT 1 FROM pg_database WHERE datname = $1", name)
            if row != 1:
                await conn.execute(f'CREATE DATABASE "{name}"')
    finally:
        await conn.close()
    for name in DATABASES:
        db_conn = await asyncpg.connect(host=str(SOCKET_DIR), user="postgres", database=name)
        try:
            for ext in ("pgcrypto", "citext"):
                await db_conn.execute(f"CREATE EXTENSION IF NOT EXISTS {ext}")
        finally:
            await db_conn.close()


def sqlalchemy_url(db: str) -> str:
    return f"postgresql+asyncpg://postgres@/{db}?host={SOCKET_DIR}"


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "start"
    if cmd == "stop":
        if is_running():
            subprocess.run(
                [bin_path("pg_ctl"), "stop", "-D", str(DATA_DIR), "-m", "fast"], check=True
            )
        print("stopped")
        return 0
    if cmd == "status":
        print(
            "running" if (PG_HOME / "bin" / "postgres").exists() and is_running() else "not running"
        )
        return 0

    ensure_binaries()
    ensure_cluster()
    start()
    if cmd == "url":
        print(sqlalchemy_url("hyproxy"))
    else:
        print("dev:  hyproxy_DB_URL=" + sqlalchemy_url("hyproxy"))
        print("test: hyproxy_TEST_DB_URL=" + sqlalchemy_url("hyproxy_test"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
