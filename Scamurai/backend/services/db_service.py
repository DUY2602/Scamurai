import os
from contextlib import contextmanager

import pymysql


def _db_config() -> dict | None:
    host = os.getenv("MYSQLHOST")
    port = os.getenv("MYSQLPORT")
    user = os.getenv("MYSQLUSER")
    password = os.getenv("MYSQLPASSWORD")
    database = os.getenv("MYSQLDATABASE")

    if not all([host, port, user, password, database]):
        return None

    return {
        "host": host,
        "port": int(port),
        "user": user,
        "password": password,
        "database": database,
        "cursorclass": pymysql.cursors.DictCursor,
        "autocommit": True,
    }


@contextmanager
def get_connection():
    config = _db_config()
    if not config:
        yield None
        return

    connection = pymysql.connect(**config)
    try:
        yield connection
    finally:
        connection.close()
