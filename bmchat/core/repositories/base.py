"""Repository base — abstração da camada de dados."""
from typing import Any


class BaseRepository:
    """Repositório base com acesso ao Database.

    Fornece helpers comuns e garante que operações sejam
    feitas via Database (thread-safe com lock interno).
    """

    def __init__(self, db):
        self.db = db

    def query(self, sql: str, params: tuple = ()):
        return self.db.query(sql, params)

    def execute(self, sql: str, params: tuple = ()):
        return self.db.execute(sql, params)
