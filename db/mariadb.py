# db/mariadb.py
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


class MariaDB:
    def __init__(self):
        self.database_url = os.getenv(
            "DATABASE_URL",
            "mysql+pymysql://api_user:curry010@13.125.217.38:3306/result_db"
        )

        self.engine = create_engine(
            self.database_url,
            pool_pre_ping=True,
            pool_recycle=3600
        )

        self.SessionLocal = sessionmaker(bind=self.engine)

    def get_session(self):
        return self.SessionLocal()
