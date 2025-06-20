import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sqlalchemy as sa
import sqlalchemy.orm as orm
import logging
from sqlalchemy.orm import Session
from sqlalchemy.ext.declarative import declarative_base


SqlAlchemyBase = declarative_base()

__factory = None
BD_url = None

def global_init(db_url):
    global __factory, DB_url
    DB_url = db_url

    if __factory != None:
        return

    engine = create_engine(db_url, echo=False)
    __factory = sessionmaker(bind=engine)

    # from models import __all_models
    # __all_models.Base.metadata.create_all(engine)


def create_session() -> Session:
    global DB_url
    db_url = DB_url
    engine = create_engine(db_url, echo=False)
    # __all_models.Base.metadata.create_all(engine)
    ss = sessionmaker(bind=engine)()
    return ss
