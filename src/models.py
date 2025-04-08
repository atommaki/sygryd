import os
from sqlalchemy import create_engine, Column, Text, DateTime, Integer, func, Table, MetaData
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base, sessionmaker, deferred
from dotenv import load_dotenv

load_dotenv()

DB_USER =       os.getenv('POSTGRES_USER')
DB_PASSWORD =   os.getenv('POSTGRES_PASSWORD')
DB_HOST =       os.getenv('POSTGRES_HOST', 'localhost')
DB_PORT =       os.getenv('POSTGRES_PORT', '5432')
DB_NAME =       os.getenv('POSTGRES_DB')

DATABASE_URI = f"postgresql+psycopg2://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(DATABASE_URI, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)

Base = declarative_base()

metadata = MetaData()

images_table = Table('images', metadata,
    Column('image',                         Text,       primary_key=True),
    Column('submitted_timestamp',           DateTime,   default=func.current_timestamp()),

    Column('docker_pull_failed',            Integer,    nullable=False),
    Column('docker_pull_failed_timestamp',  DateTime,   nullable=True),

    Column('sbom_timestamp',                DateTime,   nullable=True),
    Column('sbom_json',                     JSONB,      nullable=True),
    Column('sbom_json_size',                Integer,    nullable=True),
    Column('sbom_duration_sec',             Integer,    nullable=True),

    Column('vscan_timestamp',               DateTime,   nullable=True),
    Column('vscan_json',                    JSONB,      nullable=True),
    Column('vscan_json_size',               Integer,    nullable=True),
    Column('vscan_duration_sec',            Integer,    nullable=True),
    Column('vscan_summary',                 JSONB,      nullable=True)
)

class Images(Base):
    __table__ = images_table

    def serialize(self):
        return {
            "image":                        self.image,
            "submitted_timestamp":          self.submitted_timestamp.isoformat() if self.submitted_timestamp else None,

            "docker_pull_failed":           self.docker_pull_failed or 0,
            "docker_pull_failed_timestamp": self.docker_pull_failed_timestamp.isoformat() if self.docker_pull_failed_timestamp else None,

            "sbom_timestamp":               self.sbom_timestamp.isoformat() if self.sbom_timestamp else None,
            "sbom_json":                    self.sbom_json,
            "sbom_json_size":               self.sbom_json_size or 0,
            "sbom_duration_sec":            self.sbom_duration_sec or 0,

            "vscan_timestamp":              self.vscan_timestamp.isoformat() if self.vscan_timestamp else None,
            "vscan_json":                   self.vscan_json,
            "vscan_json_size":              self.vscan_json_size or 0,
            "vscan_duration_sec":           self.vscan_duration_sec or 0,
            "vscan_summary":                self.vscan_summary
        }


class ImagesLight(Base):
    __table__ = images_table

    sbom_json = deferred(images_table.c.sbom_json)
    vscan_json = deferred(images_table.c.vscan_json)

    def serialize(self):
        return {
            "image":                        self.image,
            "submitted_timestamp":          self.submitted_timestamp.isoformat() if self.submitted_timestamp else None,

            "docker_pull_failed":           self.docker_pull_failed or 0,
            "docker_pull_failed_timestamp": self.docker_pull_failed_timestamp.isoformat() if self.docker_pull_failed_timestamp else None,

            "sbom_timestamp":               self.sbom_timestamp.isoformat() if self.sbom_timestamp else None,
            "sbom_json_size":               self.sbom_json_size or 0,
            "sbom_duration_sec":            self.sbom_duration_sec or 0,

            "vscan_timestamp":              self.vscan_timestamp.isoformat() if self.vscan_timestamp else None,
            "vscan_json_size":              self.vscan_json_size or 0,
            "vscan_duration_sec":           self.vscan_duration_sec or 0,
            "vscan_summary":                self.vscan_summary
        }
