from sqlmodel import SQLModel, create_engine

# Azure Database connection string (example for Azure SQL Database)
DATABASE_URL = "mysql+pymysql://adminsql:6EkwFTZqGBv6a5i@harry61551sql.mysql.database.azure.com/sqldatabase"


# Create the engine
engine = create_engine(DATABASE_URL, echo=True)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)
