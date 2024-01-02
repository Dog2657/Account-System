from pymongo import MongoClient, collation
from bson.objectid import ObjectId
from core import environment
from sys import exit


Connection = MongoClient("mongodb+srv://{username}:{password}@{cluster_name}.rh3peva.mongodb.net/?retryWrites=true&w=majority".format(
    username=environment.get("DB_Username") or "",
    password=environment.get("DB_Password") or "",
    cluster_name=environment.get("DB_Cluster_Name") or ""
))

Database = Connection["primary"]


try:
    Connection.admin.command('ping')
except Exception as e:
    print(f"""\n-------------------
Database failed to connect: \n
Details:
    Username: {environment.get("DB_Username")}
    Password: {"*" * len(environment.get("DB_Password")) if environment.get("DB_Password") else None} 
    Cluster Name: {environment.get("DB_Cluster_Name")}\n
Error: \n   {e}
\n-------------------\n""")
    exit(1)