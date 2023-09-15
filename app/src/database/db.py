from pymongo import MongoClient, collation
from bson.objectid import ObjectId
from core import environment
from sys import exit


Connection = MongoClient("mongodb+srv://{username}:{password}@{cluster_name}.rh3peva.mongodb.net/?retryWrites=true&w=majority".format(
    username=environment.get("DB_Username") or "",
    password=environment.get("DB_Password") or "",
    cluster_name=environment.get("DB_Cluster_Name") or ""
))


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


def formatId(id: str):
    try:
        return ObjectId(id)
    except:
        return None


class DataManager:
    def __init__(self, Name: str, Collection: str) -> None:
        self.DatabaseName = Name
        self.CollectionName = Collection
        self.DB = Connection[self.DatabaseName][self.CollectionName]

    def getCollection(self) -> collation:
        return self.DB
    
    def insert(self, data: dict) -> str:
        return str(self.DB.insert_one(data).inserted_id)
    
    def count(self, query: dict, **prams) -> int:
        return self.DB.count_documents(query, None, prams)
    
    def exists(self, query: dict) -> bool:
        return self.count(query, limit=1) != 0

    def find(self, query: dict = None, projection: dict = None, id: str = "") -> dict | None:
        if(projection is None):
            projection = {}

        if(query is None):
            query = {}

        if(id):
            query["_id"] = ObjectId(id)

        result = self.DB.find_one(query, projection)
        if(result != None):
            result["_id"] = str(result["_id"])

        return result
    
    def findMany(self, query: dict, projection: dict = None, skip: int = 0, limit: int = None) -> dict | None:
        if(projection is None):
            projection = {}

        result = self.DB.find(query, projection).skip(skip if skip >= 0 else 0)
        if(limit):
            result = result.limit(limit if limit >= 1 else 1)
        return result
    
    def update(self, update: dict, query: dict = None, id: str = "") -> bool:
        if(query is None):
            query = {}

        if(id):
            query["_id"] = ObjectId(id)
        return self.DB.update_one(query, update).modified_count != 0

    def delete(self, query: dict = None, id: str = "") -> bool:
        if(query is None):
            query = {}

        if(id):
            query["_id"] = ObjectId(id)
        return self.DB.delete_one(query).deleted_count != 0
    

class TimedDataManager(DataManager):
    def __init__(self, Name: str, Collection: str):
        super().__init__(Name, Collection)
        try:
            self.DB.create_index("expires", expireAfterSeconds=0 )
        except Exception as e:
            print("Unable to create expires index")


class UserManager(DataManager):
    def findUserByEmail(self, address: str, projection: dict = None) -> dict | None:
        return self.find(query={"email": address.lower()}, projection=projection)
    
    def findUserByUsername(self, username: str, projection: dict = None) -> dict | None:
        return self.find({"username": {'$regex': f'^{username}$', "$options": 'i'} }, projection=projection)
    
    def findUserBySelector(self, selector: str, projection: dict = None) -> dict | None:
        return self.find({'$or': [
            {"email": selector.lower()},
            {"username": {'$regex': f'^{selector}$', "$options": 'i'} }
        ]})
    
    