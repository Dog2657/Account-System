from pymongo.collection import Collection
from bson.objectid import ObjectId
from .db import Database

def formatId(id: str):
    try:
        return ObjectId(id)
    except:
        return None

def getCollation(name: str) -> Collection:
    return Database[name]


class General:
    def __init__(self, Name: str) -> None:
        self.name = Name

    def getCollection(self) -> Collection:
        return getCollation(self.name)
    
    def insert(self, data: dict) -> str:
        return str(self.getCollection().insert_one(data).inserted_id)
    
    def count(self, query: dict, **prams) -> int:
        return self.getCollection().count_documents(query, None, prams)
    
    def exists(self, query: dict) -> bool:
        return self.count(query, limit=1) != 0

    def find(self, query: dict = None, projection: dict = None, id: str = "") -> dict | None:
        if(projection is None):
            projection = {}

        if(query is None):
            query = {}

        if(id):
            query["_id"] = ObjectId(id)

        result = self.getCollection().find_one(query, projection)
        if(result != None):
            result["_id"] = str(result["_id"])

        return result
    
    def findMany(self, query: dict, projection: dict = None, skip: int = 0, limit: int = None) -> dict | None:
        if(projection is None):
            projection = {}

        result = self.getCollection().find(query, projection).skip(skip if skip >= 0 else 0)
        if(limit):
            result = result.limit(limit if limit >= 1 else 1)
        return result
    
    def update(self, update: dict, query: dict = None, id: str = "") -> bool:
        if(query is None):
            query = {}

        if(id):
            query["_id"] = ObjectId(id)
        return self.getCollection().update_one(query, update).modified_count != 0

    def delete(self, query: dict = None, id: str = "") -> bool:
        if(query is None):
            query = {}

        if(id):
            query["_id"] = ObjectId(id)
        return self.getCollection().delete_one(query).deleted_count != 0
    
    def createIndex(self, key: str, **kwargs):
        self.getCollection().create_index(key, **kwargs)

    

class User(General):
    def findByEmail(self, address: str, query: dict = None, projection: dict = None):
        return self.find({**query, "email": address.lower()}, projection)
    
    def findByUsername(self, username: str, query: dict = None, projection: dict = None):
        return self.find({**query, "username": {'$regex': f'^{username}$', "$options": 'i'} }, {projection})
    
    def findBySelector(self, selector: str, projection: dict = None):
        return self.find({'$or': [
            {"email": selector.lower()},
            {"username": {'$regex': f'^{selector}$', "$options": 'i'}}
        ]}, {projection})
    