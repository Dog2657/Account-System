from . import managers


UserDB = managers.User("Users")

PendingUserDB = managers.General("Pending")
PendingUserDB.createIndex("expires",  expireAfterSeconds = 0)

AuthCodesDB = managers.General("Codes")
AuthCodesDB.createIndex("expires",  expireAfterSeconds = 0)

invalidAccessTokensDB = managers.General("LoggedOutTokens")
invalidAccessTokensDB.createIndex("expires",  expireAfterSeconds = 0)