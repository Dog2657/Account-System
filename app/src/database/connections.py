from .db import DataManager, UserManager, TimedDataManager

UserDB = UserManager("Auth", "Users")
PendingUserDB = TimedDataManager("Auth", "Pending")
AuthCodesDB = TimedDataManager("Auth", "Codes")
invalidAccessTokensDB = TimedDataManager("Auth", "LoggedOutTokens")