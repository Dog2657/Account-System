from datetime import timedelta

#This is used to change email (While logged in)
Email_Change_Token_Lifetime = timedelta(minutes=15)


#Used when login in with 2fa email enabled
Email_Auth_Codes_Lifetime = timedelta(minutes=15)

#Used for email validation when activating email 2fa
Email_2fa_Activation_Token_Lifetime = timedelta(minutes=15)

#Used for disableing email 2fa
Email_2fa_Deactivation_Token = timedelta(minutes=15)