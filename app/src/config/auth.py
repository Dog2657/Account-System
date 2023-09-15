#This is used for how long till access tokens expire
#In hours
Access_Token_Lifetime = 2

#This is used to auth 2fa
#It's swaped to an access token when correctly authed
#In minutes
Twofa_Token_Lifetime = 30


#This used for the "Forgot password" feture
#It's sent as a token on the https://url.com/password-reset/{Token} inside of emails
#In minutes
Password_Reset_Token_Lifetime = 15




#Used for activating time based auth
#In Minutes
Time_2fa_Activation_Token_Lifetime  = 15


#Used to create a new account (External services included)
#In hours
Pending_Accounts_Lifetime_Token = 1

#Used to validate email addresses when making new accounts
#In minutes
Pending_Account_Code_Lifetime = 15

#The token to create an account using a external service
#In minutes
Service_Account_Creation_Lifetime = 15