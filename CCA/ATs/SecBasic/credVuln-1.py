def readAccount(matchIndex):
    # Get basic info
    match = matches[matchIndex]
    username = matches[matchIndex + 1]

    # Go till secret or password location
    while (not match == "secret") and (not match == "password"):
        matchIndex = matchIndex + 1
        match = matches[matchIndex]
    
    authType = match
    authSec = matches[matchIndex+1]
    authSecName = ""
    if authSec == "0":
        Out(OutSev.Critical, "The account \"%s\" has credentials stored in plaintext. This is extremely insecure.\nYou should use scrypt." % (username))
    elif authSec == "5":
        Out(OutSev.Warning, "The account \"%s\" has credentials stored with MD5. MD5 is now a weak algorithm.\nYou should use scrypt." % (username))
    elif authSec == "7":
        Out(OutSev.Warning, "The account \"%s\" has credentials stored with Type 7 encryption. Type 7 is just obfuscation.\nYou should use scrypt." % (username))

for matchIndex in range(len(matches)):
    match = matches[matchIndex]

    if match == "username":
        readAccount(matchIndex)