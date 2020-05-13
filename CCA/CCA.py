from colorama import Fore, Style, Back # for pretty printouts made ez
from sys import argv, exit, stdout, path # for args
import paramiko # for ssh and config retrival
import base64
import io
import json
from time import sleep
import socket
import re
from enum import Enum

## Log Levels
OutputLevel = 3
class OutSev(Enum):
    Critical = 0
    Error = 1
    Warning = 2
    Info = 3
    Debug = 4
##

def Out(Sev, Message, File=False):
    # Add file implementation for scripting usage
    if type(Sev) == str:
        print(Message)
        return   

    if(Sev.value <= OutputLevel):

        if(Sev == OutSev.Critical):
            print(" %s%s[%s]%s%s %s" % ((Fore.RED, Style.BRIGHT, Sev.name, Fore.WHITE, Style.NORMAL, Message)))
        elif(Sev == OutSev.Error):
            print(" %s%s[%s]%s%s %s" % ((Fore.RED, Style.NORMAL, Sev.name, Fore.WHITE, Style.NORMAL, Message)))
        elif(Sev == OutSev.Warning):
            print(" %s%s[%s]%s%s %s" % ((Fore.YELLOW, Style.NORMAL, Sev.name, Fore.WHITE, Style.NORMAL, Message)))
        elif(Sev == OutSev.Info):
            print(" %s%s[%s]%s%s %s" % ((Fore.WHITE, Style.NORMAL, Sev.name, Fore.WHITE, Style.NORMAL, Message)))
        elif(Sev == OutSev.Debug):
            print(" %s%s[%s]%s%s %s" % ((Fore.CYAN, Style.NORMAL, Sev.name, Fore.WHITE, Style.NORMAL, Message))) 

        stdout.flush()
        return
    else:
        # ignored
        return 

##### ARG HANDLING #####

Out(OutSev.Info, "Parsing arguments and settings...")

### USAGE ###
usageText = '''Usage:
CCA.py -a <ip> -r <port> -u <username> -p <password>
Individual:
\t-a   --address
\t\tThe target device to get the config from.
\t-r   --port
\t\tThe target device port.
\t-u   --user
\t\tThe target device username to connect with.
\t-p   --pass
\t\tThe target device password for username to connect with.

Import:

Arguments:
\t-h  --help
\t\tPrint out the usage message. You are looking at it right now!
\t-o  --output <0-4>
\t\tLogging level.
\t-t   --timeout <1-10>
\t\tSSH connection timeout.
\t--knownhost
\t\tUnknown hosts will not be connected to.
'''

def usage():
    print(usageText)
### USAGE ####

### PARSING ###
def matchAny(src, matches, caseSensitive=False):
    for possibleMatch in matches:
        if caseSensitive:
            if possibleMatch == src:
                return 1
        else:
            if possibleMatch.lower() == src.lower():
                return 1
    return 0

## Args
strictKnownHostPolicy=False
noPaging=True
newOutputLevel = OutputLevel # Send all read outs during parsing, but new var to store new output level
RootATPolicyLocation = path[0] + "/ATs/"
ATPolicyName = "SecBasic.json"
ATPolicy = RootATPolicyLocation + ATPolicyName
timeout = 3

## Individual Args
addr=""
port=22
user=""
passwd=""

## Import Args
skipCount = 0
for argIndex in range(1, len(argv)):
    if skipCount > 0:
        skipCount = skipCount - 1
        continue

    arg = argv[argIndex]

    if matchAny(arg, {"-h", "--help"}):
        usage()
        exit(0)
    elif matchAny(arg, {"-a", "--address"}):
        addr = argv[argIndex + 1]
        skipCount = skipCount + 1
    elif matchAny(arg, {"-r", "--port"}):
        port = int(argv[argIndex + 1])
        skipCount = skipCount + 1
    elif matchAny(arg, {"-u", "--user"}):
        user = argv[argIndex + 1]
        skipCount = skipCount + 1
    elif matchAny(arg, {"-p", "--pass"}):
        passwd = argv[argIndex + 1]
        skipCount = skipCount + 1
    elif matchAny(arg, {"-t", "--timeout"}):
        try:
            timeout = argv[argIndex + 1]
        except IndexError as ie:
            Out(OutSev.Critical, "No timeout value given.")
            usage()
            exit(0)

        try:
            timeout = int(timeout)

            if newOutputLevel < 1 or newOutputLevel > 10:
                Out(OutSev.Critical, "Invalid timeout value given.")
                usage()
                exit(0)

            Out(OutSev.Info, "Setting the new timeout level to: %s" % (timeout))
        except Exception as e:
            Out(OutSev.Critical, "Failed to parse new timeout value.")
            usage()
            exit(0)

        skipCount = skipCount + 1
    elif matchAny(arg, {"-o", "--output"}):
        try:
            newOutputLevel = argv[argIndex + 1]
        except IndexError as ie:
            Out(OutSev.Critical, "No log level given.")
            usage()
            exit(0)

        try:
            newOutputLevel = int(newOutputLevel)

            if newOutputLevel > 4 or newOutputLevel < 0:
                Out(OutSev.Critical, "Invalid new log level given.")
                usage()
                exit(0)

            Out(OutSev.Info, "Setting the new output level to: %s" % (OutSev(newOutputLevel).name))
        except Exception as e:
            Out(OutSev.Critical, "Failed to parse new log level.")
            usage()
            exit(0)
        
        skipCount = skipCount + 1
    elif matchAny(arg, {"--knownhost"}):
        Out(OutSev.Info, "")
    else:
        print("Unable to parse \"%s\"\n%s" % (arg, usage()))
### PARSING ###

### AT LOADING ###
Out(OutSev.Info, "Loading Analysis Template Policy \"%s\"..." % (ATPolicyName))
ATPJSON = ""
with open(ATPolicy, "r") as tmpATPFile:
    for line in tmpATPFile.readlines():
            ATPJSON = ATPJSON + line
Out(OutSev.Info, "Analysis Template Policy Loaded.")
Out(OutSev.Info, "Parsing Analysis Template Policy...")
ATP = json.loads(ATPJSON)
Out(OutSev.Info, "Analysis Template Policy Parsed.")
### AT LOADING ###

Out(OutSev.Info, "Arguments and settings parsed.")
OutputLevel = newOutputLevel # Set new log level

Out("", "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

##### ARG HANDLING #####

##### APP #####

### SSH ###
def genSSH(dstAddr, dstPort, username, password):
    # Parse address
    if not type(dstAddr) == str:
        Out(OutSev.Error, "Unable to connect to device due to invalid address.")
        raise Exception(src1="genSSH", src2="dstAddr", value="String is required.")

    # Get SSH
    ssh = paramiko.SSHClient()

    # Handle Host Known Policies
    if not strictKnownHostPolicy:
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        Out(OutSev.Error, "Unable to connect to device due to unknown host.")
        raise Exception(src1="genSSH", src2="knownHostPolicy", value="String is required.")

    # Connect
    try:
        # allow_agent=False,look_for_keys=False prevents errors caused by paramiko looking for SSH keys even when using passwd auth
        ssh.connect(dstAddr, port=dstPort, username=username, password=password, auth_timeout=timeout, allow_agent=False, look_for_keys=False)
    except socket.error as e:
        if e.errno == 49:
            Out(OutSev.Error, "Unable to connect to device due to failure to assign requested address.")
            raise Exception(src1="genSSH", src2="connect", value="Failure to Assign requested address.")
        else:
            Out(OutSev.Critical, "An unexpected error %s () has occured." % (e.errno))

    # Get Channel
    channel = ssh.invoke_shell()

    # Handle Paging
    if noPaging:
        channel.send("terminal length 0\n")

    # Clear Channel
    sleep(1)
    out = channel.recv(9999)
    sleep(1)
        
    return ssh, channel

def closeSSH(ssh):
    ssh.close()

def getHostname(channel):
    resp = execCMD(channel, "\n")
    resp = resp.replace("\r\n", "").replace("#", "")
    return resp

startStr = "Current configuration :"
endStr = "end\r\n"
def getCFG(channel):
    resp = execCMD(channel, "show run\n")
    #print(resp.encode("unicode_escape"))
    startIndex = resp.index(startStr)
    endIndex = resp.index(endStr) + (len(endStr) - 2) # -2 to remove the \r\n
    resp = resp[startIndex:endIndex]
    return resp

def execCMD(channel,cmd):
    sendRequest(channel,cmd)
    resp = getResponse(channel)
    return resp

def sendRequest(channel, cmd):
    sleep(0.5) # incase send_ready is not updated yet
    while not channel.send_ready():
        sleep(0.5)
    channel.send(cmd)


def getResponse(channel):
    sleep(0.5) # incase recv_ready is not updated yet
    while not channel.recv_ready():
        sleep(0.5)
    resp = channel.recv(99999)
    resp = (''.join(resp.decode('ascii').split(',')))
    #print(resp.encode('unicode_escape').decode("ascii"))
    if not resp.endswith("#"):
        return getResponse(channel)
    else:
        return resp

### SSH ###

### Execute ATs ###
def readAll(fileName):
    final = ""
    with open(fileName, "r") as file:
        for line in file.readlines():
            final = final + line + "\n"
    return final
    
matches = ""
def checkPolicies(cfg):
    for ATT1 in ATP:
        Out(OutSev.Debug, "Checking Policy \"%s\"..." % (ATP[ATT1]["name"]))
        global matches # needed for external code to utilize
        matches = re.findall(ATP[ATT1]["match"], cfg)
        if not matches == None:
            execCode = readAll(RootATPolicyLocation + ATP[ATT1]["exec"])
            exec(execCode)
### Execute ATs ###

### Run on Devices ###
def checkDevice(ip, port, user, passwd):
    try:
        hostname = "" # Set to nothing so I dont have to deal with unrefrenced assignments and try catches later...
        Out(OutSev.Debug, "Connecting to \"%s:%s\"..." % (ip, port))
        session, channel = genSSH(ip, port, user, passwd)
        hostname = getHostname(channel)
        Out(OutSev.Debug, "Connected to \"%s\" (%s:%s)." % (hostname, ip, port))
        Out(OutSev.Debug, "Downloading CFG from \"%s\" (%s:%s)..." % (hostname, ip, port))
        cfg = getCFG(channel)
        Out(OutSev.Debug, "CFG Downloaded from \"%s\" (%s:%s)." % (hostname, ip, port))
        return cfg, hostname 
    except Exception as e:
        if hostname == "":
            Out(OutSev.Error, "Failed to Connect to \"%s:%s\"." % (ip, port))
        else: 
            Out(OutSev.Error, "Failed to Connect to \"%s\" (%s:%s)." % (hostname, ip, port))

if not addr == "":
    Out(OutSev.Info, "Starting on \"%s:%s\"..." % (addr, port))
    try:
        cfg, hostname = checkDevice(addr, port, user, passwd)
        checkPolicies(cfg)
        Out(OutSev.Info, "Finished on \"%s\" (%s:%s)." % (hostname, addr, port))
    except:
        Out(OutSev.Error, "Error on \"%s:%s\"..." % (addr, port))
    
### Run on Devices ###

##### APP #####