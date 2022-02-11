import os


def getDNSClient(osVal):
    if osVal == None or len(osVal) ==0: 
        return ""
    else : 
        dns = osVal[0][29:-1]
        return dns

def getServer(osVal):
    if osVal == None or len(osVal) ==0: 
        return ""
    else : 
        server = osVal[1][8:-1]
        return server

def getRequestType(osVal):
    if osVal == None or len(osVal) ==0: 
        return ""
    else : 
        server = osVal[2][8:-1]
        return server




# test request Types default #
cmd = "python3 DnsClient.py @8.8.8.8 www.mcgill.ca"
returned_value = os.popen(cmd).readlines()  # returns the exit code in unix
assert(getRequestType(returned_value)== "type: A")

# test request Types mx #
cmd = "python3 DnsClient.py -mx @8.8.8.8 www.mcgill.ca"
returned_value = os.popen(cmd).readlines()  # returns the exit code in unix
assert(getRequestType(returned_value) == "type: MX")

# test request Types ns #
cmd = "python3 DnsClient.py -ns @8.8.8.8 www.mcgill.ca"
returned_value = os.popen(cmd).readlines()  # returns the exit code in unix
assert(getRequestType(returned_value) == "type: NS")










