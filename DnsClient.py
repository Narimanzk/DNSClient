import argparse
import socket
import struct
import random
import time

#parse arguments from commandline
parser = argparse.ArgumentParser()

parser.add_argument('-t', action='store', dest='timeout', type=int, default=5)
parser.add_argument('-r', action='store', dest='max_retries', type=int, default=3)
parser.add_argument('-p', action='store', dest='port', type=int, default=53)
parser.add_argument('server', action='store')
parser.add_argument('name', action='store')


mex = parser.add_mutually_exclusive_group(required=False)
mex.add_argument('-mx', action='store_true', default=False, dest='MX')
mex.add_argument('-ns', action='store_true', default=False, dest='NS')

params = parser.parse_args()

timeout = params.timeout
max_retries = params.max_retries
port = params.port
server = params.server[1::]
name = params.name
retry = 0


if params.NS:
    query_type = "NS"
elif params.MX:
    query_type = "MX"
else:
    query_type = "A"

qtype = {'NS': 2, 'MX': 15, 'A': 1, 'CNAME': 5}

#create a socket
skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
skt.settimeout(timeout)


#create a packet
qpckt = b''
dns = struct.pack('>HHHHHH', random.getrandbits(16), 256, 1, 0, 0, 0)

for num in server.split('.'):
    dns += struct.pack('B', len(num))
    for char in num:
        dns += struct.pack('c', char.encode('utf-8'))

dns += struct.pack('B', 0)
dns += struct.pack('>HH', qtype[query_type], 1)

qpckt = dns

#transfering packets
start = time.time()

def transfer(socket, query_packet, retry=0):

    if retry > max_retries:
        return None , 1
    
    try:
        socket.sendto(query_packet, (server, port))
        spkt = skt.recv(4096)
    
    except socket.timeout:
        return transfer(socket, query_packet, retry+1)
    
    return spkt , 0

spkt , error = transfer(skt, qpckt)
end = time.time()

#Print arguments
print("DNS Client sending request for " + name)
print("Server: " + server)
print("Request type: " + query_type)

#Timeout error
if(error == 1):
    print("ERROR: Maximum number of retries " + max_retries + " exceeded.")
    exit


#Parsing packet
def packet(resp):
    pidx = 0

    header = struct.unpack_from(">HHHHHH", resp, pidx)
    print(header)
    flag = header[1]
    qd, an, ns, ar = header[2::]
    qst, pidx = question(resp, pidx + 12)
    ans, pidx = record(resp, pidx, an)
    auth, pidx = record(resp, pidx, ns)
    addit, pidx = record(resp, pidx, ar)

    packet = {
    "header": {
        "id": header[0],
        "qr": (flag & 0x8000) >> 15,
        "opcode": (flag & 0x7800) >> 11,
        "aa": (flag & 0x0400),
        "tc": (flag & 0x200),
        "rd": (flag & 0x100) >> 8,
        "ra": (flag & 0x80) >> 7,
        "z": (flag & 0x70) >> 4,
        "rcode": flag & 0xF,
        "qdcount": qd, 
        "ancount": an,
        "nscount": ns,
        "arcount": ar
        },
    "question": qst,
    "answer": ans,
    "authority": auth,
    "additional": addit
    }
    
    return packet

def question(resp, uidx):
    q , idx = domain(resp, uidx)
    qty, qcls = struct.unpack_from(">HH", resp, idx)
    result = {"question":q, "qtype":qty, "qclass":qcls}
    return result, idx + 4

def domain(resp , idx):
    question = []
    parts = struct.unpack_from(">B", resp, idx)[0]
    idx += 1

    while parts != 0:
        if parts & 0xc0 == 0xc0:
            ptr = (struct.unpack_from(">H", resp, idx - 1)[0]) & 0x3fff
            temp = domain(resp, ptr)[0]
            question.append(temp)
            idx += 1
            break
    
        temp = struct.unpack_from(f">{parts}c", resp, idx)
        temp = b''.join(temp).decode()
        question.append(temp)

        idx += parts
        parts = struct.unpack_from(">B", resp, idx)[0]
        idx += 1
    
    return '.'.join(question), idx

def record(resp, idx, count):
    result = []

    for _ in range(count):
        name, idx = domain(resp, idx)
        atype, aclass, ttl, rdlength = struct.unpack_from(">HHIH", resp, idx)
        idx += 10

        rdata = ""
        if atype == 1:
            nums = struct.unpack_from(">BBBB", resp, idx)
            nums = list(map(str, nums))
            rdata , idx = '.'.join(nums), idx + 4
        elif atype == 2:
            rdata, idx = domain(resp, idx)
        elif atype == 5:
            rdata, idx = domain(resp, idx)
        elif atype == 15: #MX
            pref = struct.unpack_from(">H", resp, idx)
            num = idx + 2
            exch, num = domain(resp, num)
            res = {"preference": pref, "exchange": exch}
            rdata, idx = res, num

        answer = {"NAME": name, "TYPE": atype, "CLASS": aclass, "TTL": ttl,"RDLENGTH": rdlength, "RDATA": rdata}

        result.append(answer)
    
    return result, idx

spkt = packet(spkt)
rcode = spkt['header']['rcode']
ra = spkt['header']['ra']
auth = bool(spkt['header']['aa'])

if rcode != 0:
    if rcode == 1:
        print("Error: the name server was unable to interpret the query")
    elif rcode == 2:
        print("Error: the name server was unable to process this query due to a problem with the name server")
    elif rcode == 3:
        print("NOTFOUND")
    elif rcode == 4:
        print("Error: the name server does not support the requested kind of query")
    elif rcode == 5:
        print("Error: the name server refuses to perform the requested operation for policy reasons")

def section(sec, name, auth):
    if len(sec) > 0:
        print(f"\n***{name} Section ({len(sec)} records)***")

    for ans in sec:
        if ans['CLASS'] != 1 or ans['RDATA'] == "":
            print("Error: Unexpected response")
            continue 
        if ans["TYPE"] == 1:
            print(f"IP\t{ans['RDATA']}\t{ans['TTL']}\t{auth}")
        elif ans["TYPE"] == 5:
            print(f"CNAME\t{ans['RDATA']}\t{ans['TTL']}\t{auth}")
        elif ans["TYPE"] == 15:
            print(f"MX\t{ans['RDATA']['exchange']}\t{ans['RDATA']['preference']}\t{ans['TTL']}\t{auth}")
        else: 
            print(f"NS\t{ans['RDATA']}\t{ans['TTL']}\t{auth}")

if ra == 0:
    print("Error: recursive queries are not supported\n")

    print(f"Response received after {end - start} seconds ({retry} retries)")

        
    section(spkt['answer'], "Answer", auth)
    section(spkt['authority'], "Authority", auth)        
    section(spkt['additional'], "Additional", auth)