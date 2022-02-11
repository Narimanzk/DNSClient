import argparse
import socket
import time

from Packet import Packet


if __name__ == "__main__":
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
    
    #Create a socket
    skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    skt.settimeout(timeout)
    # create a packet to send
    client_packet = Packet()
    query = client_packet.create(name, query_type)
    # transfer packet
    start = time.time()

    def transfer(sock, query_packet, retry):    
        if retry > max_retries:
            return None, 1
        try:
            sock.sendto(query_packet, (server, port))
            server_packet = sock.recv(4096)
        except socket.timeout:
            return transfer(sock, query_packet, retry + 1)

         
        return server_packet, 0

    server_packet, error = transfer(skt, query, 0)
    end = time.time()

    # extract the respond
    def response(dns, response, time, error):

        print(f"Dns Client sending request for {name}")
        print(f"Server: {server}")
        print(f"Request type: {query_type}\n")
        
        if error == 1:
            print(f"ERROR   Maximum number of retries {max_retries} exceeded")
            return

        # decode packet
        response = dns.packet(response)
        
        rcode = response['header']['rcode']
        ra = response['header']['ra']
        auth = bool(response['header']['aa'])

        if rcode != 0:
            if rcode == 1:
                print("ERROR\tthe name server cannot interpret the query")
            elif rcode == 2:
                print("ERROR\tthe name server cannot resolve the query")
            elif rcode == 3:
                print("NOTFOUND")
            elif rcode == 4:
                print("ERROR\tthe query is not supported by the server")
            elif rcode == 5:
                print("ERROR\tthe policy is violated. Server request is refused")
            return 

        if ra == 0:
            print("ERROR\trecursive queries are not supported\n")
        

        print(f"Response received after {time} seconds ({retry} retries)")
        section(response['answer'], "Answer", auth)
        section(response['authority'], "Authority", auth)
        section(response['additional'], "Additional", auth)
        


    def section(section, name, auth):

        if len(section) > 0:
            print(f"\n***{name} Section ({len(section)} records)***")
                
        for ans in section:
            if ans['CLASS'] != 1 or ans['RDATA'] == "":
                print("ERROR\tUnexpected response")
                continue 
            if ans["TYPE"] == 1:
                print(f"IP\t{ans['RDATA']}\t{ans['TTL']}\t{auth}")
            elif ans["TYPE"] == 5:
                print(f"CNAME\t{ans['RDATA']}\t{ans['TTL']}\t{auth}")
            elif ans["TYPE"] == 15:
                print(f"MX\t{ans['RDATA']['exchange']}\t{ans['RDATA']['preference']}\t{ans['TTL']}\t{auth}")
            else: 
                print(f"NS\t{ans['RDATA']}\t{ans['TTL']}\t{auth}")

    response(client_packet, server_packet, end - start, error)