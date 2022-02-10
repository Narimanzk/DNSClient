import socket 
import time 

from dns_packet import DnsPacket

class DnsClient():
    ''' 
    A class that establishes a UDP socket connection to 
    a DNS server and send a query to that socket

    Attributes
    ----------
    timeout : int
        socket timeout
    max_retires : int
        maximum number of retries
    port : int
        port number
    query_type : string
        query type
    server : string
        ip address of the DNS server
    name : string
        domain name
    '''
    def __init__(self, params):
        self.timeout = params.timeout
        self.max_retries = params.max_retries
        self.port = params.port
        self.server = params.server[1::]
        self.name = params.name
        
        self.query_type = "A"
        if params.NS:
            self.query_type = "NS"
        if params.MX:
            self.query_type = "MX"

        self.retry = 0

    
    def send_query(self):
        ''' Creates a socket instance and send a DNS packet through it
        '''
        # initialize the socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)

        # build a dns packet
        dns = DnsPacket()
        query_packet = dns.build_packet(self.name, self.query_type)

        # send and receive
        start = time.time()
        server_packet, error_code = self.send(sock, query_packet)
        end = time.time()

        # decode and print response
        self.print_response(dns, server_packet, end - start, error_code)

    
    def send(self, sock, query_packet, retry=0):
        ''' Send a packet through a socket intance
        Retry a certain number of times if faillure occur

        Parameters
        ----------
        sock : socket
            a socket instance
        query_packet : bytes
            packet in bytes
        retry : int
            the number of current retry cycle
        
        Returns
        -------
        server_packet : bytes
            packet received in bytes
        '''
        # update self.retry
        self.retry = retry 

        # if retry more than expected
        if retry > self.max_retries:
            return None, 1
        try:
            # send the packet
            sock.sendto(query_packet, (self.server, self.port))
            # get the response
            server_packet = sock.recv(4096)
        except socket.timeout:
            # retry if socket timeout
            return self.send(sock, query_packet, retry + 1)
       
        # return the response 
        return server_packet, 0

    
    def print_response(self, dns, response, interval, error_code):
        ''' Format the response and print it to stdout

        Parameters
        ----------
        dns : DnsClient
            a DnsClient instance
        response : dict
            a dictionary that store the response
        interval : float
            timelapse from sending to receiving
        error_code : int
            error code
        '''
        print(f"DnsClient sending request for {self.name}")
        print(f"Server: {self.server}")
        print(f"Request type: {self.query_type}\n")

        # check if timeout
        if error_code == 1:
            print(f"Error: Maximum number of retries {self.max_retries} exceeded")
            return 

        # decode packet
        response = dns.unpack_packet(response)
        # get rcode, ra, and aa
        rcode = response['header']['rcode']
        ra = response['header']['ra']
        auth = bool(response['header']['aa'])
            
        # check if packet error
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
            return 

        # check if support the server support recursive query
        if ra == 0:
            print("Error: recursive queries are not supported\n")

        # print timelapse
        print(f"Response received after {interval} seconds ({self.retry} retries)")

        # print answer section
        self.print_section(response['answer'], "Answer", auth)
            
        # print authority section
        self.print_section(response['authority'], "Authority", auth)
            
        # print additional section
        self.print_section(response['additional'], "Additional", auth)
        


    def print_section(self, section, section_name, auth):
        ''' Print the records in a section

        Parameters
        ----------
        count : int
            number of records
        section : dict
            dictionary of records
        section_name : dict
            name of the section
        auth : boolean
            auth or not
        '''
        if len(section) > 0:
            print(f"\n***{section_name} Section ({len(section)} records)***")
                
        for ans in section:
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
        

    def print_error(self, error_code):
        ''' Print error according to error code

        Parameters
        ----------
        error_code : int
            error code
        '''
        if error_code == 1:
            print("Error: the name server was unable to interpret the query")
        elif error_code == 2:
            print("Error: the name server was unable to process this query due to a problem with the name server")
        elif error_code == 3:
            print("NOTFOUND")
        elif error_code == 4:
            print("Error: the name server does not support the requested kind of query")
        elif error_code == 5:
            print("Error: the name server refuses to perform the requested operation for policy reasons")