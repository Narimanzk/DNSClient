import struct 
import random

QType = {
    'A': 1, 
    'NS': 2, 
    'MX': 15,
    'CNAME': 5
}

class DnsPacket():
    '''
    A class that builds a dns packet and
    analyze the response packet 
    '''
    def __init__(self):
        self.client_packet = b'' # dns packet

    def build_packet(self, address, query_type):
        '''Build a DNS package given address and question type

        Parameters
        ----------
        address : str
            address string
        query_type : str
            question type

        Returns
        -------
        dns : bytes
            bytes object represents a dns packet 
        '''

        # contruct the packet's header: id, flag, qdcount, ancount, nscount, arcount 
        dns = struct.pack('>HHHHHH', random.getrandbits(16), 256, 1, 0, 0, 0)

        # construct the packet's body
        # split address by '.' character
        url_list = address.split('.')
        # loop through each sub url and add it to dns
        for url in url_list:
            # add the length of this url
            dns += struct.pack('B', len(url))
            # add the url
            for c in url:
                # add an encoded character in url
                dns += struct.pack('c', c.encode('utf-8'))
        
        # add end of data 
        dns += struct.pack('B', 0)

        # add query type and query class 
        dns += struct.pack('>HH', QType[query_type], 1)

        # store dns
        self.client_packet = dns 

        # return the packet
        return dns 


    def unpack_packet(self, response):
        '''
        Decode a dns response packet

        Parameters
        ----------
        response : bytes
            bytes object represents a dns response packet

        Returns
        -------
        dict
        '''
        result = {} # dictionary to store data
        
        # intialize unpack index
        unpack_index = 0

        # unpack response header, 6 H from 0 index
        response_hq = struct.unpack_from(">HHHHHH", response, unpack_index)
        
        qdcount, ancount, nscount, arcount = response_hq[2::]

        # header flags
        flag = response_hq[1]

        # unpack question
        question, unpack_index = self.unpack_question(response, unpack_index + 12)

        # unpack answer section
        answer, unpack_index = self.unpack_record(response, unpack_index, ancount)

        # unpack authority section
        authority, unpack_index = self.unpack_record(response, unpack_index, nscount)

        # unpack additionals section
        additional, unpack_index = self.unpack_record(response, unpack_index, arcount)

        result = {
            "header": {
                "id": response_hq[0],
                "qr": (flag & 0x8000) >> 15,
                "opcode": (flag & 0x7800) >> 11,
                "aa": (flag & 0x0400),
                "tc": (flag & 0x200),
                "rd": (flag & 0x100) >> 8,
                "ra": (flag & 0x80) >> 7,
                "z": (flag & 0x70) >> 4,
                "rcode": flag & 0xF,
                "qdcount": qdcount, 
                "ancount": ancount,
                "nscount": nscount,
                "arcount": arcount
            },
            "question": question,
            "answer": answer,
            "authority": authority,
            "additional": additional
        }

        # return result
        return result 


    def unpack_question(self, response, unpack_index):
        ''' Unpack the question section

        Parameters
        ----------
        response : bytes
            response in bytes
        unpack_index : int
            index to start unpacking from 
        
        Returns
        -------
        result : dict
        unpack_index : int
            index stop
        '''
        # unpack question
        question, index = self.unpack_domain(response, unpack_index)

        # unpack qtype and qclass
        qtype, qclass = struct.unpack_from(">HH", response, index)

        # build result
        result = {
            "question": question,
            "qtype": qtype ,
            "qclass": qclass
        }

        return result, index + 4


    def unpack_domain(self, response, unpack_index):
        ''' Unpack domain name

        Parameters
        ----------
        response : bytes
        unpack_index : int

        Returns
        -------
        name : str
            domain name
        unpack_index : int
        '''
        index = unpack_index

        # extract question 
        question = []
        # get first 8 bits
        part = struct.unpack_from(">B", response, index)[0]
        index += 1
        while part != 0:
            # check if this is a pointer - two 1s from the left
            if part & 0xc0 == 0xc0: 
                # get pointer value - 14 bits from the right
                pointer = (struct.unpack_from(">H", response, index - 1)[0]) & 0x3fff
                # get part this pointer points to 
                temp_part = self.unpack_domain(response, pointer)[0]
                # update question
                question.append(temp_part)
                # increment index
                index += 1
                break
            
            # if this is a regular name
            temp_part = struct.unpack_from(f">{part}c", response, index)
            temp_part = b''.join(temp_part).decode()
            question.append(temp_part)

            # update index 
            index += part 
            
            # move to next part
            part = struct.unpack_from(">B", response, index)[0]

            # update index
            index += 1
        
        return '.'.join(question), index     


    def unpack_record(self, response, unpack_index, count):
        ''' Unpack a section (answer, authority, additional)

        Parameters
        ----------
        response : bytes
        unpack_index : int
        count : int
            number of records

        Returns
        -------
        result : dict
            dictionary of records
        unpack_index : int
        '''
        # start index 
        index = unpack_index

        # arrays to store all answers
        answers = []

        for _ in range(count):
            # unpack NAME
            name, index = self.unpack_domain(response, index)
    
            # unpack TYPE, CLASS, TTL, RDLENGTH
            atype, aclass, ttl, rdlength = struct.unpack_from(">HHIH", response, index)
            # update index
            index += 10

            # unpack RDATA
            rdata = ""
            if atype == 1: # IP
                rdata, index = self.unpack_ip(response, index)
            elif atype == 2: # NS
                rdata, index = self.unpack_ns(response, index)
            elif atype == 5: # CNAME
                rdata, index = self.unpack_cname(response, index)
            elif atype == 15: #MX
                rdata = self.unpack_ms(response, index)
        
            result = {
                "NAME": name, 
                "TYPE": atype,
                "CLASS": aclass, 
                "TTL": ttl,
                "RDLENGTH": rdlength,
                "RDATA": rdata 
            }

            answers.append(result)

        return answers, index 

    
    def unpack_ip(self, message, index):
        ''' Unpack an IP address

        Paramters
        ---------
        message : bytes
        index: int

        Returns
        -------
        ip : string
        unpack_index : int
        '''
        ip_list = struct.unpack_from(">BBBB", message, index)
        ip_list = list(map(str, ip_list))
        return '.'.join(ip_list), index + 4


    def unpack_ns(self, message, index):
        ''' Unpack an NS record

        Paramters
        ---------
        message : bytes
        index: int

        Returns
        -------
        name : string
        unpack_index : int
        '''
        name, index = self.unpack_domain(message, index)
        return name, index 

    def unpack_cname(self, message, index):
        ''' Unpack an CNAME record

        Paramters
        ---------
        message : bytes
        index: int

        Returns
        -------
        name : string
        unpack_index : int
        '''
        return self.unpack_ns(message, index)

    def unpack_mx(self, message, index):
        ''' Unpack an MX record

        Paramters
        ---------
        message : bytes
        index: int

        Returns
        -------
        name : string
        unpack_index : int
        '''
        # unpack preference 
        preference = struct.unpack_from(">H", message, index)
        index += 2

        # unpack exchange
        exchange, index = self.unpack_domain(message, index)
        
        result = {
            "preference": preference,
            "exchange": exchange 
        }

        return result, index 