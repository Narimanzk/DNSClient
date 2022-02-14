import struct 
import random


class Packet():
    def __init__(self):
        self.client_packet = b''

    def create(self, address, qtype):
        qtypes = {'A': 1, 'NS': 2, 'CNAME': 5, 'MX': 15}
        dns = struct.pack('>HHHHHH', random.getrandbits(16), 256, 1, 0, 0, 0)
        
        for url in address.split('.'):
            dns += struct.pack('B', len(url))
            for c in url:
                dns += struct.pack('c', c.encode('utf-8'))
         
        dns += struct.pack('B', 0)
        dns += struct.pack('>HH', qtypes[qtype], 1)

        self.client_packet = dns 
        return dns 


    def packet(self, response):
        idx = 0

        response_hq = struct.unpack_from(">HHHHHH", response, idx)
        
        qd, an, ns, ar = response_hq[2::]
        flag = response_hq[1]

        question, idx = self.question(response, idx + 12)
        answer, idx = self.record(response, idx, an)
        authority, idx = self.record(response, idx, ns)
        additional, idx = self.record(response, idx, ar)

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
                "qdcount": qd, 
                "ancount": an,
                "nscount": ns,
                "arcount": ar
            },
            "question": question,
            "answer": answer,
            "authority": authority,
            "additional": additional
        }
        return result 


    def question(self, response, index):
        
        question, idx = self.domain(response, index)
        qtype, qclass = struct.unpack_from(">HH", response, idx)

        result = {"question": question, "qtype": qtype , "qclass": qclass}
        return result, idx + 4

    def record(self, response, idx, count):
        answers = []

        for _ in range(count):
            name, idx = self.domain(response, idx)
    
            # unpack TYPE, CLASS, TTL, RDLENGTH
            atype, aclass, ttl, rdlength = struct.unpack_from(">HHIH", response, idx)
            idx += 10

            rdata = ""
            if atype == 1: # IP
                ips = list(map(str, struct.unpack_from(">BBBB", response, idx)))
                rdata, idx = '.'.join(ips), idx + 4
            elif atype == 2: # NS
                rdata, idx = self.domain(response, idx)
            elif atype == 5: # CNAME
                rdata, idx = self.domain(response, idx)
            elif atype == 15: #MX
                preference = struct.unpack_from("!H", response, idx)[0]
                exchange, idx = self.domain(response, idx + 2)
                rdata = {"preference": preference, "exchange": exchange}
                
        
            result = {"NAME": name, "TYPE": atype, "CLASS": aclass, "TTL": ttl, "RDLENGTH": rdlength, "RDATA": rdata}

            answers.append(result)

        return answers, idx

    def domain(self, response, idx):
        question = []
        
        part = struct.unpack_from(">B", response, idx)[0]
        idx += 1
        
        while part != 0:
            if part & 0xc0 == 0xc0: 
                ptr = (struct.unpack_from(">H", response, idx - 1)[0]) & 0x3fff
                temp = self.domain(response, ptr)[0]
                
                question.append(temp)
                idx += 1
                break
            
            temp = struct.unpack_from(f">{part}c", response, idx)
            temp = b''.join(temp).decode()
            question.append(temp)

            idx += part 
            part = struct.unpack_from(">B", response, idx)[0]
            idx += 1
        
        return '.'.join(question), idx  

