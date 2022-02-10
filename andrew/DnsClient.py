import argparse

from dns_query import DnsClient


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

    # create a dns client 
    dns_client = DnsClient(params)

    # send the query and display the response
    dns_client.send_query()