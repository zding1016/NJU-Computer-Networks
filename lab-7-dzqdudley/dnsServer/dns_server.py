'''DNS Server for Content Delivery Network (CDN)
'''

import sys
from socketserver import UDPServer, BaseRequestHandler
from utils.dns_utils import DNS_Request, DNS_Rcode
from utils.ip_utils import IP_Utils
from datetime import datetime
import math
from fnmatch import fnmatch
from random import randint

import re
from collections import namedtuple


__all__ = ["DNSServer", "DNSHandler"]

class DNS_Record:
    def __init__(self, domain_name, type, value):
        self.name=domain_name
        self.type=type
        self.value=value

class DNSServer(UDPServer):
    def __init__(self, server_address, dns_file, RequestHandlerClass, bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate=True)
        self._dns_table = []
        self.parse_dns_file(dns_file)
        
    def parse_dns_file(self, dns_file):
        # ---------------------------------------------------
        # TODO: your codes here. Parse the dns_table.txt file
        # and load the data into self._dns_table.
        # --------------------------------------------------
        file=open(dns_file)
        line=file.readline()
        while line:
            line=line.strip('\n')
            elements=line.split(" ")
            self._dns_table.append(DNS_Record(elements[0], elements[1], elements[2:]))
            line=file.readline()
        '''
        for item in self._dns_table:
            print(item.name)
            print(item.type)
            print(item.value)
        '''

    @property
    def table(self):
        return self._dns_table


class DNSHandler(BaseRequestHandler):
    """
    This class receives clients' udp packet with socket handler and request data. 
    ----------------------------------------------------------------------------
    There are several objects you need to mention:
    - udp_data : the payload of udp protocol.
    - socket: connection handler to send or receive message with the client.
    - client_ip: the client's ip (ip source address).
    - client_port: the client's udp port (udp source port).
    - DNS_Request: a dns protocl tool class.
    We have written the skeleton of the dns server, all you need to do is to select
    the best response ip based on user's infomation (i.e., location).

    NOTE: This module is a very simple version of dns server, called global load ba-
          lance dns server. We suppose that this server knows all the ip addresses of 
          cache servers for any given domain_name (or cname).
    """
    
    def __init__(self, request, client_address, server):
        self.table = server.table
        super().__init__(request, client_address, server)

    def calc_distance(self, pointA, pointB):
        ''' TODO: calculate distance between two points '''
        return pow(pointA[0]-pointB[0],2)+pow(pointA[1]-pointB[1],2)
    def find_best_ip(self, client_ip, item):
        best_ip = ''
        best_dist = float('inf')
        client_loc = IP_Utils.getIpLocation(client_ip)
        if client_loc == None:
            return item.value[randint(0,len(item.value)-1)]

        for val in item.value:
            server_loc = IP_Utils.getIpLocation(val)
            if server_loc == None:
                continue
            dist = self.calc_distance(client_loc, server_loc)
            if dist < best_dist:
                best_dist = dist
                best_ip = val
        return best_ip

    def get_response(self, request_domain_name):
        response_type, response_val = (None, None)
        # ------------------------------------------------
        # TODO: your codes here.
        # Determine an IP to response according to the client's IP address.
        #       set "response_ip" to "the best IP address".
        client_ip, _ = self.client_address
        found = False
        for item in self.table:
            temp = ''
            if item.name[len(item.name)-1] == '.':
                temp = item.name[:len(item.name)-2]
            else:
                temp = item.name + '.'
            if fnmatch(request_domain_name, item.name) or fnmatch(request_domain_name, temp):
                found=True
                if item.type == "CNAME":
                    response_type = "CNAME"
                    response_val = item.value[0]
                elif item.type == "A":
                    response_type = "A"
                    response_val= self.find_best_ip(client_ip, item)
                break
        if found == False:
            return (None, None)
        # -------------------------------------------------
        return (response_type, response_val)

    def handle(self):
        """
        This function is called once there is a dns request.
        """
        ## init udp data and socket.
        udp_data, socket = self.request

        ## read client-side ip address and udp port.
        client_ip, client_port = self.client_address

        ## check dns format.
        valid = DNS_Request.check_valid_format(udp_data)
        if valid:
            ## decode request into dns object and read domain_name property.
            dns_request = DNS_Request(udp_data)
            request_domain_name = str(dns_request.domain_name)
            self.log_info(f"Receving DNS request from '{client_ip}' asking for "
                          f"'{request_domain_name}'")

            # get caching server address
            response = self.get_response(request_domain_name)

            # response to client with response_ip
            if None not in response:
                dns_response = dns_request.generate_response(response)
            else:
                dns_response = DNS_Request.generate_error_response(
                                             error_code=DNS_Rcode.NXDomain)
        else:
            self.log_error(f"Receiving invalid dns request from "
                           f"'{client_ip}:{client_port}'")
            dns_response = DNS_Request.generate_error_response(
                                         error_code=DNS_Rcode.FormErr)

        socket.sendto(dns_response.raw_data, self.client_address)

    def log_info(self, msg):
        self._logMsg("Info", msg)

    def log_error(self, msg):
        self._logMsg("Error", msg)

    def log_warning(self, msg):
        self._logMsg("Warning", msg)

    def _logMsg(self, info, msg):
        ''' Log an arbitrary message.
        Used by log_info, log_warning, log_error.
        '''
        info = f"[{info}]"
        now = datetime.now().strftime("%Y/%m/%d-%H:%M:%S")
        sys.stdout.write(f"{now}| {info} {msg}\n")
