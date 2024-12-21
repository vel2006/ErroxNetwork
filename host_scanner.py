from kamene.all import Ether, ARP, IP, ICMP, conf, sr, srp
class PortScannerError(Exception):
    def __init__(self, error_message):
        super().__init__(error_message)
class PortScanner():
    def __init__(self):
        self.MAX_PROCESSES = 10
        self.conf = False
        self.SML_LIST = (7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 
        199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027,
        1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000,
        5009, 5051, 5060, 5101, 5109, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081,
        8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157)
        self.MED_LIST = (1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42, 43, 53, 70, 79, 80, 81, 82,
        83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212,
        222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443, 444, 445, 458, 464, 465,
        481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648,
        666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 873, 880,
        888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 6069, 6070)
    def syn_scan_port(self, destination_ip:str, destination_port:int, timeout_length:int):
        """
            \'syn_scan_port\' will do a scan on target device port. Returns True if the device responded, False if the device did not respond
            Below are the arguments explained:
                \'destination_ip\':str is an argument that will set the target IPv4 address to scan
                \'destination_port\':int is an argument that will set the target port to scan
                \'timeout_length\':int is an argument that will set the timeout_length for the TCP connection
        """
        answered, unanswered = sr1(IP(dst=destination_ip, ttl=64)/TCP(dport=destination_port, flags='s'), timeout=timeout_length)
        if answered:
            return True
        return False
    def ack_scan_port(self, destination_ip:str, destination_port:int, timeout_length:int):
        """
            \'udp_scan_port\' will do a scan on target device port. Returns True if the device responded, False if the device did not respond
            Below are the arguments explained:
                \'destination_ip\':str is an argument that will set the target IPv4 address to scan
                \'destination_port\':int is an argument that will set the target port to scan
                \'timeout_length\':int is an argument that will set the timeout_length for the TCP connection
        """
        answered, unanswered = sr1(IP(dst=destination_ip, ttl=64)/TCP(dport=destination_port, flags='a'), timeout=timeout_length)
        if answered:
            return True
        return False
    def udp_scan_port(self, destination_ip:str, destination_port:int, timeout_length:int):
        """
            \'udp_scan_port\' will do a scan on target device port. Returns True if the device responded, False if the device did not respond
            Below are the arguments explained:
                \'destination_ip\':str is an argument that will set the target IPv4 address to scan
                \'destination_port\':int is an argument that will set the target port to scan
                \'timeout_length\':int is an argument that will set the timeout_length for the UDP connection
        """
        answered, unanswered = sr1(IP(dst=destination_ip, ttl=64)/UDP(dport=destination_port), timeout=timeout_length)
        if answered:
            return True
        return False
    def set_process_limit(self, new_process_limit:int):
        """
            Sets the process limit for managed scans, it will not be updated inside of currently running scans.
        """
        self.MAX_PROCESSES = new_process_limit
    def list_port_lists(self):
        """
            Returns the hard-coded in tuples of ports that will be scanned when doing a scan using them.
        """
        return_dict = {
            'SML': self.SML_LIST,
            'MED': self.MED_LIST
        }
        return return_dict
    def managed_scan_port(self, destination_ip:str, tcp_connection:bool, connection_type:str, ports_to_scan:tuple, return_dictionary:dict, process_id:int):
        """
            \'managed_scan_port\' is not to be called. It is a method used by \'managed_tcp_scan_ports\' and \'managed_udp_scan_ports\'.
            Not joking. Dont call this.
        """
        responded_ports = []
        if tcp_connection is True:
            for port in ports_to_scan:
                answered, unanswered = sr1(IP(dst=destination_ip, ttl=64)/TCP(dport=port, flags=connection_type), timeout=5)
                if answered:
                    responded_ports.append(port)
        else:
            for port in ports_to_scan:
                answered, unanswered = sr1(IP(dst=destination_ip, ttl=64)/UDP(dport=port), timeout=5)
                if answered:
                    responded_ports.append(port)
        return_dictionary[process_id] = responded_ports
    def managed_tcp_scan_ports(self, target_ip:str, use_custom_port:bool, ports_to_scan:int, syn_scan:bool, custom_list:tuple):
        """
            \'managed_tcp_scan_ports\' is designed to automate the scanning of ports listed inside of \'list_port_lists()\'.
            It works by creating processes with evenly distrobuted ports that will be automatically scanned within each process.
            Below the arguments are explained:
                \'target_ip\':str is the target IPv4 address that you wish to scan
                \'use_custom_port\':bool is a bool for scanning a custom list, if True it will pull the passed tuple in the \'custom_list\' argument
                \'custom_list\':tuple is a variable that contains a custom tuple of ports that will be scanned
                \'ports_to_scan\':int is a variable that will dictate the hard-coded list of ports that will be scanned (can only be 0 or 1)
                \'syn_scan\':bool is a variable that will dictate the type of scan on each port, if True it will do a SYN scan and False will do a ACK scan
            Below are example usages:
                (using a hard-coded list)
                managed_tcp_scan_ports("192.168.1.254", False, 0, True, None) # SYN scan
                managed_tcp_scan_ports("192.168.1.254", False, 1, True, None) # ACK scan
                (using a custom list)
                managed_tcp_scan_ports("192.168.1.254", True, None, True, tuple([1, 4, 12, 18, 20, 80, 443, 2020, 8080, 1000]))  # SYN scan
                managed_tcp_scan_ports("192.168.1.254", True, None, False, tuple([1, 4, 12, 18, 20, 80, 443, 2020, 8080, 1000])) # ACK scan
        """
        open_ports = []
        process_manager = Manager()
        return_dictionary = process_manager.dict()
        scan_processes = []
        last_ports_count = 0
        if syn_scan is True:
            match ports_to_scan:
                case 0:
                    ports_per_process = int(len(self.SML_LIST)/self.MAX_PROCESSES)
                    for process_id in range(1, self.MAX_PROCESSES):
                        process = Process.run(target=managed_scan_port, args=(target_ip, True, 's', self.SML_LIST[last_ports_count:(last_ports_count + ports_per_process)], return_dictionary, process_id))
                        scan_processes.append(process)
                case 1:
                    ports_per_process = int(len(self.MED_LIST)/self.MAX_PROCESSES)
                    for process_id in range(1, self.MAX_PROCESSES):
                        process = Process.run(target=managed_scan_port, args=(target_ip, True, 's', self.MED_LIST[last_ports_count:(last_ports_count + ports_per_process)], return_dictionary, process_id))
                        scan_processes.append(process)
                case _:
                    raise PortScannerError(f"Incompatable input scan type \'{ports_to_scan}\'!")
        else:
            match ports_to_scan:
                case 0:
                    ports_per_process = int(len(self.SML_LIST)/self.MAX_PROCESSES)
                    for process_id in range(1, self.MAX_PROCESSES):
                        process = Process.run(target=managed_scan_port, args=(target_ip, True, 'a', self.SML_LIST[last_ports_count:(last_ports_count + ports_per_process)], return_dictionary, process_id))
                        scan_processes.append(process)
                case 1:
                    ports_per_process = int(len(self.MED_LIST)/self.MAX_PROCESSES)
                    for process_id in range(1, self.MAX_PROCESSES):
                        process = Process.run(target=managed_scan_port, args=(target_ip, True, 'a', self.MED_LIST[last_ports_count:(last_ports_count + ports_per_process)], return_dictionary, process_id))
                        scan_processes.append(process)
                case _:
                    raise PortScannerError(f"Incompatable input scan type \'{ports_to_scan}\'!")
        for process in scan_processes:
            process.join()
        for key in scan_processes.keys():
            for port in scan_processes[key]:
                open_ports.append(port)
        return open_ports
    def managed_udp_scan_ports(self, target_ip:str, use_custom_port:bool, ports_to_scan:int, custom_list:tuple):
        """
            \'managed_udp_scan_ports\' is designed to automate the scanning of ports listed inside of \'list_port_lists()\'.
            It works by creating processes with evenly distrobuted ports that will be automatically scanned within each process.
            Below the arguments are explained:
                \'target_ip\':str is the target IPv4 address that you wish to scan
                \'use_custom_port\':bool is a bool for scanning a custom list, if True it will pull the passed tuple in the \'custom_list\' argument
                \'custom_list\':tuple is a variable that contains a custom tuple of ports that will be scanned
                \'ports_to_scan\':int is a variable that will dictate the hard-coded list of ports that will be scanned (can only be 0 or 1)
            Below are example usages:
                (using a hard-coded list)
                managed_udp_scan_ports("192.168.1.254", False, 0, None)
                managed_udp_scan_ports(False, 1, None)
                (using a custom list)
                managed_udp_scan_ports("192.168.1.254", True, None, tuple([1, 4, 12, 18, 20, 80, 443, 2020, 8080, 1000]))
        """
        open_ports = []
        process_manager = Manager()
        return_dictionary = process_manager.dict()
        scan_processes = []
        last_ports_count = 0
        if use_custom_port is True:
            ports_per_process = int(len(custom_list)/self.MAX_PROCESSES)
            for process_id in range(1, self.MAX_PROCESSES):
                process = Process.run(target=managed_scan_port, args=(target_ip, False, '0', custom_list[last_ports_count:(last_ports_count + ports_per_process)], return_dictionary, process_id))
                scan_processes.append(process)
        else:
            match ports_to_scan:
                case 0:
                    ports_per_process = int(len(self.SML_LIST)/self.MAX_PROCESSES)
                    for process_id in range(1, self.MAX_PROCESSES):
                        process = Process.run(target=managed_scan_port, args=(target_ip, False, '0', self.SML_LIST[last_ports_count:(last_ports_count + ports_per_process)], return_dictionary, process_id))
                        scan_processes.append(process)
                case 1:
                    ports_per_process = int(len(self.MED_LIST)/self.MAX_PROCESSES)
                    for process_id in range(1, self.MAX_PROCESSES):
                        process = Process.run(target=managed_scan_port, args=(target_ip, False, '0', self.MED_LIST[last_ports_count:(last_ports_count + ports_per_process)], return_dictionary, process_id))
                        scan_processes.append(process)
                case _:
                    raise PortScannerError(f"Incompatable input scan type \'{ports_to_scan}\'!")
            for process in scan_processes:
                process.join()
            for key in scan_processes.keys():
                for port in scan_processes[key]:
                    open_ports.append(port)
        return open_ports
