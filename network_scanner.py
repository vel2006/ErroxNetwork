from kamene.all import Ether, ARP, IP, ICMP, conf, sr, srp
import requests
import netifaces
import ipaddress
class ErroxNetworkError(Exception):
    def __init__(self, error_message):
        super().__init__(error_message)
class ErroxNetwork():
    def __init__(self):
        self.NETWORK_ADDRESS = ""
        self.DEFAULT_GATEWAY = ""
        self.DEFAULT_INTERFACE = 0
        self.INET = ""
        self.NETWORK_OCTECTS = ""
        self.HOST_OCTECTS = ""
        self.BROADCAST_ADDRESS = ""
        self.NETWORK_OBJECT = ""
        self.WIFI_ROUTER_PAGES = {
            'AT&T': {
                'DevicePages': ["/cgi-bin/home.ha", "/cgi-bin/devices.ha", "/cgi-bin/sysinfo.ha", "/cgi-bin/routerpasswd.ha", "/cgi-bin/remoteaccess.ha", "/cgi-bin/restart.ha"],
                'BroadbandPages': ["/cgi-bin/broadbandstatistics.ha", "/cgi-bin/broadbandconfig.ha", "/cgi-bin/fiberstat.ha"],
                'HomeNetworkPages': ["/cgi-bin/lanstatistics.ha", "/cgi-bin/etherlan.ha", "/cgi-bin/ipv6lan.ha", "/cgi-bin/wconfig_unified.ha", "/cgi-bin/wmacauth.ha", "/cgi-bin/dhcpserver.ha", "/cgi-bin/ipalloc.ha"],
                'VoicePages': ["/cgi-bin/voice.ha", "/cgi-bin/voiceconfig.ha", "/cgi-bin/voicestat.ha"],
                'FirewallPages': ["/cgi-bin/firewall.ha", "/cgi-bin/packetfilter.ha", "/cgi-bin/apphosting.ha", "/cgi-bin/pshosts.ha", "/cgi-bin/ippass.ha", "/cgi-bin/dosprotect.ha",  "/cgi-bin/securityoptions.ha"],
                'DiagnosticPages': ["/cgi-bin/diag.ha", "/cgi-bin/speed.ha", "/cgi-bin/logs.ha", "/cgi-bin/update.ha", "/cgi-bin/reset.ha", "/cgi-bin/syslog.ha", "/cgi-bin/events.ha", "/cgi-bin/nattable.ha"],
                'Unknown': ['/cgi-bin/sitemap.ha']
                },
            'TP-Link': {
                'Javascript': ["/js/libs/jquery.min.js", "/js/libs/cryptoJS.min.js", "/js/libs/tpEncrypt.min.js", "/js/app/url.js"],
                'CSS': [],
                'Local': [],
                'Config': [],
                'Themes': [],
                'Modules': ["/modules/login/controllers.js"]
            }
        }
        conf.verb = 0
    def get_default_gateway(self):
        """
            \'get_default_gateway\' will return and set the \'ErroxNetwork\' object\'s default gateway, which is needed in almost every other method for this class.
        """
        all_gatways = netifaces.gateways()
        default_gateway = all_gatways.get('default', {}).get(netifaces.AF_INET)
        if default_gateway:
            self.DEFAULT_GATEWAY = default_gateway[0]
            self.DEFAULT_INTERFACE = default_gateway[1]
            self.INET = netifaces.AF_INET
            return default_gateway[0]
        return None
    def get_network_subnetmask(self):
        """
            \'get_network_subnetmask\' will return and set the \'ErroxNetwork\' object\'s subnetmask, which is needed for doing network scans, and getting the network address.
            If the \'ErroxNetwork\' object\'s default gateway is not set (set via called methods) it will raise an error.
        """
        if self.DEFAULT_INTERFACE != "":
            self.SUBNETMASK = netifaces.ifaddresses(self.DEFAULT_INTERFACE)[self.INET][0]['netmask']
        else:
            raise ErroxNetworkError("\'self.DEFAULT_INTERFACE\' is not set!")
        return self.SUBNETMASK
    def get_network_address(self):
        """
            \'get_network_address\' will return the network address, which is needed for doing an ARP scan.
            If the \'ErroxNetwork\' object\'s default gateway and subnet mask are not set (set via called methods) it will raise an error.
        """
        if self.DEFAULT_GATEWAY != "" and self.SUBNETMASK != "":
            self.NETWORK_OBJECT = ipaddress.IPv4Network(f"{self.DEFAULT_GATEWAY}/{self.SUBNETMASK}", strict=False)
            self.NETWORK_ADDRESS = str(self.NETWORK_OBJECT)
        else:
            raise ErroxNetworkError("\'self.DEFUALT_GATEWAY\' and/or \'self.SUBNETMASK\' is not set!")
        return self.NETWORK_ADDRESS
    def get_gateway_webpage(self, router_company:str, page_catagory:str, wanted_webpage:str):
        """
            \'get_gateway_webpage\' attempts to request a webpage from the router.
            If the wanted webpage is not inside of the known pages dictionary an error will be raised.
            If the \'ErroxNetwork\' object\'s default gateway is not set (set via called methods) it will raise an error.

            Below is a discription of all the arguments:

                \'router_company\':str is a variable that is to refrence the keys / companies inside of the known pages dictionary
                \'page_gatagory\':str is a variable that is to refrence the catagory that the webpage is inside of in the known pages dictionary
                \'wanted_webpage\':str is a variable that is to refrence the values / pages inside of the known pages dictionary for the company
        """
        if self.DEFAULT_GATEWAY == "":
            raise ErroxNetworkError("\'self.DEFAULT_GATWAY\' is not set!")
        elif router_company not in self.WIFI_ROUTER_PAGES.keys():
            raise ErroxNetworkError(f"\'{router_company}\' is not in \'self.WIFI_ROUTER_PAGES\'!")
        elif page_catagory not in self.WIFI_ROUTER_PAGES[router_company].keys():
            raise ErroxNetworkError(f"\'{page_catagory}\' is not in \'self.WIFI_ROUTER_PAGES.keys()\'!")
        elif wanted_webpage not in self.WIFI_ROUTER_PAGES[router_company][page_catagory]:
            raise ErroxNetworkError(f"\'{wanted_webpage}\' is not in \'self.WIFI_ROUTER_PAGES[{router_company}]\'!")
        else:
            response = requests.get(f"http://{self.DEFAULT_GATEWAY}{wanted_webpage}")
            if response.status_code != 200:
                return ErroxNetworkError(f"Response from page \'http://{self.DEFAULT_GATEWAY}{wanted_webpage}\' returned with status code of: \'{response.status_code}\' not 200")
            return response.content
    def get_router_webpage(self, target_ip:str, router_company:str, page_catagory:str, wanted_webpage:str):
        """
            \'get_gateway_webpage\' attempts to request a webpage from the router ip address provided.
            If the wanted webpage is not inside of the known pages dictionary an error will be raised.

            Below is a discription of all the arguments:

                \'router_company\':str is a variable that is to refrence the keys / companies inside of the known pages dictionary
                \'page_gatagory\':str is a variable that is to refrence the catagory that the webpage is inside of in the known pages dictionary
                \'wanted_webpage\':str is a variable that is to refrence the values / pages inside of the known pages dictionary for the company
        """
        if target_ip is None:
            raise ErroxNetworkError("\'target_ip\' cannot be None!")
        elif router_company not in self.WIFI_ROUTER_PAGES.keys():
            raise ErroxNetworkError(f"\'{router_company}\' is not in \'self.WIFI_ROUTER_PAGES\'!")
        elif page_catagory not in self.WIFI_ROUTER_PAGES[router_company].keys():
            raise ErroxNetworkError(f"\'{page_catagory}\' is not in \'self.WIFI_ROUTER_PAGES.keys()\'!")
        elif wanted_webpage not in self.WIFI_ROUTER_PAGES[router_company][page_catagory]:
            raise ErroxNetworkError(f"\'{wanted_webpage}\' is not in \'self.WIFI_ROUTER_PAGES[{router_company}]\'!")
        else:
            response = requests.get(f"http://{target_ip}{wanted_webpage}")
            if response.status_code != 200:
                return ErroxNetworkError(f"Response from page \'http://{target_ip}{wanted_webpage}\' returned with status code of: \'{response.status_code}\' not 200")
            return response.content
    def get_network_broadcast(self):
        """
            \'get_network_broadcast\' returns a string for the network broadcast address.
            If the \'ErroxNetwork\' object\'s network object is not set (set via called methods) it will raise an error.
        """
        if self.NETWORK_OBJECT != "":
            self.BROADCAST_ADDRESS = str(self.NETWORK_OBJECT.broadcast_address)
            return self.BROADCAST_ADDRESS
        raise ErroxNetworkError("\'self.NETWORK_OBJECT\' is not set!")
    def get_gateway_webpages(self):
        """
            \'get_gatway_webpages\' returns a dictionary of all known pages on an american made wifi router or added pages and routers.
        """
        return self.WIFI_ROUTER_PAGES
    def get_company_gateway_webpages(self, company:str):
        """
            \'get_company_gateway_webpages\' returns the values inside of the dictionary corrisponding to the company name passed.
            If a nonexisting company name is passed, an error will be raised.
        """
        if company in self.WIFI_ROUTER_PAGES.keys():
            return self.WIFI_ROUTER_PAGES[company]
        else:
            raise ErroxNetworkError(f"{company} was not found inside of \'self.WIFI_ROUTER_PAGES\'!")
    def add_gateway_pages(self, company_name:str, page_catagory:str, page_to_add:str):
        """
            \'add_gateway_pages\' adds a value / page to the known pages for routers.
            If the page already exists in that catagory inside of the company it will return an error, not raise one >:3.
        """
        if page_to_add not in self.WIFI_ROUTER_PAGES[company_name][page_catagory].values():
            self.WIFI_ROUTER_PAGES[company_name][page_catagory].append(page_to_add)
        else:
            return ErroxNetworkError(f"{page_to_add} already exists in catagory {page_catagory} inside of {company_name}!")
    def ping_device(self, target_ip:str, packet_count:int):
        """
            \'ping_device\' pings the target IPv4 address using ICMP echo packets, not the best on a secure network, but good enough.

            Returns a tuple of the amount of answered and unanswered packets.
            Below is how to read the tuple along with an example:

                (4, 1)
                 ^  ^
                 |  |
                 |  -- Unanswered packets
                 |
                 ----- Answered packets
        """
        answered_pings = 0
        unanswered_pings = 0
        for i in range(0, packet_count):
            answered, unanswered = sr(IP(dst=target_ip)/ICMP(), timeout=5)
            if answered:
                answered_pings += 1
            else:
                unanswered_pings += 1
        return tuple([answered_pings, unanswered_pings])
    def arping_device(self, target_ip:str, target_mac:str, packet_count:int):
        """
            \'arping_device\' pings the target IPv4 address using ARP request packets, the best on a secure network due to a guanentee
            response or decline from the device, rather than the network blocking the ICMP trafic. Is it the loudest way of pinging a
            device (outside of slapping the bear metal) but is the most guarenteed to see if the device is online.

            Returns a tuple of the amount of answered and unanswered packets.
            Below is how to read the tuple along with an example:

                (4, 1)
                 ^  ^
                 |  |
                 |  -- Unanswered packets
                 |
                 ----- Answered packets
        """
        answered_pings = 0
        unanswered_pings = 0
        for i in range(0, packet_count):
            answered, unanswered = sr(Ether(dst=target_mac)/ARP(pdst=target_ip), timeout=5)
            if answered:
                answered_pings += 1
            else:
                unanswered_pings += 1
        return tuple([answered_pings, unanswered_pings])
    def arp_scan_network(self):
        """
            \'arp_scan_network\' will attempt to scan the current network for any devices that will respond to ARP requests and will return a list of mac addresses that responded.
            If the \'ErroxNetwork\' object\'s network address is not set (set via calling methods) an error will be raised.
        """
        if self.NETWORK_ADDRESS != "":
            responded_devices = []
            answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.NETWORK_ADDRESS), timeout=5)
            for sent, recieved in answered:
                responded_devices.append(str(recieved.hwsrc))
            return responded_devices
        else:
            raise ErroxNetworkError("\'self.NETWORK_ADDRESS\' is not set!")
    def find_mac_from_ip(self, target_ip:str):
        """
            \'find_mac_from_ip\' attempts to find the MAC address of an IP address via ARP.
            Below is a discription of it\'s arguments:

                \'target_ip\':str is the IPv4 address you wish to find the MAC address of.
        """
        answered, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip), timeout=5)
        if answered:
            return answered[0][1].hwsrc
        else:
            return ErroxNetworkError("Did not get an ARP response from network.")
    def find_ip_from_mac(self, target_mac:str):
        """
            \'find_ip_from_mac\' attempts to find the IP address of a MAC address via ARP.
            Below is a discription of it\'s arguments:

                \'target_mac\':str is the MAC address you wish to find the IPv4 address of.
        """
        if self.NETWORK_ADDRESS != "":
            answered, unanswered = srp(Ether(dst=target_mac)/ARP(pdst=self.NETWORK_ADDRESS), timeout=2)
        else:
            raise ErroxNetworkError("\'self.NETWORK_ADDRESS\' is not set!")
