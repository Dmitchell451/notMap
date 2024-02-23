import argparse
import scapy.all
from scapy.layers.inet import ICMP, IP, TCP
from scapy.sendrecv import sr

responseList = []
parser = argparse.ArgumentParser(description='argparser')
parser.add_argument("IP")
args=parser.parse_args()

SYN = IP(dst = args.IP)/TCP(flags = 'S',seq = 1000, dport =[1,1024])

ans = (sr(SYN))
print(ans)




