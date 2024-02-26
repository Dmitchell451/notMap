import argparse
import scapy.all
from scapy.layers.inet import ICMP, IP, TCP
from scapy.sendrecv import sr

portDict = {
    2: 'CompressNet',
    3: 'CompressNet',
    5: 'Remote Job Entry',
    7: 'Echo Protocol',
    11: 'Systat protocol',
    13: 'Daytime protocol',
    17: 'QOTD',
    18: 'Message Send Protocol',
    19: 'CHARGEN',
    20: 'FTP',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    80: 'HTTP',
    443: 'HTTPS',

}

responseString = ""
parser = argparse.ArgumentParser(description='argparser')
parser.add_argument("IP")
args = parser.parse_args()
portNum = 1
print("scanning host at " + args.IP)

SYN  = IP(dst=args.IP) / TCP(flags='S', seq=1000, dport=(1,1024), sport=45789)


ans, unans = ((sr(SYN, verbose=False, timeout=20)))
loopCount = 0
for i in ans:

    if str(ans[loopCount]).find("flags=SA") != -1:

       if portDict.get(loopCount + 1) is not None:
           responseString += f"Port {loopCount + 1, portDict.get(loopCount + 1)} Open\n"
    loopCount += 1

print(responseString)

