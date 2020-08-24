from scapy.all import *
import math
from sklearn import metrics
import pprint as pp
import numpy as np

load_layer("ip")
load_layer("tls")


def scale(len):
    if (len > 1504):
        len = 1504

    return (int(len / 64))


maxlen = int(math.ceil(1504 / 64))
chains = {}


def newchain():
    c = [0 for x in range(maxlen)]
    return (c)


def updatechain(who, slot):
    # print("Update "+who+" @ "+str(slot))
    if (not (who in chains)):
        chains[who] = newchain()

    chains[who][slot] = chains[who][slot] + 1


def markov(src, dst, len):
    slot = scale(len)
    updatechain(src, slot)
    updatechain(dst, slot)


def pkt_parser(pkt):
    if (pkt.haslayer('IP')):
        ip = pkt.getlayer(IP)
        tcp = pkt.getlayer(TCP)
        # print(ip.src+" -> "+ip.dst+" / "+str(tls.len))
        markov(ip.src + ":" + str(tcp.sport), ip.dst + ":" + str(tcp.dport), ip.len)


def printchain(a):
    # print(a)
    s = sum(a)
    for x in range(maxlen):
        a[x] = int((a[x] * 100) / s)

    print(a)

# MAIN

import sys, argparse

parser = argparse.ArgumentParser(description='Analyze packet lenght distributions in two different pcaps')
parser.add_argument('pcaps', metavar='P', nargs="+", help='the pcaps to analyze')
parser.add_argument('-f', metavar='F', dest = "filter", nargs=1, help='a filter in BPF syntax to be applied to both pcaps')
args = parser.parse_args()

print ("Analyzing pcaps: ", args.pcaps)
print("Using BPF filter: ", args.filter)

filter = args.filter[0]
# empty distributions list to subsequently compute pairwise distances
distributions = []

for pcap in args.pcaps:
    print(pcap, filter)
    pkts = sniff(offline=pcap, prn=pkt_parser, filter=filter)  # Read pkts from pcap_file

    for host in chains:
        print("From " + host)
        printchain(chains[host])

    # we put all our distributions in a list
    for host in chains:
        distributions.append(np.array(chains[host]))

# we calculate pairwise distances between distribution vectors
count = 0
# distance tolerance
tol = 100

pairwise = metrics.pairwise_distances(distributions, metric="euclidean")
# pp.pprint(pairwise)

for row in pairwise:
    for element in row:
        if (element > tol):
            count += 1

print("{:4d} flow pairs had a > {:3d} distance".format(count, tol))


