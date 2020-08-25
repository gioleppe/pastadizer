import numpy as np
from scapy.all import *
from scapy.layers.inet import TCP, IP
from sklearn import metrics
import seaborn as sns
import matplotlib.pyplot as plt

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

    # print(a)


# MAIN

import argparse

parser = argparse.ArgumentParser(description='Analyze packet lenght distributions in two or more pcaps')
parser.add_argument('pcaps', metavar='P', nargs="+", help='the pcaps to analyze')
parser.add_argument('-f', metavar='F', dest="filter",
                    help='a filter in BPF syntax to be applied to both pcaps. default = "tcp"',
                    default="tcp")
parser.add_argument('-t', type=int, metavar='T', dest="threshold",
                    help='The threshold for flux similarity analysis. default = 100',
                    default=100)
parser.add_argument("-m", dest="map",
                    help="Plot a heatmap with seaborn visualizing the pairwise distance matrix",
                    action="store_true")

args = parser.parse_args()

print("Analyzing pcaps: ", args.pcaps)
print("Using BPF filter: ", args.filter)

#print(args.filter[0])
filter = args.filter

# empty distributions list to subsequently compute pairwise distances
distributions = []

for pcap in args.pcaps:
    print(pcap, filter)
    pkts = sniff(offline=pcap, prn=pkt_parser, filter=filter)  # Read pkts from pcap_file

    # for host in chains:
    # print("From " + host)
    # printchain(chains[host])

    # we put all our distributions in a list
    for host in chains:
        distributions.append(np.array(chains[host]))

# we calculate pairwise distances between distribution vectors
count = 0
# distance tolerance
tol = args.threshold

pairwise = metrics.pairwise_distances(distributions, metric="euclidean")
# pp.pprint(pairwise)

for row in pairwise:
    for element in row:
        if (element > tol):
            count += 1
print(len(pairwise))
print("{:d} flow pairs had a > {:d} distance".format(count, tol))

if args.map:
    plt.figure(figsize=(8, 8))
    sns.heatmap(
        pairwise,
        cmap='OrRd',
        linewidth=1,
        mask=pairwise < tol
    )
    plt.show()

