# pastadizer
Packet Size Typical Distribution Analyzer for Network Management 19/20 Class.

This tool gets two or more .pcap files as input 
and outputs the number of flow pairs that are more distant than a certain
threshold.

You can pass the threshold as a command line argument
 along with a BPF syntax filter and the pcaps to be analyzed.

### Dependencies
The tool has the following dependencies:
- **Scikit-learn 0.23.2**
- **Scapy 2.4.3** 
- **Numpy 1.19.1**
- **Seaborn 0.9.0**
- **Matplotlib 3.3.1**

To install the required dependencies you 
can run these command assuming you are in a 
conda environment

`conda install scapy numpy scikit-learn seaborn matplotlib`

alternatively, if you're using plain pip, you can use

`pip3 install scapy numpy scikit-learn seaborn matplotlib`

This is not recommended though, since it
 installs dependencies systemwide and could potentially break other projects.
 
 ### How it works
 
 The tool uses code at https://github.com/daniele-sartiano/doh 
 to build network flows distribution vectors from a list of .pcap files,
  then it computes euclidean 
 distance between all the flows, finally plotting the number
 of flow pairs that cross a certain threshold input as command line argument.
 If called with the -m flag, the tool plots a seaborn heatmap showing 
 at first glance how dissimilar flows are by plotting the pairwise distance matrix.
 Flows under the tolerance threshold are masked.
 
 ### Running the tool
 
 In order to run the tool you can use 
 
~~~
git clone https://github.com/gioleppe/pastadizer
cd pastadizer
python3 pastadizer <first_pcap> <second_pcap> [<other_pcaps>] -f <BPF_filter> [-m]
~~~

You can also use the -h flag to show an help message.