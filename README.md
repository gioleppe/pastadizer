# pastadizer
Packet Size Typical Distribution Analyzer for Network Management 19/20 Class.

This tool gets two or more .pcap files as input 
and outputs the number of flux pairs that are more distant than a certain
threshold.

You can pass the threshold as a command line argument
 along with a BPF syntax filter and the pcaps to be analyzed.

### Dependencies
The tool has the following dependencies:
- **Scikit-learn 0.23.2**
- **Scapy 2.4.3** 
- **Numpy 1.19.1**

To install the required dependencies you 
can run these command assuming you are in a 
conda environment

`conda install scapy numpy scikit-learn`

alternatively, if you're using plain pip, you can use

`pip install scapy numpy scikit-learn`

This is not recommended though, since it
 installs dependencies systemwide and could potentially break other projects.
 
 ### Running the tool
 
 In order to run the tool you can use 
 
~~~
git clone https://github.com/gioleppe/pastadizer
cd pastadizer
python pastadizer <first_pcap> <second_pcap> [<other_pcaps>] -f <BPF_filter>
~~~

You can also use the -h flag to show an help message.