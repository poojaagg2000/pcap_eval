# pcap_eval
This is a pcap evaluation tool written in C++ to extract relevant metrics from the pcap files. In particular, the following to be extracted from the pcaps:
The average TCP throughput (file download) between 2 endpoints </br>
The UDP echo packet delay variation per second </br>
The TCP throughput as a function of time </br>
The UDP throughput as a function of time </br>

Building the software:

pcap_eval uses cmake to build the software. Create the build directory, cd into it, and invoke cmake  </br>
mkdir build </br>
cd build </br>
cmake .. </br>
cmake --build . </br>

</br>
Evaluate basic TCP/UDP performance from a pcap </br>
</br>
usage: [-p port] [pcap files...] </br>

  -h             display help </br>
  -m <mode>      mode-protocol to analyze </br>
                 "tcprate" to analyze tcp avg rate </br>
                 "tcpbins" to analyze tcp data rate bins </br>
                 "udpbins" to analyze udp data rate bins </br>
                 "udpdelay" to analyze udp delay </br>
  -p #           destination port number </br>
  -s <ip_addr>   src ip address to track </br>
  -d <ip_addr>   dest ip address to track </br>
  -n #           number of timeslabs for data rate binning </br>
  -b #           bin start time for data rate binning </br>
  -t #           time bin width for data rate binning </br>
</br>
For example: </br>
./pcap_eval -s "10.1.4.1" -d "10.1.1.1" -n 12 -m "tcprate" <$filenm>
