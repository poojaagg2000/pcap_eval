# pcap_eval
This is a pcap evaluation tool written in C++ to extract relevant metrics from the pcap files. In particular, the following to be extracted from the pcaps:
The average TCP throughput (file download) between 2 endpoints
The UDP echo packet delay variation per second 
The TCP throughput as a function of time
The UDP throughput as a function of time

Evaluate basic TCP/UDP performance from a pcap

usage: [-p port] [pcap files...]

  -h             display help
  -m <mode>      mode-protocol to analyze
                 "tcprate" to analyze tcp avg rate
                 "tcpbins" to analyze tcp data rate bins
                 "udpbins" to analyze udp data rate bins
                 "udpdelay" to analyze udp delay
  -p #           destination port number
  -s <ip_addr>   src ip address to track
  -d <ip_addr>   dest ip address to track
  -n #           number of timeslabs for data rate binning
  -b #           bin start time for data rate binning
  -t #           time bin width for data rate binning

For example:
./pcap_eval -s "10.1.4.1" -d "10.1.1.1" -n 12 -m "tcprate" <$filenm>
