#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdlib>

#include <getopt.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap/pcap.h>


struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

typedef struct _sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
} sniff_tcp;

typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

/* wireless frame types, mostly from tcpdump (wam) */
/* lm: copied from nids */
#define FC_TYPE(fc)             (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc)          (((fc) >> 4) & 0xF)
#define DATA_FRAME_IS_QOS(x)    ((x) & 0x08)
#define FC_WEP(fc)              ((fc) & 0x4000)
#define FC_TO_DS(fc)            ((fc) & 0x0100)
#define FC_FROM_DS(fc)          ((fc) & 0x0200)
#define T_MGMT 0x0		/* management */
#define T_CTRL 0x1		/* control */
#define T_DATA 0x2		/* data */
#define T_RESV 0x3		/* reserved */
#define EXTRACT_LE_16BITS(p) \
	((unsigned short)*((const unsigned char *)(p) + 1) << 8 | \
	(unsigned short)*((const unsigned char *)(p) + 0))
#define EXTRACT_16BITS(p)	((unsigned short)ntohs(*(const unsigned short *)(p)))
#define LLC_FRAME_SIZE 8
#define LLC_OFFSET_TO_TYPE_FIELD 6
#define ETHERTYPE_IP 0x0800

/* lm: code copied from nids */
bool update_wifi_offset(struct pcap_pkthdr* hdr,
			const u_char* pkt,
			int* offset)
{
	 /* I don't know why frame control is
	  * always little endian, but it works
	  * for tcpdump, so who am I to
	  * complain? (wam)
	  */
	uint16_t fc = EXTRACT_LE_16BITS(pkt + *offset);
	if (FC_TYPE(fc) != T_DATA || FC_WEP(fc)) {
		return false;
	}
	if (FC_TO_DS(fc) && FC_FROM_DS(fc)) {
		/* a wireless distribution
		 * system packet will have
		 * another MAC addr in the frame - 6 bytes
		 */
	    /* Also indicates the presence of mesh control fields - 6 bytes */
	    *offset += 12; 
	}
	*offset += 24;
	if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
		*offset += 2;
	if ((int)hdr->len < *offset + LLC_FRAME_SIZE)
		return false;

	if (ETHERTYPE_IP !=
		EXTRACT_16BITS(pkt + *offset
				+ LLC_OFFSET_TO_TYPE_FIELD))
	{
		/* EAP, LEAP, and other 802.11
		 * enhancements can be
		 * encapsulated within a data
		 * packet too.  Look only at
		 * encapsulated IP packets (Type
		 * field of the LLC frame).
		 */
		return false;
	}
	*offset += LLC_FRAME_SIZE;
	return true;
}

double time_delta(const struct timeval* end,
		  const struct timeval* start)
{
	double ret = end->tv_sec - start->tv_sec;
	ret += (end->tv_usec - start->tv_usec)/1000000.;
	return ret;
}

using namespace std;

pcap_t* my_pcap_open_offline(const char* fname, char* errbuf, FILE** popen_fp)
{
	*popen_fp = NULL;

	/* Check for compression */
	size_t l = strlen(fname);
	if (l >= 3 && strcmp(fname + l - 3, ".gz") == 0) {
		assert(l < 200); // XXX
		char cmdbuf[256];
		snprintf(cmdbuf, sizeof(cmdbuf), "gzip -cd \"%s\"", fname);
		*popen_fp = popen(cmdbuf, "r");
		if (*popen_fp == NULL) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE,
			  "popen(): %s", strerror(errno));
			return NULL;
		}
		return pcap_fopen_offline(*popen_fp, errbuf);
	}

	return pcap_open_offline(fname, errbuf);
}

class ratebin_mgr {
    int numtimeslabs;
    int timeslabwidth;
    int timeslabstart;

    typedef struct _bin_entry {
	int lower_bound = 0;
	int upper_bound = 0;
	unsigned long int sum = 0;
    } bin_entry;

    bin_entry* sentbins;
    bin_entry* recvbins;


private:
    void init_bins(bin_entry bins[])
    {
	int i;
	int index;
	for (i = timeslabstart, index = 0; i < timeslabstart  + numtimeslabs * timeslabwidth;
	     i = i + timeslabwidth, index++) {
	    bins[index].lower_bound = i;
	    bins[index].upper_bound = i + timeslabwidth;
	    bins[index].sum = 0;
	}
	return;
    }

    void print_bins(bin_entry bins[])
    {
	for (int i = 0; i < numtimeslabs; i++) {
	    printf ("%d, %d, %ld\n", bins[i].lower_bound, bins[i].upper_bound, bins[i].sum);
	}
	return;
    }

    void print_bin_datarates(bin_entry bins[])
    {
	printf( "Header, TimeStart , TimeEnd, BytesTransferred, DataRate\n");
	printf( "Units, sec, sec, bytes, kb/s\n");

	for (int i = 0; i < numtimeslabs; i++) {
	    printf ("Data: %d, %d, %ld, %5.2f\n", bins[i].lower_bound, bins[i].upper_bound, bins[i].sum,
		    bins[i].sum*8.0/timeslabwidth/1000.0);
	}
	return;
    }

    void bin_val(bin_entry bins[], int key, int value)
    {
	for (int i = 0; i < numtimeslabs; i++) {
	    if ((bins[i].lower_bound <= key) && (bins[i].upper_bound > key))
		bins[i].sum += value;
	}
	return;
    }

public:
    ratebin_mgr (int numslabs, int slabwidth, int slabstart):
	numtimeslabs(numslabs), timeslabwidth(slabwidth), timeslabstart(slabstart) {

	sentbins = new bin_entry[numtimeslabs];
	recvbins = new bin_entry[numtimeslabs];
	init();
    }

    ~ratebin_mgr() {
	delete [] sentbins;
	delete [] recvbins;
    }

    void init() {
	init_bins(sentbins);
	init_bins(recvbins);
	return;
    }

    void bin_value(int key, int value, bool reverse = false)
    {
	if (!reverse)
	    bin_val(sentbins, key, value);
	else
	    bin_val(recvbins, key, value);
	return;
    }

    void print_stats () {

	printf("DETAILS: Data sent\n");
	print_bin_datarates(sentbins);
	printf("DETAILS: Data recv\n");
	print_bin_datarates(recvbins);
	return;
    }

};

class tcp_handler {

public:
    enum action_t {
		   avgrate = 0,
		   binrate = 1,
		   dupacks = 2
    };

private:
    unsigned long int max_seqnbr = 0;
    unsigned long int max_ack = 0;
    bool dup_ack = false;
    unsigned long int dup_ack_cnt = 0;
    bool started = false;
    struct timeval start_time;
    struct timeval end_time;
    int dport = -1;
    action_t action = avgrate;

    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    unsigned long int num_pkts = 0;
    unsigned long int num_pkts_sent = 0;
    unsigned long int num_pkts_recv = 0;

    ratebin_mgr *ratebins;

public:
    tcp_handler (char* src, const char* dest, int numslabs, int slabwidth, int
		 slabstart, int port, action_t a = avgrate) : dport(port),
							      action(a)  {
	if ((action == binrate) || (action == dupacks)) {
	    strcpy(src_ip, src);
	    strcpy(dest_ip, dest);
	    ratebins = new ratebin_mgr(numslabs, slabwidth, slabstart);
	}
	init();
    }

    ~tcp_handler() {
	delete ratebins;
    }

    void init() {
	num_pkts = 0;
	num_pkts_sent = 0;
	num_pkts_recv = 0;

	if (action == binrate)
	    ratebins->init();

	started = false;
	max_seqnbr = 0;
	max_ack = 0;
	dup_ack = false;
	dup_ack_cnt = 0;
    }

    void print_stats () {
	/* Print stats */

	if (action == avgrate) {
	    printf("xfer_time %g\n", started ? time_delta(&end_time, &start_time) : 0.0);
	    printf("xfer_bytes %lu\n", max_seqnbr);
	}
	else if (action == binrate) {
	    printf("tcp_pkts %lu\n", num_pkts);
	    printf("conversation pkts sent: %lu recv %lu\n", num_pkts_sent, num_pkts_recv);
	    ratebins->print_stats();
	}
	else if (action == dupacks) {
	    printf("Number of DUP acks %lu\n", dup_ack_cnt);
	}
	return;
    }

    void pkt_handler (const sniff_tcp *tcp_hdr, const struct sniff_ip *ip_hdr,
		      const struct pcap_pkthdr *hdr) {

	if (dport != -1 && ntohs(tcp_hdr->th_dport) != dport)
	    return;

	char src[INET_ADDRSTRLEN];
	char dest[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ip_hdr->ip_src), src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip_hdr->ip_dst), dest, INET_ADDRSTRLEN);

	int size_ip_hdr = (ip_hdr->ip_vhl & 0x0f) << 2;
	int size_tcp = ((tcp_hdr->th_offx2 & 0xf0) >> 4) * 4;;

	num_pkts++;
	double key = hdr->ts.tv_sec + hdr->ts.tv_usec/1000000.0;
	int bytes = ntohs(ip_hdr->ip_len) - size_ip_hdr - size_tcp;

	bool reverse = false;

	if ((strcmp(src_ip, src) == 0) && (strcmp(dest_ip, dest) == 0)){
	    ratebins->bin_value(key, bytes, false);
	    num_pkts_sent++;
	}

	if ((strcmp(src_ip, dest) == 0) && (strcmp(dest_ip, src) == 0)){
	    ratebins->bin_value(key, bytes, true);
	    reverse = true;
	    num_pkts_recv++;
	}

	if (!started) {
	    started = true;
	    start_time = hdr->ts;
	}

	const unsigned long int seqnbr = ntohl(tcp_hdr->th_seq);
	if (seqnbr > max_seqnbr)
	    max_seqnbr = seqnbr;
	end_time = hdr->ts;

	const char * direction = reverse ? "recv" : "sent";

	const unsigned long int ack = ntohl(tcp_hdr->th_ack);
	if (ack > max_ack) {
	    max_ack = ack;
	    dup_ack = false;
	}
	else if ((ack == max_ack) && !(ack <= 1) && !dup_ack) {
	    dup_ack = true;
	    dup_ack_cnt++;
	    if (action == dupacks)
		printf ("%s: Time: %g , DUP Ack: %lu\n", direction, key, ack);
	}

	//const unsigned short int win = ntohs(tcp_hdr->th_win);
	//printf ("%s: Time: %g , Seqnbr: %lu , Ack: %lu , win: %u, bytes: %d\n",
	//	direction, key, seqnbr, ack, win, bytes);
	return;
    }
};

class udp_handler {
public:
    enum action_t {
		   udpdelay = 0,
		   binrate = 1
    };

private:
    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    unsigned long int num_pkts = 0;
    unsigned long int num_pkts_sent = 0;
    unsigned long int num_pkts_recv = 0;
    action_t action = binrate;
    ratebin_mgr *ratebins;

    bool justsent=false;
    double lasttimesent = 0.0;
    double lasttimerecv = 0.0;
    int dport = -1;
public:
    udp_handler(char* src, const char* dest, int numslabs, int slabwidth, int slabstart,
		action_t a, int port = -1) : action(a), dport(port) {
	strcpy(src_ip, src);
	strcpy(dest_ip, dest);

	ratebins = new ratebin_mgr(numslabs, slabwidth, slabstart);
	init();
    }

    ~udp_handler() {
	delete ratebins;
    }

    void init() {
	num_pkts = 0;
	num_pkts_sent = 0;
	num_pkts_recv = 0;

	ratebins->init();

	justsent=false;
	lasttimesent = 0.0;
	lasttimerecv = 0.0;
	return;
    }

    void pkt_handler(const udp_header *udp_hdr, const struct sniff_ip * ip_hdr,
		     const struct pcap_pkthdr *hdr) {

	if ((dport != -1) && ((ntohs(udp_hdr->sport) != dport) && (ntohs(udp_hdr->dport) != dport)))
	    return;

	char src[INET_ADDRSTRLEN];
	char dest[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ip_hdr->ip_src), src, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ip_hdr->ip_dst), dest, INET_ADDRSTRLEN);

	num_pkts++;
	double pkt_time = hdr->ts.tv_sec + hdr->ts.tv_usec/1000000.0;
	int bytes = ntohs(udp_hdr->len) - sizeof(udp_header);

	if ((strcmp(src_ip, src) == 0) && (strcmp(dest_ip, dest) == 0)){
	    ratebins->bin_value(pkt_time, bytes, false);
	    num_pkts_sent++;
	    lasttimesent = pkt_time;
	    justsent=true;
	}

	if ((strcmp(src_ip, dest) == 0) && (strcmp(dest_ip, src) == 0)){
	    ratebins->bin_value(pkt_time, bytes, true);
	    num_pkts_recv++;
	    lasttimerecv = pkt_time;
	    double delay = lasttimerecv - lasttimesent;
	    if ((action == udpdelay) && (justsent==true)) {
		printf ("UDP Pkt Recv: %5.3f Delay: %5.3fms\n", lasttimerecv,
			delay*1000);
		justsent=false;
	    }
	}
    }

    void print_stats () {

	printf("udp_pkts %lu\n", num_pkts);
	printf("conversation pkts sent: %lu recv %lu\n", num_pkts_sent, num_pkts_recv);
	if (action == binrate)
	    ratebins->print_stats();
	return;
    }
};

bool pcap_evaluate(const char* fn, u_char protocol,
		   tcp_handler* tcp_mgr, udp_handler* udp_mgr)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	putc('\n', stdout);
	printf("file %s\n", fn);

	/* Open the pcap */
	FILE* popen_fp;
	pcap_t* ph = my_pcap_open_offline(fn, errbuf, &popen_fp);
	if (ph == NULL) {
		fprintf(stderr, "Error opening pcap: %s\n", errbuf);
		return false;
	}

	/* Compute the offset of the link layer headers */
	int base_offset = 0;
	int dlt = pcap_datalink(ph);
	switch (dlt) {
	case DLT_PPP: {
		// XXX: This is a hack that works for ns3 generated
		// traces
		base_offset = 2;
		break;
	}
	case DLT_EN10MB: {
		base_offset = 14;
		break;
	}
	case DLT_IEEE802_11: {
		/* Computed later on a per-packet basis */
		break;
	}
	default:
		fprintf(stderr, "Error:  Unsupported layer 2 header type.\n");
		return false;
	}

	/* Iterate over packets, collect stats */
	struct pcap_pkthdr hdr;
	const u_char* pkt;

	if ((protocol == IPPROTO_UDP) && (udp_mgr != NULL))
	    udp_mgr->init();

	if ((protocol == IPPROTO_TCP) && (tcp_mgr != NULL))
	    tcp_mgr->init();

	while ((pkt = pcap_next(ph, &hdr)) != NULL) {
		/* Compute the IP header offset */
		int offset = base_offset;

		/* Frame size computation copied from nids */
		if (dlt == DLT_IEEE802_11) {
		    if (!update_wifi_offset(&hdr, pkt, &offset))
			continue;
		}

		/* Get the IP header */
		struct sniff_ip ip_hdr;
		memcpy(&ip_hdr, pkt + offset, sizeof(ip_hdr));

		if ((ip_hdr.ip_vhl >> 4) != 4) {
			/* not ipv4 */
			continue;
		}
		if (ip_hdr.ip_p != protocol) {
			/* not the intended protocol */
			continue;
		}
		int ip_hdr_size = (ip_hdr.ip_vhl & 0x0f) << 2;

		assert (ip_hdr_size >= 20);

		if (protocol == IPPROTO_TCP) {
		    sniff_tcp tcp_hdr;
		    memcpy(&tcp_hdr, pkt + offset + ip_hdr_size, sizeof(tcp_hdr));
		    tcp_mgr->pkt_handler(&tcp_hdr, &ip_hdr, &hdr);
		}
		else if (protocol == IPPROTO_UDP) {
		    udp_header udp_hdr;
		    memcpy(&udp_hdr, pkt + offset + ip_hdr_size, sizeof(udp_hdr));
		    udp_mgr->pkt_handler(&udp_hdr, &ip_hdr, &hdr);
		}
	}

	if (protocol == IPPROTO_TCP) {
	    tcp_mgr->print_stats();
	}
	else if (protocol == IPPROTO_UDP) {
	    udp_mgr->print_stats();
	}

	/* Clean up */
	if (popen_fp) {
		pclose(popen_fp);
	} else {
		/* Note we're not callin pcap close if we pclose() the
		 * process ourselves.  That's because pcap_close()
		 * apparently tries to close the file handle itself,
		 * which is unfortunate.
		 * Anyways, the leak is preferable to double closing a
		 * file.
		 */
		pcap_close(ph);
	}

	return true;
}


void usage()
{
    puts("Evaluate basic TCP/UDP performance from a pcap");
    puts("");
    puts("usage: [-p port] [pcap files...]");
    puts("");
    puts("  -h             display help");
    puts("  -m <mode>      mode-protocol to analyze");
    puts("                 \"tcprate\" to analyze tcp avg rate");
    puts("                 \"tcpbins\" to analyze tcp data rate bins");
    puts("                 \"udpbins\" to analyze udp data rate bins");
    puts("                 \"udpdelay\" to analyze udp delay");
    puts("  -p #           destination port number");
    puts("  -s <ip_addr>   src ip address to track");
    puts("  -d <ip_addr>   dest ip address to track");
    puts("  -n #           number of timeslabs for data rate binning");
    puts("  -b #           bin start time for data rate binning");
    puts("  -t #           time bin width for data rate binning");

}

int main(int argc, char** argv)
{
	int dport = -1;
	char * src_ip = NULL;
	char * dest_ip = NULL;

	int timeslabstart = 0;
	int timeslabwidth = 5;
	int numtimeslabs = 20;

	char mode[9] = "tcprate";

	/* Read args */
	int c;
	while ((c = getopt(argc, argv, "hp:s:d:t:n:m:b:")) != -1) {
		switch (c) {
		case 'h': {
			usage();
			break;
		}
		case 'p': {
			dport = atoi(optarg);
			break;
		}
		case 'b': {
			timeslabstart = atoi(optarg);
			break;
		}
		case 't': {
			timeslabwidth = atoi(optarg);
			break;
		}
		case 'm': {
		    strncpy(mode, optarg, sizeof(mode));
		    break;
		}
		case 'n': {
		    numtimeslabs = atoi(optarg);
		    break;
		}
		case 's': {
		    src_ip = optarg;
		    break;
		}
		case 'd': {
		    dest_ip = optarg;
		    break;
		}
		case '?':
			return 1;
		};
	}

	u_char protocol = IPPROTO_TCP;
	udp_handler *udp_manager = NULL;
	tcp_handler *tcp_manager = NULL;

        if ((strcmp(mode, "udpbins") == 0) || (strcmp(mode, "udpdelay") == 0)) {
	    protocol = IPPROTO_UDP;

	    udp_handler::action_t udpaction = udp_handler::binrate;

	    if (strcmp(mode, "udpdelay") == 0)
		udpaction = udp_handler::udpdelay;

	    if (src_ip == NULL || dest_ip == NULL) {
		fprintf (stderr, "src and dest not set for udp analysis\n\n");
		usage();
		return -1;
	    }

	    udp_manager = new udp_handler(src_ip, dest_ip, numtimeslabs, timeslabwidth,
					  timeslabstart, udpaction, dport);
	}
	else if ((strcmp(mode, "tcpbins") == 0) || (strcmp(mode, "tcprate") == 0)
		|| (strcmp(mode, "tcpdups") == 0)){

	    protocol = IPPROTO_TCP;

	    tcp_handler::action_t tcpaction = tcp_handler::avgrate;
	    if (strcmp(mode, "tcpbins") == 0 || (strcmp(mode, "tcpdups") == 0)) {
		if (src_ip == NULL || dest_ip == NULL) {
		    fprintf (stderr, "src and dest not set for udp analysis\n\n");
		    usage();
		    return -1;
		}
		if (strcmp(mode, "tcpbins") == 0)
		    tcpaction = tcp_handler::binrate;
		else
		    tcpaction = tcp_handler::dupacks;
	    }

	    tcp_manager = new tcp_handler(src_ip, dest_ip, numtimeslabs, timeslabwidth,
					  timeslabstart, dport, tcpaction);
	}
	else {
	    fprintf (stderr, "unknown mode chosen for pcap-eval\n\n");
	    usage();
	    return -1;
	}

	for (int i = optind; i < argc; ++i) {
	    pcap_evaluate(argv[i], protocol, tcp_manager, udp_manager);
	}

	delete udp_manager;
	delete tcp_manager;

	return 0;
}
