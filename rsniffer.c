#include <pcap.h> 
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <arpa/inet.h> 
#include <netinet/if_ether.h> 

#define TZSP_DEFAULT_PORT 37008

#define VERSION "02"
#define BUILD "2019-11-22 00:02"
#define AUTHOR "vitaly.ponomarev@gmail.com"

#define PROTO_TZSP 0
#define PROTO_ERSPAN 1

#define MAX_CAPTURE_BUFFER_SIZE 8192

int	streamSocket;
int	flagSilent;
int	flagProto;
struct 	sockaddr_in streamDestination;
struct  tzsp_hdr {
	    uint8_t version;
	    uint8_t type;
	    uint8_t encapH;
	    uint8_t encapL;

	    uint8_t tagEnd;
	} tzspHdr;

struct gre_hdr {
    uint16_t	hdr;
    uint16_t	proto;
    uint32_t	seq;
} gre;

struct erspan_hdr {
    uint16_t	ver;
    uint16_t	dir;
    uint32_t	unk;
} ers;


char	*txBuf;

void usage(const char *prog) {
    fprintf(stdout,
	"rsniffer: capture packets via libpcap and transmit captured flow to external box using TZSP or ERSPAN protocol.\n"
	"\n"
	"Usage: %s [-h] [-l] [-E] [-s] [-i INTERFACE] [-p DEST_PORT] DEST_HOST FILTER_RULE\n"
	"       %s -l\n"
	"\t-v		Show version\n"
	"\t-l		List available INTERFACEs\n"
	"\t-h		Display this message\n"
	"\t-i		Capture interface (default: first interface)\n"
	"\t-p		Destination UDP port (default: 37008)\n"
	"\t-E		Use ERSPAN protocol (default: TZSP)\n"
	"\t-s		Silent: do not print counters during processing\n"
	"\tDEST_HOST	Send UDP flow to specified host\n"
	"\tFILTER_RULE	Filter rule for pcap library\n"
	"\n",
	prog, prog);
}

void version() {
    fprintf(stdout, "rsniffer: version %s, build %s, by %s\n", VERSION, BUILD, AUTHOR);
}

void list_devs() {
    char	errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t	*alldevs;
    pcap_if_t	*d;
    int		i=0;
 
    // Get list of pcap devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1){
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
	return;
    }
 
    // Print result
    printf("List of pcap devices:\n");
    for(d= alldevs; d != NULL; d= d->next)
    {
	i++;
        printf("dev [%s]", d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf("\n");
    }

    // Msg if no devices were found
    if (!i) {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return;
    }

    // Free resources
    pcap_freealldevs(alldevs);
}

void my_callback(u_char *args, const struct pcap_pkthdr* hdr, const u_char* packet) { 
	// Transmission buffer

	static int count = 1;
	static long bytes = 0;
	if (!flagSilent) {
	    fprintf(stdout, "\r%4u (%lu bytes)", count, bytes);
	    fflush(stdout);
	}
	count++; 
	bytes += hdr->caplen;

	int offset = 0;
	if (flagProto == PROTO_ERSPAN) {
	    gre.seq = ntohl(htonl(gre.seq)+1);
	    memcpy(txBuf, &gre, sizeof(gre));
	    offset += sizeof(gre);
	    memcpy(txBuf + offset, &ers, sizeof(ers));
	    offset += sizeof(ers);
	} else {
	    memcpy(txBuf, &tzspHdr, sizeof(tzspHdr));
	    offset += sizeof(tzspHdr);
	}
	memcpy(txBuf + offset, packet, (hdr->caplen<MAX_CAPTURE_BUFFER_SIZE)?hdr->caplen:MAX_CAPTURE_BUFFER_SIZE);

        if (sendto(streamSocket, txBuf, offset + hdr->caplen, 0 , (struct sockaddr *) &streamDestination, sizeof(streamDestination))==-1)
        {
            printf("Fatal error: can't send data via socket!\n");
	    exit(1);
        }

}

int main(int argc,char **argv) { 

	unsigned int dest_port;
	char *dest_host;

	int i;
	char *dev; 
	char *filter_rule;
	char errbuf[PCAP_ERRBUF_SIZE]; 
	pcap_t* descr; 
	const u_char *packet; 
	struct pcap_pkthdr hdr;
	struct ether_header *eptr; /* net/ethernet.h */ 
	struct bpf_program fp;     /*выражение фильтрации в составленном виде */ 
	bpf_u_int32 maskp;         /*маска подсети */ 
	bpf_u_int32 netp;          /* ip */ 

	// Init parameters
	dest_port	= TZSP_DEFAULT_PORT;
	dest_host	= NULL;
	flagSilent	= 0;
	flagProto	= PROTO_TZSP;

	// Load command-line parameters
	int ch;
	while ((ch = getopt(argc, argv, "vslhEi:p:")) != -1) {
	    switch (ch) {
		case 'v':	version();
				exit(1);
				break;
		case 'E':	flagProto = PROTO_ERSPAN;
				break;

		case 's':	flagSilent = 1;
				break;

		case 'h':	usage(argv[0]);
				exit(1);
				break;

		case 'l':	list_devs();
				exit(1);
				break;

		case 'p':	if (sscanf(optarg, "%u", &dest_port) != 1) {
				    printf("Invalid value for '-i PORT' tag.\n");
				    usage(argv[0]);
				    exit(1);
				}
				break;
		
		case 'i':	dev = strdup(optarg);
				break;

	    }
	}

	// Search for default dev if device is not specified
	if ((dev == NULL) && ((dev = pcap_lookupdev(errbuf)) == NULL)) {
		fprintf(stderr, "Error during lookup for default dev: %s\n", errbuf);
		exit(1);
	} 


	// Check if HOST and FILTER are specified
	if ((argc < 2) || (argc <= optind)) {
	    printf("Error: DEST_HOST is not specified.\n");
	    exit(1);
	}

	if (argc <= (optind+1)) {
	    printf("Error: FILTER_RULE is not specified.\n");
	    exit(1);
	}    
	dest_host = strdup(argv[optind]);
	filter_rule = strdup(argv[optind+1]);

	// Print PCAP desired configuration
	printf("Sniffing device : %s\n", dev);
	printf("Sniffing filter : %s\n", filter_rule);
	printf("Destination host: %s udp/%u\n", dest_host, dest_port);

	// Get device info
	pcap_lookupnet(dev, &netp, &maskp, errbuf); 

	// Check device type, for "-" use `offline` mode
	if (strcmp(dev, "-") == 0) {
	    descr = pcap_open_offline("-", errbuf);
	    if (descr == NULL) {
		printf("pcap_open_offline(): cannot open STDIN with error: %s\n", errbuf);
		exit(1);
	    }
	} else {
	    // Open PCAP session
	    descr = pcap_open_live(dev, BUFSIZ, 1,-1, errbuf); 
	    if(descr == NULL) {
		printf("pcap_open_live(): cannot open device [%s] with error: %s\n", dev, errbuf);
		exit(1);
	    }
	}

	// Prepare filter condition
	if(pcap_compile(descr, &fp, filter_rule, 0, netp) == -1) {
		fprintf(stderr, "Error calling pcap_compile\n");
		exit(1);
	} 

	// Apply filter
	if(pcap_setfilter(descr, &fp) == -1) {
		fprintf(stderr, "Error setting filter\n");
		exit(1);
	} 

	// Init socket stream for ougoing traffic
	if (flagProto == PROTO_TZSP) {
	    if ((streamSocket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
		perror("Cannot init UDP socket.\n");
		exit(1);
	    }
	} else {
	    if ((streamSocket = socket(PF_INET, SOCK_RAW, IPPROTO_GRE)) == -1) {
		perror("Cannot init RAW/ERSPAN socket.\n");
		exit(1);
	    }
	    
	    gre.hdr = ntohs(0x1000);
	    gre.proto = ntohs(0x88be);
	    gre.seq = ntohl(0);

	    ers.ver = ntohs(0x1017);
	    ers.dir = ntohs(0x0864);
	    ers.unk = 0;
	}
	memset((char *) &streamDestination, 0, sizeof(streamDestination));

	streamDestination.sin_family = AF_INET;
	streamDestination.sin_port = htons(dest_port);
     
	if (inet_aton(dest_host, &streamDestination.sin_addr) == 0) 
	{
    	    fprintf(stderr, "inet_aton() failed\n");
    	    exit(1);
	}

	tzspHdr.version = 1;
	tzspHdr.type = 0;
	tzspHdr.encapH = 0;
	tzspHdr.encapL = 1;
	tzspHdr.tagEnd = 1;

	txBuf = malloc(MAX_CAPTURE_BUFFER_SIZE + sizeof(tzspHdr));

	// Last message
	printf("Starting loop..\n");
	fflush(stdout);

	// Run loop
	pcap_loop(descr, -1, my_callback, NULL); 
	return 0; 
}

