#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <libnet.h>
#include <pcap.h>
#include <pthread.h>


#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
#define TH_OFF(th)		(((th)->th_offx2 & 0xf0) >> 4)

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};

/* TCP header */
struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	u_int32_t th_seq;	/* sequence number */
	u_int32_t th_ack;	/* acknowledgement number */

	u_char th_offx2;	/* data offset, rsvd */
	u_char th_flags;
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};


#define SOCKET_SCAN 	1
#define SYN_SCAN 	2
#define FIN_SCAN	3

#define UNKNOWN 	1
#define OPEN 		2
#define CLOSE		3

struct scaninfo_struct{
	// scan parameter from user input 
	int scan_type;
	char interface[32]; 
	struct in_addr ipaddr;   
	char ipaddr_string[32]; // The same content with ipaddr, but with different format
	int startport;
	int endport;
	int portnum;  // endport - startport +1

	//only used in syn-fin scan
	int sourceport;
	pthread_cond_t *cond;
	int flags;  //used to set tcp flags

	// for keeping scanning result
	int *portstatus;
	int alreadyscan;
};

const int S_SUCCESS = 0;
const int S_FAILURE = 1;


/*
 * get the IP address of the network device
 */
void getLocalIp(char *ip, const char *dev)
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1)
	{
		printf("Can not get local ip address \n");
		return;
	}

	struct ifreq ifr;
	memset(&ifr.ifr_name, 0, sizeof(ifr.ifr_name));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if (ioctl(sock, SIOCGIFADDR, &ifr) == -1)
	{
		printf("Can not get local ip address \n");
		return;
	}

	struct sockaddr_in sin;
	memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
	const char *tmp = inet_ntoa(sin.sin_addr);
	strncpy(ip, tmp, 16);
}

int sendPacket(const char *ip_src, const char *ip_dst,	u_int16_t port_src, u_int16_t port_dst, u_int8_t flags, char *device)
{

	libnet_t *l;
	char errbuf[LIBNET_ERRBUF_SIZE];

	int ack;

	
	// initialization
	l = libnet_init(LIBNET_RAW4, device, errbuf);
	if (l == NULL)
	{
		printf("libnet init: %s \n", errbuf);
		libnet_destroy(l);
		return S_FAILURE;
	}


	/* build TCP header
		Set ack 0, if it is a SYN packet. Else set ack a random value.
		Set random value to the sequence number and window.
	*/
	if (flags == TH_SYN) 
		ack = 0;
	else 
		ack = rand() % 200000 + 200000;

	libnet_ptag_t tcp_tag = libnet_build_tcp(
			port_src,
			port_dst,
			rand() % 200000 + 200000,
			ack,
			flags,
			rand() % 3000 + 5000,
			0,
			0,
			LIBNET_TCP_H,
			NULL,
			0,
			l,
			0
			);


	if (tcp_tag == -1)
	{
		printf("building tcp header error \n ");
		libnet_destroy(l);
		return S_FAILURE;
	}

	// build IPv4 header
	libnet_ptag_t ipv4_tag = libnet_build_ipv4(
			LIBNET_IPV4_H + LIBNET_TCP_H,
			0,
			0,
			0,
			64,
			IPPROTO_TCP,
			0,
			libnet_name2addr4(
				l,
				(char *)ip_src,
				LIBNET_DONT_RESOLVE
				),
			libnet_name2addr4(
				l,
				(char *)ip_dst,
				LIBNET_DONT_RESOLVE
				),
			NULL,
			0,
			l,
			0
			);

	if (ipv4_tag == -1)
	{
		printf("building ipv4 header error \n");
		libnet_destroy(l);
		return S_FAILURE;
	}

	// send the packet
	int retval = libnet_write(l);
	if (retval == -1)
	{
		printf("sending packet error");
		libnet_destroy(l);
		return S_FAILURE;
	}

	libnet_destroy(l);
	return S_SUCCESS;
}

/*
 * send the packets
 */
void *sendthread(void *args)
{
	struct scaninfo_struct *pscaninfo = (struct scaninfo_struct *)args;
	char src_ip[16];
	struct ifreq ifr;
	int i;
	int sock;
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1)
	{
		printf("Can not get local ip address \n");
		return;
	}

	memset(&ifr.ifr_name, 0, sizeof(ifr.ifr_name));
	strncpy(ifr.ifr_name, pscaninfo->interface, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFADDR, &ifr) == -1)
	{
		printf("Can not get local ip address \n");
		return;
	}

	struct sockaddr_in sin;
	memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
	const char *tmp = inet_ntoa(sin.sin_addr);
	strncpy(src_ip, tmp, 16);


//	getLocalIp(src, pscaninfo->interface);

	for (i = pscaninfo->startport; i <= pscaninfo->endport; i++)
	{
		sendPacket(src_ip, pscaninfo->ipaddr_string, pscaninfo->sourceport, i, pscaninfo->flags,pscaninfo->interface);
	}

	return NULL;
}

/*
 * receive the packets
 * see usage of libpcap
 */

void packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
	struct scaninfo_struct *pscaninfo = (struct scaninfo_struct *)args;

	const int SIZE_ETHERNET = 14;

	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;

	u_int size_ip;
	u_int size_tcp;

	ethernet = (struct sniff_ethernet *)(packet);
	ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %d bytes \n",size_ip);
		return;
	}
	tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %d bytes \n",size_tcp);
		return;
	}

	int sp = ntohs(tcp->th_sport);
	int dp = ntohs(tcp->th_dport);

	int startPort = pscaninfo->startport;
	int endPort = pscaninfo->endport;
	if (pscaninfo->scan_type == SYN_SCAN)
	{
		if (dp == pscaninfo->sourceport)
		{
			/* for SYN packets, the open ports always
			 * return a SYN|ACK packet. */
			if (tcp->th_flags == (TH_SYN | TH_ACK))
				pscaninfo->portstatus[sp - pscaninfo->startport] = OPEN;
			/* the closed ports always
			 * return a packet with RST. */
			else if ((tcp->th_flags & TH_RST) != 0)
				pscaninfo->portstatus[sp - pscaninfo->startport] = CLOSE;
			/* for other instance, it seems UNKNOWN. */
			else
				pscaninfo->portstatus[sp - pscaninfo->startport] = UNKNOWN;
			pscaninfo->alreadyscan++;			
		}
	}
	else if (pscaninfo->scan_type == FIN_SCAN)
	{
		if (dp == pscaninfo->sourceport)
		{
			/* it seams that the FIN scan
			 * can only find ports closed. */
			if ((tcp->th_flags & TH_RST) != 0)
				pscaninfo->portstatus[sp - pscaninfo->startport] = CLOSE;
			else
				pscaninfo->portstatus[sp - pscaninfo->startport] = UNKNOWN;
			pscaninfo->alreadyscan++;			
		}
	}

	/* all the numOfPorts ports are scanned,
	 * wake up the main thread. */
	if (pscaninfo->alreadyscan >= pscaninfo->portnum)
		pthread_cond_signal(pscaninfo->cond);
}
void *receivethread(void *args)
{
	struct scaninfo_struct *pscaninfo = (struct scaninfo_struct *)args;

	bpf_u_int32 net;
	bpf_u_int32 mask;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_lookupnet(pscaninfo->interface, &net, &mask, errbuf);

	pcap_t *handle;
	handle = pcap_open_live(pscaninfo->interface, 100, 1, 0, errbuf);
	if (handle == NULL)
	{
		printf("pcap open device failure \n");
		return NULL;
	}

	struct bpf_program fp;
	char filter[100] = "tcp port ";
	char tmp[20];
	snprintf(tmp, sizeof(tmp), "%d", pscaninfo->sourceport);
	strcat(filter, tmp);
	strcat(filter, " and src host ");
	strcpy(tmp,pscaninfo->ipaddr_string);
	strcat(filter, tmp);

	int retval = 0;
	retval = pcap_compile(handle, &fp, filter, 0, net);
	if (retval == -1)		return NULL;
	retval = pcap_setfilter(handle, &fp);
	if (retval == -1) return NULL;

	pcap_loop(handle, 0, packet_handler, (u_char *)pscaninfo);

	return NULL;
}





/*
void socket_scan(struct scaninfo_struct *pscaninfo);
void synfin_scan(struct scaninfo_struct *pscaninfo);
void *sendthread(void *args);
void *receivethread(void *args);
void getLocalIp(char *ip, const char *dev);
void packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet);
void sendPacket( const char *ip_src, const char *ip_dst,	u_int16_t sp, u_int16_t dp, u_int8_t flags, char *interface);
*/

//usage: command scan_type interface IPaddr startport endport

int parse_scanpara(int argc, char *argv[],struct scaninfo_struct *pparse_result){
	if (argc != 6) {
		printf("The count of parameters error!\n");
		return 1;
	}
	if (!strcmp(argv[1],"SOCKET_SCAN"))
		pparse_result->scan_type = SOCKET_SCAN;
	else if (!strcmp(argv[1],"SYN_SCAN"))
		pparse_result->scan_type = SYN_SCAN;

	else if (!strcmp(argv[1],"FIN_SCAN"))
		pparse_result->scan_type = FIN_SCAN;
	else {
		printf("An Unsupported scan tyep!\n");
		return 1;
	}

	strcpy(pparse_result->interface, argv[2]);
	strcpy(pparse_result->ipaddr_string,argv[3]);
	if (inet_aton(argv[3],&pparse_result->ipaddr) ==0 )
	{
		printf("IPaddr format error! please check it! \n");
		return 1;
	} 
	pparse_result->startport = atoi(argv[4]);
	pparse_result->endport = atoi(argv[5]);
	pparse_result->portnum = pparse_result->endport - pparse_result->startport + 1;
	if (pparse_result->scan_type == SYN_SCAN)
		pparse_result->flags = TH_SYN;
	else  if (pparse_result->scan_type == FIN_SCAN)
		pparse_result->flags = TH_FIN;
	return 0;

}

void initial_portstatus(struct scaninfo_struct *pscaninfo){
	int i; 
	pscaninfo->portstatus = (int *) malloc(pscaninfo->portnum * 4);
	for (i = 0; i < pscaninfo->portnum; i++)
		pscaninfo->portstatus[i] = UNKNOWN;
	pscaninfo->alreadyscan = 0;
}

void output_scanresult(struct scaninfo_struct scaninfo){
	int i;
	printf(" Scan result ot the host(%s):\n", scaninfo.ipaddr_string);
	printf("    port               status\n");
	for (i = 0; i < scaninfo.portnum; i++) {
		if (scaninfo.portstatus[i] == OPEN)
			printf("	%d   		open\n",scaninfo.startport+i);
		else if (scaninfo.portstatus[i] == CLOSE)
			printf("	%d   		close\n",scaninfo.startport+i);
		else
			printf("	%d   		unknown\n",scaninfo.startport+i);
	}
}
void socket_scan(struct scaninfo_struct *pscaninfo){
	int i;
	for (i = pscaninfo->startport; i <= pscaninfo->endport; i++)
	{
		struct sockaddr_in addr;
		int sock = socket(AF_INET, SOCK_STREAM, 0);
		if (sock == -1)
		{
			printf("create socket error! \n");
			return ;
		}

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(i);
		inet_pton(AF_INET, pscaninfo->ipaddr_string, &addr.sin_addr);

		int retval = connect(sock, (const struct sockaddr *)(&addr), sizeof(addr));
		if (retval == 0)
			pscaninfo->portstatus[i- pscaninfo->startport] = OPEN;
		else
			pscaninfo->portstatus[i- pscaninfo->startport]= CLOSE;
		close(sock);
			
	}
}


void synfin_scan(struct scaninfo_struct *pscaninfo){
	pthread_t s_thread;
	pthread_t r_thread;

	pthread_cond_t cond;
	pthread_mutex_t mutex;

	/* set the timeout value */
	struct timespec to;
	struct timeval now;

	pthread_mutex_init(&mutex, NULL);
	pthread_cond_init(&cond, NULL);
	pscaninfo->cond = &cond;

	srand(time(NULL));
	pscaninfo->sourceport = rand() % 2000 + 2000;

	/* create the receiving thread */
	pthread_create(&r_thread, NULL, receivethread, (void *)(pscaninfo));
	/* wait for 200ms,
	 * if not, it seems that the first
	 * several packets can not be captured. */
	usleep(200000);
	/* create the sending thread,
	 * it should return shortly */
	pthread_create(&s_thread, NULL, sendthread, (void *)(pscaninfo));
	pthread_join(s_thread, NULL);

	gettimeofday(&now, NULL);
	to.tv_sec = now.tv_sec;
	to.tv_nsec = now.tv_usec * 1000;
	to.tv_sec += 1;

	/* wait until timeout */
	pthread_cond_timedwait(&cond, &mutex, &to);
	pthread_cancel(r_thread);

	pthread_cond_destroy(&cond);
	pthread_mutex_destroy(&mutex);
}
int main(int argc,char *argv[]){

	struct scaninfo_struct scaninfo;

	if (parse_scanpara(argc, argv,&scaninfo)) {
		printf("Usage %s SOCKET_SCAN/SYN_SCAN/FIN_SCAN interface IPaddr startport endport",argv[0]);
		exit(1);
	}
	initial_portstatus(&scaninfo);

	if (scaninfo.scan_type == SOCKET_SCAN)
		socket_scan(&scaninfo);
	else if ((scaninfo.scan_type == SYN_SCAN ) || (scaninfo.scan_type == FIN_SCAN))
		synfin_scan(&scaninfo);
	else {
		printf("Unsupported scan type! \n");
		exit(1);
	}	 
	
	output_scanresult(scaninfo);	
}





