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


#define IP_RF 0x8000		
#define IP_DF 0x4000		
#define IP_MF 0x2000		
#define IP_OFFMASK 0x1fff

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

/* 帧头格式 */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* 目标MAC地址 */
	u_char ether_shost[ETHER_ADDR_LEN]; /* 源MAC地址 */
	u_short ether_type; /* 上层协议类型 */
};

/* IP 头格式 */
struct sniff_ip {
	u_char ip_vhl;		/* 高4位为IP协议版本，低4位为IP头长度 */
	u_char ip_tos;		/* 服务类型 */
	u_short ip_len;		/* 长度 */
	u_short ip_id;		/* 分片标识 */
	u_short ip_off;		/* 高3位分片标识，低13位为分片偏移量 */
	u_char ip_ttl;		/* IP报文生存周期 */
	u_char ip_p;		/* 上层协议类型标识 */
	u_short ip_sum;		/* 校验和 */
	struct in_addr ip_src,ip_dst; /* IP源地址和IP目标地址 */
};
/* ICMP 头格式 */
struct sniff_icmp
{
    u_int8_t icmp_type;  /* ICMP类型 */
    u_int8_t icmp_code;  /* ICMP代码 */
    u_int16_t icmp_sum;  /* 校验和 */
	//u_int16_t icmp_id;	 /* 标识 */
	//u_int16_t icmp_seq;	 /* 序列号 */
};
/* UDP 头格式 */
struct sniff_udp
{
    u_int16_t udp_sport;  /* 源端口号 */
    u_int16_t udp_dport;  /* 目的端口号 */
    u_int16_t udp_len;    /* 长度 */
    u_int16_t udp_sum;	  /* 校验和 */
};


#define UDP_SCAN 1

#define UNKNOWN 	1
#define OPEN 		2
#define CLOSE		3
/* 扫描信息结构 */
struct scaninfo_struct{
	int scan_type;
	char interface[32]; 
	struct in_addr ipaddr;   
	char ipaddr_string[32];
	int startport;
	int endport;
	int portnum;

	pthread_cond_t *cond;

	int *portstatus;
	int alreadyscan;
};
 /* UDP探测报文发送函数 */
 void send_udp(struct scaninfo_struct *pscaninfo){
	int i;
	for (i = pscaninfo->startport; i <= pscaninfo->endport; i++)
	{
		usleep(1000000); //由于Linux系统限制了ICMP目标不可达报文的发送速率，所以应该根据情况控制UDP探测报文的发送速率。
		struct sockaddr_in addr;
		int sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (sock == -1)
		{
			printf("create socket error! \n");
			return ;
		}

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(i);
		inet_pton(AF_INET, pscaninfo->ipaddr_string, &addr.sin_addr);
		
		int retval = sendto(sock,NULL,0,0,(const struct sockaddr *)(&addr), sizeof(addr));//UDP报文发送
		if (retval<0) 
			printf("Send message to Host Failed !");
		close(sock);	
	}
}

//ICMP报文处理函数
void packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{	
	struct scaninfo_struct *pscaninfo = (struct scaninfo_struct *)args;

	const int SIZE_ETHERNET = 14;

	const struct sniff_ethernet *ethernet; //帧头指针
	const struct sniff_ip *ip;				//IP头指针
	const struct sniff_icmp *icmp;			//ICMP指针
	const struct sniff_ip *ipw;				//产生差错的报文的IP头指针
	const struct sniff_udp *udp;			//UDP头指针

	u_int size_ip;
	u_int size_icmp;
	u_int size_ipw;

	ethernet = (struct sniff_ethernet *)(packet);
	ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20) return;
	//判断ICMP报文是否为目的不可达差错控制报文
	icmp = (struct sniff_icmp *)(packet+SIZE_ETHERNET+size_ip);
	if (icmp->icmp_type != 3) return;
	
	ipw = (struct sniff_ip *)(packet+SIZE_ETHERNET+size_ip+8);
	size_ipw = IP_HL(ipw) * 4;
	if (size_ipw < 20) return;
	//获取产生差错的报文的目的IP地址
	struct in_addr ip_check = ipw->ip_dst;
	//获取目的不可达差错控制报文的UDP首部
	udp = (struct sniff_udp *)(packet+SIZE_ETHERNET+size_ip+8+size_ipw);
	//获取UDP首部的目的端口号
	int dstport = ntohs(udp->udp_dport);
	
	if (ip_check.s_addr == (pscaninfo->ipaddr).s_addr)
	{//判断ICMP不可达报文的差错报文的目的IP地址是否与UDP发送报文一致
		if (icmp->icmp_code == 3)//判断ICMP报文是否为端口不可达报文
			pscaninfo->portstatus[dstport - pscaninfo->startport] = CLOSE;
		else
			pscaninfo->portstatus[dstport - pscaninfo->startport] = UNKNOWN;
		pscaninfo->alreadyscan++;
	}

	if (pscaninfo->alreadyscan >= pscaninfo->portnum)
		pthread_cond_signal(pscaninfo->cond);
}
//ICMP报文捕获线程函数
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
	char filter[20] = "icmp";	//过滤函数，只捕获ICMP报文

	int retval = 0;
	retval = pcap_compile(handle, &fp, filter, 0, net);
	if (retval == -1)		return NULL;
	retval = pcap_setfilter(handle, &fp);
	if (retval == -1) return NULL;

	pcap_loop(handle, 0, packet_handler, (u_char *)pscaninfo);

	return NULL;
}
//命令行解析函数
int parse_scanpara(int argc, char *argv[],struct scaninfo_struct *pparse_result){
	if (argc != 6) {
		printf("The count of parameters error!\n");
		return 1;
	}
	if (!strcmp(argv[1],"UDP_SCAN"))
		pparse_result->scan_type = UDP_SCAN;
	else {
		printf("An Unsupported scan type!\n");
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
	return 0;

}
//扫描信息结构初始化函数
void initial_portstatus(struct scaninfo_struct *pscaninfo){
	int i; 
	pscaninfo->portstatus = (int *) malloc(pscaninfo->portnum * 4);
	for (i = 0; i < pscaninfo->portnum; i++)
		pscaninfo->portstatus[i] = UNKNOWN;
	pscaninfo->alreadyscan = 0;
}
//扫描结果输出函数
void output_scanresult(struct scaninfo_struct scaninfo){
	int i;
	printf(" Scan result of the host(%s):\n", scaninfo.ipaddr_string);
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
//UDP端口扫描函数
void udp_scan(struct scaninfo_struct *pscaninfo){

	pthread_t r_thread;

	pthread_cond_t cond;
	pthread_mutex_t mutex;

	/* 设置超时时间值 */
	struct timespec to;
	struct timeval now;
	
	/* 变量初始化  */
	pthread_mutex_init(&mutex, NULL);
	pthread_cond_init(&cond, NULL);
	pscaninfo->cond = &cond;

	/* 创建接收线程 */
	pthread_create(&r_thread, NULL, receivethread, (void *)(pscaninfo));
	/* 发送UDP探测报文 */
	send_udp(pscaninfo);
	
	/* 设置扫描超时时间  */
	gettimeofday(&now, NULL);
	to.tv_sec = now.tv_sec;
	to.tv_nsec = now.tv_usec * 1000;
	to.tv_sec += 1;
	pthread_cond_timedwait(&cond, &mutex, &to);
	
	/* 释放资源  */
	pthread_cancel(r_thread);
	pthread_cond_destroy(&cond);
	pthread_mutex_destroy(&mutex);
}

int main(int argc,char *argv[]){

	struct scaninfo_struct scaninfo;

	if (parse_scanpara(argc, argv,&scaninfo)) {
		printf("Usage %s UDP_SCAN interface IPaddr startport endport",argv[0]);
		exit(1);
	}
	initial_portstatus(&scaninfo);

	if (scaninfo.scan_type == UDP_SCAN)
	{
		udp_scan(&scaninfo);
	}
	else {
		printf("Unsupported scan type! \n");
		exit(1);
	}	 
	output_scanresult(scaninfo);	
}





