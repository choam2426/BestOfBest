#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>

char *hostname = NULL; //argv[1] 저장용
//GET, POST, PUT
char signature[3][4] = {{0x47, 0x45, 0x54, 0x20}, {0x50, 0x4F, 0x53, 0x54}, {0x50, 0x55, 0x54, 0x20}};
char DELETE_sig[6] = {0x44, 0x45, 0x4C, 0x45, 0x54, 0x45};

//data에 "Host: " + argv[1] 있는지 확인
int find_str(unsigned char* buf){
	int length = 7 + strlen(hostname);
	char s[length];
	snprintf(s, sizeof(s), "Host: %s", hostname);
	if (strstr((char *)buf, s) != NULL) {
		printf("DROP!!!!!!!!!!!!!!!!!!!!");
        return 1;
    	}
    return 0;
}

//차단할 패킷인지 판정하는 함수
u_int32_t judge(struct nfq_data *tb) {
	unsigned char *data;
	int ret;
	ret = nfq_get_payload(tb, &data);
	char ip_hdr_ver = data[0] >> 4; //version
        char ip_hdr_len = (data[0] & 0b00001111)*4; //IP header length
	char data_off = ((data[ip_hdr_len+12]>>4)*4)+ip_hdr_len; //IHL + THL = data_offset
	
	if (ip_hdr_ver == 4){ //IPv4
		for(int i=0; i<3; i++){ //GET, POST, PUT 인지 확인
			if (memcmp(signature[i], &data[data_off], 4) == 0){
				if(find_str(&data[data_off])){
					return NF_DROP; //차단
				}
			}
		}
		//DELETE 메소드인지 확인
		if (memcmp(DELETE_sig, &data[data_off], 6) == 0){
			if(find_str(&data[data_off])){
				return NF_DROP;
			}
		}
	}
        return NF_ACCEPT; //패킷 허용
}


static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		printf("payload_len=%d ", ret);
	}
	fputc('\n', stdout);

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	u_int32_t result = judge(nfa); //패킷 처리 판단
	printf("entering callback\n");
	return nfq_set_verdict(qh, id, result, 0, NULL);
}


int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	hostname = strdup(argv[1]);
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			printf("\n");	
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
