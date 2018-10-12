#include "gbn.h"
state_t s;
uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}


void sig_handler(int signum){
	s.timed_out = 0;
	printf("Timeout has occurred\n");
	alarm(TIMEOUT);
	signal(SIGALRM, sig_handler);
}


gbnhdr * make_packet(uint8_t type, uint8_t seqnum, int isHeader, char *buffer, int datalen){
	printf("datalen %i\n", datalen);
	gbnhdr *packet = malloc(sizeof(gbnhdr));
	packet->type = type;
	packet->seqnum = seqnum;

	if (isHeader == 0) packet->checksum = 0;
	else {
		memcpy(packet->data, buffer, datalen);
		packet->datalen = datalen;
		packet->checksum = checksum((uint16_t *) buffer, datalen);
	}
	return packet;
}


int is_timeout() {
	if (s.timed_out == 0) {
		s.timed_out = -1;
		return 0;
	}
	return -1;
}

/*
 * params:
 * 1.packet,
 * 2.expected type
 */
int check_packetType(gbnhdr *packet, int type) {
	if (packet->type != type) return -1;
	return 0;
}

/*
 * params: 1. packet, 2. expected expected number
 * rec_seqnum should be expected seqnum
 * seq for ACK should be last sent seqnum
 */
int check_seqnum(gbnhdr *packet, int expected) {
	if (packet->seqnum != expected) return -1;
	return 0;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	/* split data into multiple packets */
	int numPackets = (int) len / DATALEN;
	printf("in send and ready to send %i packets\n", numPackets);
	int lastPacketSize = len % DATALEN;
	if (len % DATALEN != 0) numPackets ++;
	int attempts[numPackets];
	memset(attempts, 0, numPackets * sizeof(int));
	char * slicedBuf = malloc(DATALEN);
	int i = 0;

	while (i < numPackets) {
		int j = 0;

		while ( i < numPackets && j < s.mode) {
			printf("sending packet %i\n", i);
			if (attempts[i] >= MAX_ATTEMPT) {
				s.state = CLOSED;
				free(slicedBuf);
				return -1;
			}
			
			int currSize = DATALEN;
			if (i == numPackets -1) currSize = lastPacketSize;
			
			memset(slicedBuf, '\0', currSize);
			memcpy(slicedBuf, buf + i * DATALEN, currSize);

			gbnhdr *packet = make_packet(DATA, s.send_seqnum, -1, slicedBuf, currSize);
			if (attempts[i] < MAX_ATTEMPT &&
						sendto(sockfd, packet, sizeof(*packet), flags, s.senderServerAddr, s.senderSocklen) == -1) {
				attempts[i] ++;
				free(packet);
				continue;
			}
			if (j == 0) alarm(TIMEOUT);
			s.send_seqnum ++;
			j++;
			i++;
			free(packet);
		}

		int unACK = j;
		while (unACK > 0) {
			/* receive ack header */
			gbnhdr *rec_header = malloc(sizeof(gbnhdr));
			recvfrom(sockfd, (char *)rec_header, sizeof(gbnhdr), 0, s.receiverServerAddr, &s.receiverSocklen);
			/* verify there is no timeout, verify type = dataack and seqnum are expected */
			if (is_timeout() == -1 && check_packetType(rec_header, DATAACK) == 0
			&& check_seqnum(rec_header, s.rec_seqnum) == 0) {
				printf("received successfully\n");
				s.mode = s.mode == SLOW ? MODERATE : FAST;
				s.rec_seqnum ++;
				unACK --;
				alarm(TIMEOUT); 
			} else {
				i -= s.send_seqnum - s.rec_seqnum;
				s.send_seqnum = s.rec_seqnum;
				s.mode = SLOW;
				free(rec_header);
				attempts[i] ++;
				break;
			}
			free(rec_header);
		}
	}
	free(slicedBuf);
	return 0;
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){
	/* receiver receive packet from sender and if valid, send DATAACK */
	printf ("in receive\n");
	gbnhdr * sender_packet = malloc(sizeof(gbnhdr));
RECV:
	if (recvfrom(sockfd, (char *)sender_packet, sizeof(gbnhdr), 0, s.receiverServerAddr, &s.receiverSocklen) == -1) {
		goto RECV;
	}
	printf("after recvfrom\n");

	/* if a data packet is received, check packet to verify its type */
	if (check_packetType(sender_packet, DATA) == 0){
		/* check data validity */
		if (check_seqnum(sender_packet, s.rec_seqnum) == -1) {
			 printf("received an unexpected seqnum, discarding data...\n");
			return 0;
		}
		int sender_packet_size = sender_packet->datalen;
		if (checksum(buf, sender_packet_size) == -1) {
			printf("data is corrupt\n");
			return 0;
		}

		memcpy(buf, sender_packet->data, sender_packet_size);
		printf("%s\n", sender_packet->data);
		/* receiver reply with DATAACK header with seqnum received */
		gbnhdr *rec_header = make_packet(DATAACK, s.rec_seqnum, 0, NULL, 0);

		if (sendto(sockfd, rec_header, sizeof(gbnhdr), 0, s.receiverServerAddr, s.receiverSocklen) == -1) {
			printf ("error sending in gbn_recv\n");
			return -1;
		}
		printf("sent data with seqnum %i\n", s.rec_seqnum);
		free(rec_header);
		/* if successfully send ACK, expected next rec_seqnum ++ */
		s.rec_seqnum ++;
		return sender_packet_size;
	}
	printf("%d\n", sender_packet->type);
	printf("after check packet\n");

	/* if a connection teardown request is received, reply with FINACK header */
	if (check_packetType(sender_packet, FIN) == 0) {
		printf("reply with FINACK header \n");
		gbnhdr *rec_header = make_packet(FINACK, 0, 0, NULL, 0);
		if (sendto(sockfd, rec_header, sizeof(gbnhdr), 0, s.receiverServerAddr, s.receiverSocklen) == -1) return -1;
		s.state = FIN_RCVD;
		return 0;
	}

	return(-1);
}


/* TODO use 4 hand shakes to ternminate */
int gbn_close(int sockfd){
	printf("in connection close\n");
    	printf("state %i\n", s.state);
	/* sender initiate a FIN request and wait for FINACK */
	if (s.state == ESTABLISHED || s.state == SYN_SENT || s.state == SYN_RCVD) {
		printf("sending fin to close connection \n");
		gbnhdr * send_header = make_packet(FIN, 0, 0, NULL, 0);
		if (sendto(sockfd, send_header, sizeof(gbnhdr), 0, s.senderServerAddr, s.senderSocklen) == -1) return -1;

		s.state = FIN_SENT;
		printf("fin sent to close connection\n");
	}
	/* if receiver sees a FIN header, reply with FINACK and close socket connection */
	else if (s.state == FIN_SENT) {
		printf("sending finack to close connection \n");
		gbnhdr * rec_header = make_packet(FINACK, 0, 0, NULL, 0);
		if (sendto(sockfd, rec_header, sizeof(gbnhdr), 0, s.receiverServerAddr, s.receiverSocklen) == -1) return -1;
		printf("finack sent to close connection\n");
		close(sockfd);
	}
	return(-1);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){
	if (sockfd < 0) return -1;
	printf("in gbn connect\n");
	/* Define Global State */
	s.mode = SLOW;
	s.senderServerAddr = (struct sockaddr *)server;
	s.senderSocklen = socklen;

	gbnhdr *send_header = make_packet(SYN, 0, 0, NULL, 0);

	signal(SIGALRM, sig_handler);


	int attempt = 0;
	s.timed_out = -1;

	/* send SYN and wait for SYNACK. after that, send a SYNACK back. */
	while (attempt < MAX_ATTEMPT) {
		if (sendto(sockfd, send_header, sizeof(send_header), 0, server, s.senderSocklen) == -1 ) {
			attempt ++;
			printf("sender send syn failed\n");
			continue;
		}
		s.state = SYN_SENT;
		printf("sender sent syn header\n");
		alarm(TIMEOUT);
		/* waiting for receiving SYNACK */
		gbnhdr *rec_header = malloc(sizeof(gbnhdr));

		if (recvfrom(sockfd, (char *)rec_header, sizeof(rec_header), 0, s.receiverServerAddr, &s.receiverSocklen) == -1) {
			printf("sender error in recvfrom syn ack\n");
			attempt ++;
			continue;
		}
		/* check for timeout, check if header type is SYNACK */
		if (check_packetType(rec_header, SYNACK) == 0) {
			printf("sender received synack header\n");
			s.state = ESTABLISHED;
			printf("sender connection established\n");
			send_header = make_packet(SYNACK, 0, 0, NULL, 0);
			sendto(sockfd, send_header, sizeof(send_header), 0, server, s.senderSocklen);
			return 0;
		} else if (1) {
			/* TODO if receive data, turn to rcvd mode */
		}
		attempt ++;
	}
	/* if reach max number of tries, close the connection */
	s.state = CLOSED;
	return(-1);
}

int gbn_listen(int sockfd, int backlog){
	printf("in listen\n");

	/* receiver receive from (listen to) header of the request to connect */
	gbnhdr *send_header = malloc(sizeof(gbnhdr));
	if (recvfrom(sockfd, (char *)send_header, sizeof(gbnhdr), 0, s.receiverServerAddr, &s.receiverSocklen) == -1) {
		printf("error rec syn from sender\n");
		return -1;
	}

	if (check_packetType(send_header, SYN) == 0) {
		s.state = SYN_RCVD;
		printf("received syn header\n");
		return 0;
	}

	return -1;
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){

    /* pointer to local struct on receiver server where sender address is to be stored */
    s.receiverServerAddr = (struct sockaddr *)server;
    s.receiverSocklen = socklen;
    printf("in bind\n");
    s.timed_out = -1;
    return bind(sockfd, server, socklen);
}	

int gbn_socket(int domain, int type, int protocol){
		
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));

    return socket(domain, type, protocol);
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){
	/*
	 * receiver send to sender either RST or SYNACK based on global state
	 * if accept, initialize the receiver sequence number to 0
	*/
	s.rec_seqnum = 0;
	gbnhdr * rec_header;
	printf("in accept\n");

	/* if connection teardown initiated, reject connection by sending RST */
	if (s.state == FIN_SENT) rec_header = make_packet(RST, 0, 0, NULL, 0);
	/* accept connection initiation by sending header with SYNACK */
	else rec_header = make_packet(SYNACK, 0, 0, NULL, 0);

	client = s.receiverServerAddr;

	signal(SIGALRM, sig_handler);


	int attempt = 0;
	s.timed_out = -1;

	/* send SYNACK and wait for SYNACK. */
	while (attempt < MAX_ATTEMPT) {
		if (sendto(sockfd, rec_header, sizeof(gbnhdr), 0, client, *socklen) == -1 ) {
			attempt ++;
			printf("receiver send synack failed\n");
			continue;
		}
		printf("receiver sent synack header\n");
		alarm(TIMEOUT);
		/* waiting for receiving SYNACK */
		gbnhdr *send_header = malloc(sizeof(gbnhdr));

		if (recvfrom(sockfd, (char *)send_header, sizeof(send_header), 0, s.senderServerAddr, &s.senderSocklen) == -1) {
			printf("receiver error in recvfrom syn ack\n");
			attempt ++;
			continue;
		}
		/* check for timeout, check if header type is SYNACK */
		if (check_packetType(send_header, SYNACK) == 0) {
			printf("receiver received synack header\n");
			s.state = ESTABLISHED;
			printf("receiver connection established\n");
			free(rec_header);
			return 0;
		} 
		attempt ++;
	}

	free(rec_header);

	return -1;
}

ssize_t maybe_recvfrom(int  s, char *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen){

	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX){


		/*----- Receiving the packet -----*/
		int retval = recvfrom(s, buf, len, flags, from, fromlen);

		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX){
			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buf[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buf[index] = c;
		}

		return retval;
	}
	/*----- Packet lost -----*/
	return(len);  /* Simulate a success */
}