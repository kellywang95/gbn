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

// signal handler that sets time out to true
void sig_handler(int signum){
	// Timeout occurs
	s.timed_out = 0;
}

// create packet for sending headers for both receiver and sender
gbnhdr * make_packet(uint8_t type, uint8_t seqnum, int isHeader, char *buffer, int datalen){
	// allocate memory for the packet
	gbnhdr *packet = malloc(sizeof(gbnhdr));
	packet->type = type;
	packet->seqnum = seqnum;

	// if just a header, ignore check sum
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
		// reset timeout
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



	if (&s.seqnum == NULL) s.seqnum = 0;
	if (&s.mode == NULL) s.mode = SLOW;

	// split data into multiple packets
	int numPackets = (int) len / DATALEN;
	int lastPacketSize = len % DATALEN;
	if (len % DATALEN != 0) numPackets ++;
	int attempts[numPackets] = { 0 };

	char * slicedBuf = malloc(DATALEN);
	int i = 0;

	while (i < numPackets) {
		int j = 0;

		while ( i < numPackets && j < s.mode) {
			if (attempts[i] >= MAX_ATTEMPT) {
				s.state = CLOSED;
				return -1;
			}
			// set packet data size
			int currSize = DATALEN;
			if (i == numPackets -1) currSize = lastPacketSize;
			// copy an equivalent size of currSize of char buffer into the new sliced buffer
			memset(slicedBuf, '\0', currSize);
			memcpy(slicedBuf, buf + i * DATALEN, currSize);

			gbnhdr *packet = make_packet(DATA, s.seqnum, -1, slicedBuf, currSize);
			if (attempts[i] < MAX_ATTEMPT &&
						sendto(sockfd, packet, sizeof(*packet), flags, s.senderServerAddr, s.senderSocklen) == -1) {
				attempts[i] ++;
				free(packet);
				continue;
			}
			if (j == 0) alarm(TIMEOUT);
			s.seqnum ++;
			j++;
			i++;
			free(packet);
		}

		int unACK = j;
		while (unACK > 0) {
			// receive ack header
			rec_header = malloc(sizeof(gbnhdr));
			recvfrom(sockfd, rec_header, sizeof(gbnhdr), 0, s.receiverServerAddr, &s.receiverSocklen);
			// verify there is no timeout, verify type = dataack and seqnum are expected
			if (is_timeout() == -1 && check_packetType(rec_header, DATAACK) == 0
			&& check_seqnum(rec_header, s.rec_seqnum) == 0) {
				s.mode = s.mode == SLOW ? MODERATE : FAST;
				s.rec_seqnum ++;
				unACK --;
				alarm(TIMEOUT); // restart timer
			} else {
				i -= s.seqnum - s.rec_seqnum;
				s.seqnum = s.rec_seqnum;
				s.mode = SLOW;
				free(packet);
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
	// receiver receive packet from sender and if valid, send DATAACK

	gbnhdr * sender_packet = malloc(sizeof(gbnhdr));
	recvfrom(sockfd, sender_packet, sizeof(gbnhdr), 0, s.receiverServerAddr, &s.receiverSocklen);

	// if a data packet is received, check packet to verify its type
	if (check_packetType(sender_packet, DATA) == 0){
		// check data validity
		// if data seqnum is not the expected seqnum
		if (check_seqnum(sender_packet, s.rec_seqnum) == -1) return 0;
		// if data is corrupt
		int sender_packet_size = sender_packet->datalen;
		if (checksum(buf, packet_size) == -1) return 0;

		memcpy(buf, sender_packet->data, sender_packet_size);
		// receiver reply with DATAACK header with seqnum received
		gbnhdr *rec_header = make_packet(DATAACK, s.rec_seqnum, 0, NULL, 0);

		if (sendto(sockfd, rec_header, sizeof(gbnhdr), 0, s.receiverServerAddr, s.receiverSocklen) == -1) return -1;

		free(rec_header);
		// if successfully send ACK, expected next rec_seqnum ++
		s.rec_seqnum ++;
		return sender_packet_size;
	}

	// if a connection teardown request is received, reply with FINACK header
	if (check_packetType(packet, FIN) == 0) {
		gbnhdr *rec_header = make_packet(FINACK, 0, 0, NULL, 0);
		if (sendto(sockfd, rec_header, sizeof(gbnhdr), 0, s.receiverServerAddr, s.receiverSocklen) == -1) return -1;
		s.state = FIN_RCVD;
		return 0;
	}

	return(-1);
}

int gbn_close(int sockfd){
	// sender initiate a FIN request and wait for FINACK
	if (s.state == ESTABLISHED || s.state == SYN_SENT || s.state == SYN_RCVD) {
		gbnhdr * send_header = make_packet(FIN, 0, 0, NULL, 0);
		if (sendto(sockfd, send_header, sizeof(gbnhdr), 0, s.senderServerAddr, s.senderSocklen) == -1) return -1;
		// successfully send FIN request to receiver
		s.state = FIN_SENT;
	}
	// if receiver sees a FIN header, reply with FINACK and close socket connection
	else if (s.state == FIN_SENT) {
		gbnhdr * rec_header = make_packet(FINACK, 0, 0, NULL, 0);
		if (sendto(sockfd, rec_header, sizeof(gbnhdr), 0, s.receiverServerAddr, s.receiverSocklen) == -1) return -1;
		// successfully close the connection
		close(sockfd);
	}
	return(-1);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){
	if (sockfd < 0) return -1;

	// Define Global State
	s.mode = SLOW;
	// Identify sender server address
	s.senderServerAddr = (struct sockaddr *)server;
	s.senderSocklen = socklen;

	// sender send SYN packet
	gbnhdr *send_header = make_packet(SYN, 0, 0, NULL, 0);

	// SIGALRM is called after timeout alarm
	signal(SIGALRM, sig_handler);

	int attempt = 0;
	s.timed_out = -1;

	while (attempt < MAX_ATTEMPT) {
		// send SYN header to initialize connection
		if (sendto(sockfd, send_header, sizeof(send_header), 0, server, socklen) == -1 ) {
			attempt ++;
			continue;
		}
		s.state = SYN_SENT;

		alarm(TIMEOUT);
		// waiting for receiving SYNACK
		gbnhdr *rec_header = malloc(sizeof(gbnhdr));

		if (recvfrom(sockfd, rec_header, sizeof(rec_header), 0, s.receiverServerAddr, &s.receiverSocklen) == -1) {
			attempt ++;
			continue;
		}
		// check for timeout, check if header type is SYNACK
		if (check_packetType(rec_header, SYNACK) == 0) {
			// connection established
			s.state = ESTABLISHED;
			return 0;
		}
		attempt ++;
	}
	// if reach max number of tries, close the connection
	s.state = CLOSED;
	return(-1);
}

int gbn_listen(int sockfd, int backlog){
	// receiver receive from (listen to) header of the request to connect
	gbnhdr *send_header = malloc(sizeof(gbnhdr));
	if (recvfrom(sockfd, send_header, sizeof(gbnhdr), 0, s.receiverServerAddr, &s.receiverSocklen) == -1) {
		return -1;
	}

	// check if packet contains SYN header
	if (check_packetType(send_header, SYN) == 0) {
		s.state = SYN_RCVD;
		return 0;
	}

	return(-1);
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){

    // pointer to local struct on receiver server where sender address is to be stored
    receiverServerAddr = (struct sockaddr *)server;
    receiverSocklen = socklen;

    s.timed_out = -1;
    return bind(sockfd, server, socklen);
}	

int gbn_socket(int domain, int type, int protocol){
		
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));

    return socket(domain, type, protocol);
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){
	// receiver send to sender either RST or SYNACK based on global state
	// if accept, initialize the receiver sequence number to 0
	s.rec_seqnum = 0;
	gbnhdr * rec_header;

	// if connection teardown initiated, reject connection by sending RST
	if (s.state == FIN_SENT) rec_header = make_packet(RST, 0, 0, NULL, 0);
	// accept connection initiation by sending header with SYNACK
	else rec_header = make_packet(SYNACK, 0, 0, NULL, 0);

	// check if successfully send to client (original connection requester)
	if (sendto(sockfd, rec_header, sizeof(rec_header), 0, client, socklen) == -1) {
		free(rec_header);
		return -1;
	}
	free(rec_header);

	return sockfd;
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
