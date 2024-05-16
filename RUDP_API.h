#ifndef RUDP_API_H
#define RUDP_API_H
#include <sys/socket.h>
#include <stddef.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

#define MAX_PACKET_SIZE 60000
#define RUDP_HEADER_SIZE 5
#define WINDOW_SIZE 5

typedef struct
{
    unsigned int SYN : 1;
    unsigned int SYN_ACK : 1;
    unsigned int ACK : 1;
    unsigned int FIN : 1;
    unsigned int FIN_ACK : 1;
    unsigned int RST : 1;
    unsigned int NACK : 1;
    unsigned int DATA : 1;
} RUDPFlags;

typedef struct
{
    uint16_t length;
    uint16_t checksum;
    RUDPFlags flags;

} RUDPHeader;

// Define a structure to hold a packet
typedef struct
{
    RUDPHeader header;
    char data[MAX_PACKET_SIZE];
    uint16_t sequence_number;

} RUDPPacket;

// define a structure for an RUDP connection
typedef struct
{
    int sockfd;
    struct sockaddr_in receiver_addr;
    struct sockaddr_in sender_addr;
    // serial number of the next packet to send
    uint16_t next_sequence_number;
} RUDPConnection;

// Function declarations
RUDPConnection *rudp_socket(struct sockaddr_in *receiver_addr, struct sockaddr_in *sender_addr, int sockfd);
int rudp_send(RUDPConnection *connection, void *buffer, size_t buffer_size);
unsigned short int calculate_checksum(void *data, unsigned int bytes);

ssize_t rudp_recv(RUDPConnection *connection, void *buffer, size_t buffer_size, struct sockaddr_in *sender_addr);
void rudp_close(RUDPConnection *connection);
int verify_checksum(void *data, unsigned int bytes, unsigned short int received_checksum);
void convert_to_network_order(RUDPPacket *packet);

#endif