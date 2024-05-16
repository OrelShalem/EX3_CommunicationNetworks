#include "RUDP_API.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

unsigned short int calculate_checksum(void *data, unsigned int bytes);

// Function to send data with a timeout
int sendto_timeout(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen, int timeout_ms)
{
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

// Function to receive data with a timeout
int recvfrom_timeout(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen, int timeout_ms)
{
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

// Function to convert data to network byte order
void convert_to_network_order(RUDPPacket *packet)
{
    packet->header.length = htons(packet->header.length);
    packet->header.checksum = htons(packet->header.checksum);
    packet->sequence_number = htons(packet->sequence_number);
}

// Creating a RUDP socket and creating a handshake between two peers
RUDPConnection *rudp_socket(struct sockaddr_in *receiver_addr, struct sockaddr_in *sender_addr, int sockfd)
{
    RUDPConnection *connection = (RUDPConnection *)malloc(sizeof(RUDPConnection));
    if (connection == NULL)
    {
        perror("Failed to allocate memory for RUDPConnection");
        exit(1);
    }

    connection->sockfd = sockfd;
    connection->receiver_addr = *receiver_addr;
    if (sender_addr != NULL)
    {
        connection->sender_addr = *sender_addr;
    }
    connection->next_sequence_number = 1;

    if (sender_addr == NULL)
    {
        // Sender side
        connection->sender_addr = *receiver_addr; // Store the receiver's address as the sender's address

        RUDPPacket syn_packet;
        syn_packet.header.length = htons(RUDP_HEADER_SIZE);
        syn_packet.header.checksum = 0;
        syn_packet.header.flags.SYN = 1;
        syn_packet.header.checksum = htons(calculate_checksum((char *)&syn_packet, sizeof(RUDPPacket)));
        printf("Sending SYN packet with checksum: %u\n", ntohs(syn_packet.header.checksum));

        if (sendto(sockfd, &syn_packet, RUDP_HEADER_SIZE, 0, (struct sockaddr *)receiver_addr, sizeof(struct sockaddr_in)) < 0)
        {
            perror("Error sending SYN packet");
            free(connection);
            exit(1);
        }

        RUDPPacket synack_packet;
        struct sockaddr_in synack_sender_addr;
        socklen_t synack_sender_addr_len = sizeof(synack_sender_addr);
        while (1)
        {
            if (recvfrom(sockfd, &synack_packet, sizeof(RUDPPacket), 0, (struct sockaddr *)&synack_sender_addr, &synack_sender_addr_len) < 0)
            {
                perror("Error receiving SYN-ACK packet");
                free(connection);
                exit(1);
            }

            if (synack_packet.header.flags.SYN == 1 && synack_packet.header.flags.ACK == 1)
            {
                printf("Received SYN-ACK packet with checksum: %u\n", ntohs(synack_packet.header.checksum));
                if (verify_checksum(&synack_packet, sizeof(RUDPPacket), synack_packet.header.checksum) == 0)
                {
                    break;
                }
            }
        }

        RUDPPacket ack_packet;
        ack_packet.header.length = htons(RUDP_HEADER_SIZE);
        ack_packet.header.checksum = 0;
        ack_packet.header.flags.ACK = 1;
        ack_packet.header.checksum = htons(calculate_checksum((char *)&ack_packet, sizeof(RUDPPacket)));
        printf("Sending ACK packet with checksum: %u\n", ntohs(ack_packet.header.checksum));

        if (sendto(sockfd, &ack_packet, RUDP_HEADER_SIZE, 0, (struct sockaddr *)&synack_sender_addr, sizeof(struct sockaddr_in)) < 0)
        {
            perror("Error sending ACK packet");
            free(connection);
            exit(1);
        }
    }
    else
    {
        // Receiver side
        RUDPPacket syn_packet;
        struct sockaddr_in syn_sender_addr;
        socklen_t syn_sender_addr_len = sizeof(syn_sender_addr);
        while (1)
        {
            if (recvfrom(sockfd, &syn_packet, sizeof(RUDPPacket), 0, (struct sockaddr *)&syn_sender_addr, &syn_sender_addr_len) < 0)
            {
                perror("Error receiving SYN packet");
                free(connection);
                exit(1);
            }

            if (syn_packet.header.flags.SYN == 1)
            {
                printf("Received SYN packet with checksum: %u\n", ntohs(syn_packet.header.checksum));
                if (verify_checksum(&syn_packet, sizeof(RUDPPacket), syn_packet.header.checksum) == 0)
                {
                    connection->sender_addr = syn_sender_addr; // Store the sender's address
                    break;
                }
            }
        }

        RUDPPacket synack_packet;
        synack_packet.header.length = htons(RUDP_HEADER_SIZE);
        synack_packet.header.checksum = 0;
        synack_packet.header.flags.SYN = 1;
        synack_packet.header.flags.ACK = 1;
        synack_packet.header.checksum = htons(calculate_checksum((char *)&synack_packet, sizeof(RUDPPacket)));
        printf("Sending SYN-ACK packet with checksum: %u\n", ntohs(synack_packet.header.checksum));

        if (sendto(sockfd, &synack_packet, RUDP_HEADER_SIZE, 0, (struct sockaddr *)&syn_sender_addr, sizeof(struct sockaddr_in)) < 0)
        {
            perror("Error sending SYN-ACK packet");
            free(connection);
            exit(1);
        }

        RUDPPacket ack_packet;
        while (1)
        {
            if (recvfrom(sockfd, &ack_packet, sizeof(RUDPPacket), 0, NULL, NULL) < 0)
            {
                perror("Error receiving ACK packet");
                free(connection);
                exit(1);
            }

            if (ack_packet.header.flags.ACK == 1)
            {
                printf("Received ACK packet with checksum: %u\n", ntohs(ack_packet.header.checksum));
                if (verify_checksum(&ack_packet, sizeof(RUDPPacket), ack_packet.header.checksum) == 0)
                {
                    break;
                }
            }
        }
    }

    return connection;
}





int rudp_send(RUDPConnection *connection, void *buffer, size_t buffer_size) {
    size_t bytes_sent = 0;
    uint16_t seq_num = connection->next_sequence_number;
    uint16_t window_start = seq_num;
    uint16_t window_end = seq_num + WINDOW_SIZE;

    while (bytes_sent < buffer_size) {
        size_t chunk_size = (buffer_size - bytes_sent) > MAX_PACKET_SIZE ? MAX_PACKET_SIZE : (buffer_size - bytes_sent);

        RUDPPacket packet;
        packet.header.length = htons(RUDP_HEADER_SIZE + chunk_size);
        packet.header.checksum = 0;
        packet.header.flags.DATA = 1;
        packet.sequence_number = htons(seq_num);
        memcpy(packet.data, (char *)buffer + bytes_sent, chunk_size);
        packet.header.checksum = htons(calculate_checksum((char *)&packet, RUDP_HEADER_SIZE + chunk_size));

        if (sendto(connection->sockfd, &packet, RUDP_HEADER_SIZE + chunk_size, 0, (struct sockaddr *)&connection->receiver_addr, sizeof(struct sockaddr_in)) < 0) {
            perror("Error sending data packet");
            return -1;
        }

        RUDPPacket ack_packet;
        struct sockaddr_in ack_addr;
        socklen_t ack_addr_len = sizeof(ack_addr);

        if (recvfrom_timeout(connection->sockfd, &ack_packet, sizeof(RUDPPacket), 0, (struct sockaddr *)&ack_addr, &ack_addr_len, 1000) >= 0) {
            convert_to_network_order(&ack_packet);
            if (ack_packet.header.flags.ACK && ack_packet.sequence_number >= window_start && ack_packet.sequence_number < window_end) {
                window_start = ntohs(ack_packet.sequence_number) + 1;
            }
        } else {
            // Retransmit packets in the window
            for (uint16_t i = window_start; i < window_end; i++) {
                RUDPPacket retransmit_packet;
                // Rebuild the packet with sequence number i
                // ...
                if (sendto(connection->sockfd, &retransmit_packet, RUDP_HEADER_SIZE + chunk_size, 0, (struct sockaddr *)&connection->receiver_addr, sizeof(struct sockaddr_in)) < 0) {
                    perror("Error retransmitting data packet");
                    return -1;
                }
            }
        }

        bytes_sent += chunk_size;
        seq_num++;

        if (seq_num == window_end) {
            window_start = seq_num;
            window_end = seq_num + WINDOW_SIZE;
        }
    }

    connection->next_sequence_number = seq_num;
    return 0;
}

ssize_t rudp_recv(RUDPConnection *connection, void *buffer, size_t buffer_size, struct sockaddr_in *sender_addr) {
    size_t bytes_received = 0;
    uint16_t expected_seq_num = 1;
    uint16_t window_start = expected_seq_num;
    uint16_t window_end = expected_seq_num + WINDOW_SIZE;

    while (bytes_received < buffer_size) {
        RUDPPacket packet;
        int packet_size = recvfrom(connection->sockfd, &packet, sizeof(RUDPPacket), 0, (struct sockaddr *)sender_addr, NULL);
        if (packet_size < 0) {
            if (errno == EFAULT) {
                char addr_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(sender_addr->sin_addr), addr_str, INET_ADDRSTRLEN);
                printf("Error receiving data packet: Bad address %s:%d\n", addr_str, ntohs(sender_addr->sin_port));
            } else {
                perror("Error receiving data packet");
            }
            return -1;
        }

        convert_to_network_order(&packet);

        if (verify_checksum(&packet, packet_size, packet.header.checksum) == 1) {
            printf("Invalid checksum\n");
            RUDPPacket ack;
            ack.header.length = htons(RUDP_HEADER_SIZE);
            ack.header.checksum = htons(calculate_checksum((char *)&ack, RUDP_HEADER_SIZE));
            ack.header.flags.ACK = 1;
            ack.sequence_number = htons(expected_seq_num - 1);
            if (sendto(connection->sockfd, &ack, RUDP_HEADER_SIZE, 0, (struct sockaddr *)sender_addr, sizeof(struct sockaddr_in)) < 0) {
                perror("Error sending ACK packet");
                return -1;
            }
        } else if (packet.sequence_number >= window_start && packet.sequence_number < window_end) {            RUDPPacket ack;
            ack.header.length = htons(RUDP_HEADER_SIZE);
            ack.header.checksum = htons(calculate_checksum((char *)&ack, RUDP_HEADER_SIZE));
            ack.header.flags.ACK = 1;
            ack.sequence_number = htons(packet.sequence_number);
            if (sendto(connection->sockfd, &ack, RUDP_HEADER_SIZE, 0, (struct sockaddr *)sender_addr, sizeof(struct sockaddr_in)) < 0) {
                perror("Error sending ACK packet");
                return -1;
            }

            size_t data_size = packet_size - RUDP_HEADER_SIZE;
            memcpy((char *)buffer + bytes_received, packet.data, data_size);
            bytes_received += data_size;
            window_start = ntohs(packet.sequence_number) + 1;
            window_end = window_start + WINDOW_SIZE;
        } else {
            printf("Received out-of-order packet. Expected sequence number: %u, Received sequence number: %u\n", expected_seq_num, ntohs(packet.sequence_number));
            RUDPPacket ack;
            ack.header.length = htons(RUDP_HEADER_SIZE);
            ack.header.checksum = htons(calculate_checksum((char *)&ack, RUDP_HEADER_SIZE));
            ack.header.flags.ACK = 1;
            ack.sequence_number = htons(expected_seq_num - 1);
            if (sendto(connection->sockfd, &ack, RUDP_HEADER_SIZE, 0, (struct sockaddr *)sender_addr, sizeof(struct sockaddr_in)) < 0) {
                perror("Error sending ACK packet");
                return -1;
            }
        }
    }

    return bytes_received;
}
// Closes a connection between peers.
void rudp_close(RUDPConnection *connection)
{
    close(connection->sockfd);
    free(connection);
}

/*
 * @brief A checksum function that returns 16 bit checksum for data.
 * @param data The data to do the checksum for.
 * @param bytes The length of the data in bytes.
 * @return The checksum itself as 16 bit unsigned number.
 * @note This function is taken from RFC1071, can be found here:
 * @note https://tools.ietf.org/html/rfc1071
 * @note It is the simplest way to calculate a checksum and is not very strong.
 * However, it is good enough for this assignment.
 * @note You are free to use any other checksum function as well.
 * You can also use this function as such without any change.
 */
unsigned short int calculate_checksum(void *data, unsigned int bytes)
{
    unsigned short int *data_pointer = (unsigned short int *)data;
    unsigned int total_sum = 0;
    // Main summing loop
    while (bytes > 1)
    {
        total_sum += *data_pointer++;
        bytes -= 2;
    }
    // Add left-over byte, if any
    if (bytes > 0)
        total_sum += *((unsigned char *)data_pointer);
    // Fold 32-bit sum to 16 bits
    while (total_sum >> 16)
        total_sum = (total_sum & 0xFFFF) + (total_sum >> 16);
    return (~((unsigned short int)total_sum));
}
int verify_checksum(void *data, unsigned int bytes, unsigned short int received_checksum)
{
    unsigned short int *data_pointer = (unsigned short int *)data;
    unsigned int total_sum = 0;
    // Main summing loop
    while (bytes > 1)
    {
        total_sum += *data_pointer++;
        bytes -= 2;
    }
    // Add left-over byte, if any
    if (bytes > 0)
        total_sum += *((unsigned char *)data_pointer);

    total_sum += received_checksum;

    // Fold 32-bit sum to 16 bits
    while (total_sum >> 16)
        total_sum = (total_sum & 0xFFFF) + (total_sum >> 16);
    return ((unsigned short int)total_sum == 0xFFFF ? 1 : 0);
}