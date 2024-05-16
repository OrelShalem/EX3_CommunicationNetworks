#include "RUDP_API.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

#define FILE_SIZE (2 * 1024 * 1024) // 2MB
#define CONTROL_MSG_SIZE 10

int main(int argc, char *argv[]) {
    if (argc != 3 || strcmp(argv[1], "-p") != 0) {
        fprintf(stderr, "Usage: %s -p <port>\n", argv[0]);
        exit(1);
    }

    int port = atoi(argv[2]);

    // Create UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    // Set up server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    // Set up client address
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = INADDR_ANY;
    client_addr.sin_port = htons(0);

    // Bind the socket to the server address
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error binding socket");
        exit(1);
    }

    // Set up RUDP socket
    RUDPConnection *rudp_conn = rudp_socket(&server_addr, &client_addr, sockfd);
    if (rudp_conn == NULL) {
        fprintf(stderr, "Failed to create RUDP socket\n");
        exit(1);
    }

    printf("Starting Receiver...\n");
    printf("Waiting for RUDP connection...\n");

    // Receive the file
    char file_data[FILE_SIZE];
    clock_t start_time, end_time;
    double total_time = 0;
    int num_runs = 0;

    while (1) {
        char control_msg[CONTROL_MSG_SIZE] = {0};
        // Receive file data
        start_time = clock();
        ssize_t bytes_received = rudp_recv(rudp_conn, file_data, FILE_SIZE, &rudp_conn->sender_addr);
        end_time = clock();

        if (bytes_received < 0) {
            fprintf(stderr, "Error receiving file\n");
            rudp_close(rudp_conn);
            exit(1);
        }

        double time_taken = ((double)(end_time - start_time)) / CLOCKS_PER_SEC * 1000; // in milliseconds
        double bandwidth = (bytes_received * 8) / (time_taken / 1000) / (1024 * 1024); // in Mbps
        printf("File transfer completed.\n");
        printf("Run #%d Data: Time=%.2fms; Speed=%.2fMB/s\n", ++num_runs, time_taken, bandwidth);
        total_time += time_taken;

        // Receive control message
        ssize_t msg_size = rudp_recv(rudp_conn, control_msg, CONTROL_MSG_SIZE, &rudp_conn->sender_addr);
        if (msg_size < 0) {
            fprintf(stderr, "Error receiving control message\n");
            rudp_close(rudp_conn);
            exit(1);
        }

        if (strcmp(control_msg, "n") == 0) {
            printf("Sender sent exit message.\n");
            break;
        }
    }

    // Calculate average time and bandwidth
    double avg_time = total_time / num_runs;
    double avg_bandwidth = (FILE_SIZE * 8) / (avg_time / 1000) / (1024 * 1024); // in Mbps

    printf("----------------------------------\n");
    printf("- * Statistics * -\n");
    printf("- Average time: %.2fms\n", avg_time);
    printf("- Average bandwidth: %.2fMB/s\n", avg_bandwidth);
    printf("----------------------------------\n");

    // Close the socket
    rudp_close(rudp_conn);

    return 0;
}