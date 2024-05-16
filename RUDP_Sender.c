#include "RUDP_API.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define FILE_SIZE (2 * 1024 * 1024) // 2MB

char *util_generate_random_data(unsigned int size)
{
    char *buffer = (char *)calloc(size, sizeof(char));
    if (buffer == NULL)
        return NULL;

    srand(time(NULL));
    for (unsigned int i = 0; i < size; i++)
        *(buffer + i) = ((unsigned int)rand() % 256);

    return buffer;
}

int main(int argc, char *argv[])
{
    if (argc != 5 || strcmp(argv[1], "-ip") != 0 || strcmp(argv[3], "-p") != 0)
    {
        fprintf(stderr, "Usage: %s -ip <IP> -p <port>\n", argv[0]);
        exit(1);
    }

    const char *ip = argv[2];
    int port = atoi(argv[4]);

    // Create UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("Failed to create UDP socket");
        exit(1);
    }

    // Set up destination address
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &(dest_addr.sin_addr)) <= 0)
    {
        perror("Invalid address");
        exit(1);
    }

    // Set up RUDP socket
    RUDPConnection *rudp_conn = rudp_socket(&dest_addr, NULL, sockfd);
    if (rudp_conn == NULL)
    {
        fprintf(stderr, "Failed to create RUDP socket\n");
        exit(1);
    }
    printf("RUDP socket created successfully\n");

    // Generate random file data
    char *file_data = util_generate_random_data(FILE_SIZE);
    if (file_data == NULL)
    {
        perror("Failed to generate random data");
        rudp_close(rudp_conn);
        exit(1);
    }

    // Send the file
    if (rudp_send(rudp_conn, file_data, FILE_SIZE) < 0)
    {
        fprintf(stderr, "Failed to send file\n");
        free(file_data);
        rudp_close(rudp_conn);
        exit(1);
    }
    printf("File sent successfully\n");

    // Ask the user if they want to send the file again
    char input[10];
    while (1)
    {
        printf("Do you want to send the file again? (y/n): ");
        fgets(input, sizeof(input), stdin);
        if (input[0] == 'y' || input[0] == 'Y')
        {
            if (rudp_send(rudp_conn, file_data, FILE_SIZE) < 0)
            {
                fprintf(stderr, "Failed to send file\n");
                break;
            }
            printf("File sent successfully\n");
        }
        else
        {
            char exit_message = 'n';
            if (rudp_send(rudp_conn, &exit_message, sizeof(char)) < 0)
            {
                fprintf(stderr, "Failed to send exit message\n");
            }
            break;
        }
    }

    // Clean up
    free(file_data);
    rudp_close(rudp_conn);

    return 0;
}