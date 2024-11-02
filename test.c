#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <iperf_api.h>

// Random IP generator function within a given range
void generate_random_ip(char *ip_buffer) {
    int octet1 = 192;          // Example: Using the range 192.168.x.x
    int octet2 = 168;
    int octet3 = rand() % 255; // Randomize the third and fourth octet
    int octet4 = rand() % 255;
    snprintf(ip_buffer, 16, "%d.%d.%d.%d", octet1, octet2, octet3, octet4);
}

int main() {
    srand(time(NULL));  // Seed for random IP generation
    char random_ip[16];
    generate_random_ip(random_ip);
   
    printf("Simulated source IP: %s\n", random_ip);

    struct iperf_test *test;

    // Initialize iperf test in client mode
    test = iperf_new_test();
    if (test == NULL) {
        fprintf(stderr, "Error creating iperf test\n");
        return -1;
    }
   
    iperf_defaults(test);                   // Set defaults for the test
    iperf_set_test_role(test, 'c');         // 'c' for client
    iperf_set_test_server_hostname(test, "127.0.0.1");  // Destination server (localhost)
    iperf_set_test_protocol(test, Ptcp);    // Use TCP
    iperf_set_test_duration(test, 5);       // Set test duration (seconds)
    iperf_set_test_bind_address(test, random_ip); // Set the random IP as source address
   
    // Run the iperf test
    if (iperf_run_client(test) < 0) {
        fprintf(stderr, "Error running iperf client: %s\n", iperf_strerror(i_errno));
        iperf_free_test(test);
        return -1;
    }

    printf("TCP packets sent from simulated IP %s\n", random_ip);

    // Clean up iperf test resources
    iperf_free_test(test);

    return 0;
}
