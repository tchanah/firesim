#ifndef UDPPORT_H
#define UDPPORT_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <map>
#include <vector>

#include "baseport.h"
#include "flit.h"

// Defined in flit.h / switchconfig.h usually, but ensuring safety
#ifndef ETH_HEADER_FLITS
#define ETH_HEADER_FLITS 2
#endif

// A class to handle UDP Packet Injection and Extraction (Gateway)
class UdpPacketInjector {
public:
    int sockfd;
    int portno;
    struct sockaddr_in serveraddr;
    
    // Switch-side queue to inject into
    // We don't store the queue here, we return packets to the caller (switch loop)
    
    // Rank -> Host Address Mapping
    std::map<int, struct sockaddr_in> rank_map;

    UdpPacketInjector(int port) {
        portno = port;
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            perror("ERROR opening socket");
            // Non-fatal? Or fatal? For simulation, maybe fatal.
        }

        // Enable reuse addr
        int optval = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int));

        // Non-blocking
        int flags = fcntl(sockfd, F_GETFL, 0);
        fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

        bzero((char *) &serveraddr, sizeof(serveraddr));
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
        serveraddr.sin_port = htons((unsigned short)portno);

        if (bind(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) {
            perror("ERROR on binding UDP port");
        }
        
        printf("UdpPacketInjector listening on port %d\n", portno);
    }

    // Process incoming UDP packets (Host -> Simulation)
    // Returns a vector of switchpacket* to be injected into queues
    // Also learns the source address for the return path
    std::vector<std::pair<int, switchpacket*>> poll() {
        std::vector<std::pair<int, switchpacket*>> injected_packets;
        
        const int MAX_BUF = 4096;
        char buf[MAX_BUF];
        struct sockaddr_in clientaddr;
        socklen_t clientlen = sizeof(clientaddr);

        while (true) {
            int n = recvfrom(sockfd, buf, MAX_BUF, 0, (struct sockaddr *) &clientaddr, &clientlen);
            if (n < 0) {
                if (errno != EWOULDBLOCK && errno != EAGAIN) {
                     perror("recvfrom error");
                }
                break; // No more packets or error
            }

            // --- Routing Logic ---
            // The Switch needs to identify the Sender Rank to route the packet to the correct
            // simulated FireSim node (Target MAC = Base + Rank + 0x22).
            //
            // Strategy: Fixed UDP Source Ports
            // PyTorch Host binds to Port 10000 + Rank.
            // Switch infers Rank = SourcePort - 10000.
            // This avoids modifying the Gloo packet header.
            
            if (n < 20) continue; // Too short
            
            uint8_t* byte_ptr = (uint8_t*)buf;
            // header structure:
            // 0-1: coll_id
            // 2: type
            // 3: op
            // 4: res0
            // 5: res1 (RANK)
            
            // Determine Sender Rank from Source Port (Fixed Mapping 10000+Rank)
            uint16_t src_port = ntohs(clientaddr.sin_port);
            int sender_rank = -1;
            
            if (src_port >= 10000 && src_port < 10008) {
                 sender_rank = src_port - 10000;
            } else {
                 if (src_port < 10000) {
                     // Debug/Log
                     continue; 
                 }
                 sender_rank = src_port - 10000; // Allow > 8 for generality (if needed)
            }

            // We do not read the header for Rank anymore.
            // uint8_t* byte_ptr = (uint8_t*)buf;
            
            // Update Map
            rank_map[sender_rank] = clientaddr;
            
            // Construct Switch Packet
            switchpacket* sp = (switchpacket*)calloc(sizeof(switchpacket), 1);
            
            // Ethernet Header Construction
            // Dst: Base + Rank + 0x22 (Accel)
            // Src: Base + Rank + 0x12 (PyTorch Host - uses 0x12 offset to bypass NIC local routing)
            //      NIC's testerMac uses 0x02 offset, so 0x12 routes to Switch instead of CPU
            
            uint64_t base_mac = 0x00126D000000ULL;
            uint64_t dst_mac = base_mac | (uint64_t)(sender_rank + 0x22);
            uint64_t src_mac = base_mac | (uint64_t)(sender_rank + 0x12);
            
            // Flit 0: [Padding(2)][Dst(6)]
            // Flit 1: [Src(6)][Type(2)]
            
            // Construct Flit 0
            // 2 bytes pad (0) + 6 bytes Dst
            // The switch and NIC use Little Endian internally, so memcpy is safe if byte order matches.
            // This mirrors logic typically found in NIC drivers.
            // Wait, standard Ethernet is: Dst(6), Src(6), Type(2).
            // FireSim Flit 0: [Pad(2)] [Dst(6)]
            
            // We construct the buffer byte-by-byte in Network Order (Big Endian) for MACs.
            // This is compatible with `memcpy` into the packet later.
            
            uint8_t packet_buffer[2048];
            memset(packet_buffer, 0, 2048);
            
            // Pad 2
            packet_buffer[0] = 0; packet_buffer[1] = 0;
            
            // Dst
            for(int i=0; i<6; i++) packet_buffer[2+i] = (dst_mac >> ((5-i)*8)) & 0xFF;
            
            // Src
            for(int i=0; i<6; i++) packet_buffer[8+i] = (src_mac >> ((5-i)*8)) & 0xFF;
            
            // Type
            packet_buffer[14] = 0; packet_buffer[15] = 0;
            
            // Payload (Copy UDP Data)
            memcpy(packet_buffer + 16, buf, n);
            
            // Convert to Flits
            // Total bytes = 16 + n
            int total_len = 16 + n;
            // Pad to 8 bytes equivalent
            int num_flits = (total_len + 7) / 8;
            
            for(int i=0; i<num_flits && i<200; i++) {
                memcpy(&sp->dat[i], packet_buffer + i*8, 8);
            }
            sp->amtwritten = num_flits;
            
            // Identify Target Port
            // Dst MAC ...22 + Rank
            // Mapping: SwitchConfig usually maps 0x22+i -> Port i.
            // So Target Port = Rank.
            injected_packets.push_back({sender_rank, sp});
        }
        return injected_packets;
    }

    // Process outgoing Switch Packets (Simulation -> Host)
    // Called from switch loop when packet is destined for Tester
    // Process outgoing Switch Packets (Simulation -> Host)
    // Called from switch loop when packet is destined for Tester
    // Returns TRUE if packet was intercepted and should be DROPPED from simulation.
    // Returns FALSE if packet should be allowed to proceed to Tester (e.g. Setup ACK).
    bool intercept_and_forward(switchpacket* sp, int dest_port) {
        // dest_port is the Switch Port index (0..7).
        // This corresponds to Rank.
        int rank = dest_port;
        
        // Inspect Payload to check for Setup ACK
        // Setup ACK has CollID=0xFFFF and OpCode=0xFE
        // Metadata starts at Flit 2 (index 2).
        // Flit is 64-bit. We can inspect bytes.
        // Assuming Little Endian (x86 host), we can access bytes directly via casting or masking.
        // sp->dat[2] is the first 8 bytes of payload.
        // Byte 0-1: CollID. Byte 3: OpCode.
        
        uint64_t meta_flit = sp->dat[ETH_HEADER_FLITS];
        uint16_t coll_id = meta_flit & 0xFFFF;
        uint8_t op_code = (meta_flit >> 24) & 0xFF;
        
        bool is_setup_ack = (coll_id == 0xFFFF && op_code == 0xFE);
        
        if (is_setup_ack) {
            // Must allow Setup ACK to pass to Tester so it can finish initialization
            return false;
        }

        // --- Critical Fix: MAC Address Check ---
        // Ensure we only intercept packets destined for the HOST (Tester), not other Accelerators.
        // Flit 0: [Pad(2)][Dst(6)]. Dst MAC ends at Byte 7 (MSB of uint64_t).
        // Host MACs end in 0x0X (e.g. 0x02 + Rank).
        // Accel MACs end in 0x2X (e.g. 0x22 + Rank).
        // If MAC byte has 0x20 bit set, it is for Accelerator -> Do NOT Intercept.
        
        uint64_t flit0 = sp->dat[0];
        uint8_t mac_lsb = (flit0 >> 56) & 0xFF;
        if ((mac_lsb & 0x20) != 0) {
             // Destined for Accelerator (0x22, 0x23, etc.)
             return false;
        }

        // Check if we know this rank
        if (rank_map.find(rank) == rank_map.end()) {
             // Unknown rank (no mapping yet). Let it pass to Tester.
             return false; 
        }
        
        
        // It is a Data Packet for a known Host.
        // Extract Payload and Forward via UDP.
        
        // Standard Gloo Packet Size (16 byte header + 1024 data = 1040 payload)
        // We extract from Flit 2 onwards.
        
        const int PAYLOAD_LEN = 1040;
        char udp_payload[PAYLOAD_LEN];

        // Flits 2 to 131
        for(int i=0; i<130; i++) { // 130 * 8 = 1040
             memcpy(udp_payload + i*8, &sp->dat[ETH_HEADER_FLITS + i], 8);
        }
        
        // Send UDP
        struct sockaddr_in target = rank_map[rank];
        int n = sendto(sockfd, udp_payload, PAYLOAD_LEN, 0, (struct sockaddr *) &target, sizeof(target));
        if (n < 0) {
            fprintf(stderr, "[INTERCEPT-ERROR] UDP sendto failed for Rank %d: %s\n", rank, strerror(errno));
        }
        
        // We successfully forwarded it.
        // Now tell the Switch to DROP it from the simulation link.
        return true;
    }
};

#endif
