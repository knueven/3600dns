/*
 * CS3600, Spring 2013
 * Project 2 Starter Code
 * (c) 2013 Alan Mislove
 *
 */

#ifndef __3600DNS_H__
#define __3600DNS_H__

#define MAX_IP_PACKET_SIZE 65542
#define QUERY_ID 1337
#define RECORDS 1
#define CNAME 5
#define MX 15
#define NS 2

typedef struct { //dns header
    unsigned int ID:16; 
    unsigned int RD:1;
    unsigned int TC:1;
    unsigned int AA:1;
    unsigned int OPCODE:4;
    unsigned int QR:1;
    unsigned int RCODE:4;
    unsigned int Z:3;  
    unsigned int RA:1;
    unsigned int QDCOUNT:16;
    unsigned int ANCOUNT:16;
    unsigned int NSCOUNT:16;
    unsigned int ARCOUNT:16;     
} dnsheader;

typedef struct {
    unsigned int TYPE:16; 
    unsigned int CLASS:16;
    unsigned int TTL:32;
    unsigned int RDLENGTH:16;
    //unsigned int PREFERENCE:16;
} dnsanswer;

typedef struct {
    unsigned int QTYPE:16;
    unsigned int QCLASS:16;  
} dnsquestion;

#endif