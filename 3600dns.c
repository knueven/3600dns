/*
 * CS3600, Spring 2013
 * Project 3 Starter Code
 * (c) 2013 Alan Mislove
 *
 */

#include <math.h>
#include <ctype.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "3600dns.h"
int parse_ip( unsigned char* packet, unsigned char* rdata, int startPosition );
int parse_qname( unsigned char* packet, unsigned char* qname, int startPosition );

/**
 * This function will print a hex dump of the provided packet to the screen
 * to help facilitate debugging.  In your milestone and final submission, you 
 * MUST call dump_packet() with your packet right before calling sendto().  
 * You're welcome to use it at other times to help debug, but please comment those
 * out in your submissions.
 *
 * DO NOT MODIFY THIS FUNCTION
 *
 * data - The pointer to your packet buffer
 * size - The length of your packet
 */
static void dump_packet(unsigned char *data, int size) {
    unsigned char *p = data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[ 16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};
    for(n=1;n<=size;n++) {
        if (n%16 == 1) {
            /* store address for this line */
            snprintf(addrstr, sizeof(addrstr), "%.4x",
               ((unsigned int)p-(unsigned int)data) );
        }
            
        c = *p;
        if (isprint(c) == 0) {
            c = '.';
        }

        /* store hex str (for left side) */
        snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        /* store char str (for right side) */
        snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

        if(n%16 == 0) { 
            /* line completed */
            printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        } else if(n%8 == 0) {
            /* half line: add whitespaces */
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++; /* next byte */
    }

    if (strlen(hexstr) > 0) {
        /* print rest of buffer if not empty */
        printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}

int main(int argc, char *argv[]) {
  /**
   * I've included some basic code for opening a socket in C, sending
   * a UDP packet, and then receiving a response (or timeout).  You'll 
   * need to fill in many of the details, but this should be enough to
   * get you started.
   */
  // process the arguments
    if (argc != 3 && argc != 4) {
         printf("Usage: ./3600dns [-ns|-mx] @<server:port> <name>\n");
        exit(-1);
    } 
    char serverType = RECORDS;
    if (argc == 4) {
        if (!strcmp(argv[1],"-mx")){
            serverType = MX;
        } else if (!strcmp(argv[1],"-ns")){
            serverType = NS;
        } else {
            return -1;
        }
        argc = 1;
    } else {
        argc = 0;
    }
   // set the default port to 53
    int port = 53;
    char* name = calloc(150,sizeof(char));
    char* server = argv[argc+1] + 1;
    memcpy( name,argv[argc+2],strlen(argv[2]) );
    char* offset = strchr(argv[argc+1], ':');
    if (offset) {
        *offset = 0;
        port = atoi(offset + 1);
    } 
   
  // construct the DNS request
    
    //Structure mallocs
    unsigned char* packetDNS =  (unsigned char*)calloc(MAX_IP_PACKET_SIZE, sizeof(char));
    if (!packetDNS) {
        return -1;
    }
    dnsheader* header =  (dnsheader*)calloc(1, sizeof(dnsheader));
    if (!header) {
        return -1;
    }
    dnsquestion* question =  (dnsquestion*)calloc(1, sizeof(dnsquestion));
    if (!question) { 
        return -1;
    }
    dnsanswer* answer =  (dnsanswer*)calloc(1, sizeof(dnsanswer));
        if (!answer) {
            return -1;
    }

    //setup the header
    header->ID = htons(QUERY_ID);
    header->RD = ~(0);
    header->QDCOUNT = htons(0x0001);
    //setup the question, QNAME is added later
    switch (serverType){
        case RECORDS: 
            question->QTYPE = htons(0x0001);
            break;
        case MX:
            question->QTYPE = htons(MX);
            break;
        case NS:
             question->QTYPE = htons(NS);
            break;
    }
    question->QCLASS = htons(0x0001);

    int packetSize = 0;
    //copy header into packet
    memcpy( packetDNS, header,  sizeof(dnsheader) );
    packetSize += sizeof(dnsheader);

    //copy qname into packet
    int length = strlen(name);
    char* period = NULL;
    *( name + length ) = '.';
    *( name + length + 1 ) = 0;
    while ( (period = strchr(name, '.')) != 0 ) {
        *period = 0;
        length = strlen(name);
        memcpy( packetDNS + packetSize, &length, 1 );
        packetSize++;
        memcpy( packetDNS + packetSize, name, length);
        packetSize += length;
        name = period + 1;
    }

    //copy zero byte at end of qname
    char zeroByte = 0;
    memcpy( packetDNS + packetSize, &zeroByte, 1 );
    packetSize++;

    //copy question into packet
    memcpy( packetDNS + packetSize, question, sizeof(dnsquestion) );
    packetSize += sizeof(dnsquestion);


   // send the DNS request (and call dump_packet with your request)
    dump_packet( packetDNS, packetSize );

   // first, open a UDP socket  
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

   // next, construct the destination address
    struct sockaddr_in out;
    out.sin_family = AF_INET;
    out.sin_port = htons( (short) port );
    out.sin_addr.s_addr = inet_addr(server);

    if (sendto(sock, packetDNS, packetSize, 0, (struct sockaddr*)&out, sizeof(out)) < 0) {
        printf("Error occured in sendto\n");
        return -1;
    }

    //Clear question buffer to use for answer buffer in the future  
    memset( packetDNS, 0, MAX_IP_PACKET_SIZE );
    memset( question, 0, sizeof(dnsquestion) );
    memset( header, 0, sizeof(dnsheader) );
    packetSize = 0;

    // wait for the DNS reply (timeout: 5 seconds)
    struct sockaddr_in in;
    socklen_t in_len;

    // construct the socket set
    fd_set socks;
    FD_ZERO(&socks);
    FD_SET(sock, &socks);

    // construct the timeout
    struct timeval t;
    t.tv_sec = 5;
    t.tv_usec = 0;
    
    // wait to receive, or for a timeout
    
    if (select(sock + 1, &socks, NULL, NULL, &t)) {
        in_len = sizeof(in);
        int status;
        status = recvfrom(sock, packetDNS, MAX_IP_PACKET_SIZE, 0, (struct sockaddr*) &in, &in_len);
        if ( status < 0) {
            printf("%s in recvfrom\n",strerror(errno));
            return -1;    
        }
        if (!header) {
            return -1;
        }
        /*==========================
            Parse response HEADER
           ==========================*/
        //Check header for consistency
        memcpy( header,packetDNS,sizeof(dnsheader) );
        if ( ntohs(header->ID) != QUERY_ID || 
             header->QR != 1 || 
             header->RD != 1 || 
             header->RA != 1 ) {
            printf("ERROR: Header mismatch\n");
            return 1;
        }
        packetSize = sizeof(dnsheader);
        int numAnswers = ntohs(header->ANCOUNT);
        /*==========================
            Parse response QUESTION QNAME
           ==========================*/
        unsigned char* qname = calloc(150, sizeof(char));
        int len = parse_qname( packetDNS, qname, sizeof(dnsheader) );
        if (!strcmp((char*)argv[2],(char*)qname+1)) {
            printf("ERROR: qname mismatch '%s'\n",qname);
            return -1;
        }
        
        packetSize += len;
        /*==========================
            Parse response QUESTION
           ==========================*/
        memcpy( question, packetDNS+packetSize, sizeof(dnsquestion) );
        if ( (ntohs(question->QTYPE) != RECORDS && 
             ntohs(question->QTYPE) != MX && 
             ntohs(question->QTYPE) != NS) || 
             ntohs(question->QCLASS) != (1) ) {
             printf("ERROR: question mismatch\n");
            return -1;
        }         
        packetSize += sizeof(dnsquestion); 
        /*==========================
            Parse response ANSWER QNAME
           ==========================*/
        do {
        memset(qname,0,150);
        len = parse_qname(packetDNS,qname,packetSize);
        if (!strcmp((char*)argv[2],(char*)qname+1)) {
            printf("ERROR: answer qname mismatch '%s'\n",qname);
            return -1;
        }
        packetSize += len;
        /*==========================
            Parse response ANSWER
           ==========================*/
        memcpy(answer,packetDNS+packetSize,sizeof(dnsanswer));
        if ((ntohs(answer->TYPE) != RECORDS && 
             ntohs(answer->TYPE) != CNAME && 
             ntohs(answer->TYPE) != MX && 
             ntohs(answer->TYPE) != NS) ||  
            ntohs(answer->CLASS) != 1 ) {
            printf("NOTFOUND\n");
            return 1;
        }
        //Two bytes need to be subtracted from dnsanswer becasue padding was added
        packetSize += sizeof(dnsanswer) - 2;
        /*=====================
            Parse response RDATA
           =====================*/
        unsigned char* rdata = calloc(150,sizeof(char));
        short preference = 0;
        if ( ntohs(answer->TYPE) == RECORDS ) {
            parse_ip(packetDNS,rdata,packetSize);
            printf("IP\t%s",rdata);
            packetSize += ntohs(answer->RDLENGTH);
        } 
        else if ( ntohs(answer->TYPE) == CNAME ) {
            len = parse_qname(packetDNS,rdata,packetSize);
            printf("CNAME\t%s",rdata);
            packetSize += len;
        } 
        else if ( ntohs(answer->TYPE) == NS ) {
            len = parse_qname(packetDNS,rdata,packetSize);
            printf("NS\t%s",rdata);
            packetSize += len;
        } 
        else if ( ntohs(answer->TYPE) == MX ) {
            memcpy(&preference,packetDNS+packetSize,sizeof(short));
            packetSize+=sizeof(preference);  
            preference = ntohs(preference); 
            len = parse_qname(packetDNS,rdata,packetSize);
            printf("MX\t%s\t%d",rdata,preference);
            packetSize += len;
        }
            
        if ( header->AA) {
            printf("\tauth\n");
        }else{
            printf("\tnonauth\n");
        }
        numAnswers--;
      } while (numAnswers);
    } else {
        // a timeout occurred
        printf("NORESPONSE");
    }
    // print out the result
    //dump_packet( packetDNS, packetSize);
    free(header);
    free(question);
    free(packetDNS);
    free(answer);
    return 0;
}


//Parse IP addresses
int parse_ip( unsigned char* packet, unsigned char* rdata, int startPosition ) {
    unsigned char a = packet[startPosition];
    int position = startPosition + 1;
    unsigned char segments[4];
   for (int i = 0; i < 4; i++)
   {
       /* if (a & 192) {
            a = packet[position];
            position = a;
        } else*/ {
            segments[i] = a;
        }
        a = packet[position];
        position++;
    }
    sprintf((char*)rdata,"%d.%d.%d.%d",segments[0],segments[1],segments[2],segments[3]);
    return 4;
}

//takes a packet, a char* and an offset and retrieves the qname at the given position
int parse_qname( unsigned char* packet, unsigned char* qname, int startPosition ) {
    unsigned char a = packet[startPosition];
    int position = startPosition + 1;
    int bytesWritten = 0;
    int final_position = 0;
    while (a != 0) {
        if (a & 192) {
            a = packet[position];
            if (!final_position) {
                final_position = position+1;
            }
            position = a;
        } else {
            for (int x = 0; x < a; x++) {
                qname[bytesWritten] = packet[position];
                position++;
                bytesWritten++;
            }
            qname[bytesWritten] = '.';
            bytesWritten++;
        }
        a = packet[position];
        position++;
    }

    if (qname[bytesWritten - 1] == '.') {
        bytesWritten--;
    }
    qname[bytesWritten] = 0; 
    if (!final_position) {
                final_position = position;
    }
    return final_position-startPosition;
}
