
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <semaphore.h>
#include <signal.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "kad.h"
#include "net.h"
#include "ext-dns.h"


/*
* DNS-Server interface for KadNode.
*/

static const uint QR_MASK = 0x8000;
static const uint OPCODE_MASK = 0x7800;
static const uint AA_MASK = 0x0400;
static const uint TC_MASK = 0x0200;
static const uint RD_MASK = 0x0100;
static const uint RA_MASK = 0x8000;
static const uint RCODE_MASK = 0x000F;


/* Response Type */
enum {
	Ok_ResponseType = 0,
	FormatError_ResponseType = 1,
	ServerFailure_ResponseType = 2,
	NameError_ResponseType = 3,
	NotImplemented_ResponseType = 4,
	Refused_ResponseType = 5
};

/* Resource Record Types */
enum {
	A_Resource_RecordType = 1,
	NS_Resource_RecordType = 2,
	CNAME_Resource_RecordType = 5,
	SOA_Resource_RecordType = 6,
	PTR_Resource_RecordType = 12,
	MX_Resource_RecordType = 15,
	TXT_Resource_RecordType = 16,
	AAAA_Resource_RecordType = 28
};

/* Operation Code */
enum {
	QUERY_OperationCode = 0, /* standard query */
	IQUERY_OperationCode = 1, /* inverse query */
	STATUS_OperationCode = 2, /* server status request */
	NOTIFY_OperationCode = 4, /* request zone transfer */
	UPDATE_OperationCode = 5 /* change resource records */
};

/* Response Code */
enum {
	NoError_ResponseCode = 0,
	FormatError_ResponseCode = 1,
	ServerFailure_ResponseCode = 2,
	NameError_ResponseCode = 3
};

/* Query Type */
enum {
	IXFR_QueryType = 251,
	AXFR_QueryType = 252,
	MAILB_QueryType = 253,
	MAILA_QueryType = 254,
	STAR_QueryType = 255
};

/* Question Section */
struct question {
	char *qName;
	uint qType;
	uint qClass;
};

union resource_data {
	struct { char *txt_data; } txt_record;
	struct { UCHAR addr[4]; } a_record;
	struct { char *name; } name_server_record;
	struct { char *name; } cname_record;
	struct { char *name; } ptr_record;
	struct { uint preference; char *exchange; } mx_record;
	struct { UCHAR addr[16]; } aaaa_record;
};

/* Resource Record Section */
struct ResourceRecord {
	char *name;
	uint type;
	uint class;
	uint ttl;
	uint rd_length;
	union resource_data rd_data;
};

struct message {
	uint id; /* Identifier */

	/* flags */
	uint qr; /* Query/Response Flag */
	uint opcode; /* Operation Code */
	uint aa; /* Authoritative Answer Flag */
	uint tc; /* Truncation Flag */
	uint rd; /* Recursion Desired */
	uint ra; /* Recursion Available */
	uint rcode; /* Response Code */

	uint qdCount; /* Question Count */
	uint anCount; /* Answer Record Count */
	uint nsCount; /* Authority Record Count */
	uint arCount; /* Additional Record Count */

	/* We only handle one question and one answers */
	struct question question;
	struct ResourceRecord answer;

	/* Buffer for the qName part. */
	char qName_buffer[256];
};

/*
* Basic memory operations.
*/

int get16bits( const UCHAR** buffer ) {
	int value = (*buffer)[0];
	value = value << 8;
	value += (*buffer)[1];
	(*buffer) += 2;
	return value;
}

void put16bits( UCHAR** buffer, uint value ) {
	(*buffer)[0] = (value & 0xFF00) >> 8;
	(*buffer)[1] = value & 0xFF;
	(*buffer) += 2;
}

void put32bits( UCHAR** buffer, ulong value ) {
	(*buffer)[0] = (value & 0xFF000000) >> 24;
	(*buffer)[1] = (value & 0xFF0000) >> 16;
	(*buffer)[2] = (value & 0xFF00) >> 16;
	(*buffer)[3] = (value & 0xFF) >> 16;
	(*buffer) += 4;
}

/*
* Deconding/Encoding functions.
*/

/* 3foo3bar3com0 => foo.bar.com */
int dns_decode_domain( char *domain, const UCHAR** buffer, int size ) {
	const UCHAR *p = *buffer;
	const UCHAR *beg = p;
	int i = 0;
	int len = 0;

	while( *p != '\0' ) {

		if( i != 0 ) {
			domain[i] = '.';
			i += 1;
		}

		len = *p;
		p += 1;

		if( i+len >=  256 || i+len >= size ) {
			return -1;
		}

		memcpy( domain+i, p, len );
		p += len;
		i += len;
	}

	domain[i] = '\0';

	/* also jump over the last 0 */
	*buffer = p + 1;

	return (*buffer) - beg;
}

/* foo.bar.com => 3foo3bar3com0 */
void dns_code_domain( UCHAR** buffer, const char *domain ) {
	char *buf = (char*) *buffer;
	const char *beg = domain;
	const char *pos;
	int len = 0;
	int i = 0;

	while( (pos = strchr(beg, '.')) != '\0' ) {
		len = pos - beg;
		buf[i] = len;
		i += 1;
		memcpy( buf+i, beg, len );
		i += len;

		beg = pos + 1;
	}

	len = strlen( domain ) - (beg - domain);

	buf[i] = len;
	i += 1;

	memcpy( buf + i, beg, len );
	i += len;

	buf[i] = 0;
	i += 1;

	*buffer += i;
}

int dns_decode_header( struct message *msg, const UCHAR** buffer, int size ) {
	uint fields;

	if( size < 12 ) {
		return -1;
	}

	msg->id = get16bits( buffer );
	fields = get16bits( buffer );
	msg->qr = fields & QR_MASK;
	msg->opcode = fields & OPCODE_MASK;
	msg->aa = fields & AA_MASK;
	msg->tc = fields & TC_MASK;
	msg->rd = fields & RD_MASK;
	msg->ra = fields & RA_MASK;
	msg->rcode = fields & RCODE_MASK;


	msg->qdCount = get16bits( buffer );
	msg->anCount = get16bits( buffer );
	msg->nsCount = get16bits( buffer );
	msg->arCount = get16bits( buffer );

	return 12;
}

void dns_code_header( struct message *msg, UCHAR** buffer ) {
	put16bits( buffer, msg->id );

	/* Set response flag only */
	put16bits( buffer, (1 << 15) );

	put16bits( buffer, msg->qdCount );
	put16bits( buffer, msg->anCount );
	put16bits( buffer, msg->nsCount );
	put16bits( buffer, msg->arCount );
}

int dns_decode_query( struct message *msg, const UCHAR *buffer, int size ) {
	int i, n;

	if( (n = dns_decode_header( msg, &buffer, size )) < 0 ) {
		return -1;
	}
	size -= n;

	if(( msg->anCount+msg->nsCount+msg->arCount) != 0 ) {
		log_warn( "DNS: Only questions expected." );
		return -1;
	}

	/* parse questions */
	for( i = 0; i < msg->qdCount; ++i ) {
		n = dns_decode_domain( msg->qName_buffer, &buffer, size );
		if( n < 0 ) {
			return -1;
		}

		size -= n;

		if( size < 4 ) {
			return -1;
		}

		int qType = get16bits( &buffer );
		int qClass = get16bits( &buffer );

		if( qType == A_Resource_RecordType || qType == AAAA_Resource_RecordType ) {
			msg->question.qName = msg->qName_buffer;
			msg->question.qType = qType;
			msg->question.qClass = qClass;
			return 1;
		}
	}

	log_warn( "DNS: No question for A or AAAA resource found in query." );
	return -1;
}

UCHAR *dns_code_response( struct message *msg, UCHAR *buffer ) {

	dns_code_header( msg, &buffer );

	/* Attach a single question section. */
	dns_code_domain( &buffer, msg->question.qName );
	put16bits( &buffer, msg->question.qType );
	put16bits( &buffer, msg->question.qClass );

	/* Attach a single resource section. */
	dns_code_domain( &buffer, msg->answer.name );
	put16bits( &buffer, msg->answer.type );
	put16bits( &buffer, msg->answer.class );
	put32bits( &buffer, msg->answer.ttl );
	put16bits( &buffer, msg->answer.rd_length );

	if( msg->question.qType == AAAA_Resource_RecordType ) {
		/* AAAA_Resource_RecordType */
		memcpy( buffer, &msg->answer.rd_data.aaaa_record.addr, 16 );
		buffer += 16;
	} else {
		/* A_Resource_RecordType */
		memcpy( buffer, &msg->answer.rd_data.a_record.addr, 4 );
		buffer += 4;
	}

	return buffer;
}

int dns_lookup( UCHAR *node_id, IP *node_addr ) {
	int n;

	/* Check if we know that node already. */
	n = 1;
	if( kad_lookup_value( node_id, node_addr, &n ) == 0 ) {
		return 0;
	}

	/* Start find process */
	kad_search( node_id );

	return 1;
}

void dns_reply_msg( struct message *msg, IP *nodeaddr ) {
	struct ResourceRecord *rr;
	struct question *qu;

	qu = &msg->question;
	rr = &msg->answer;

	/* Header: leave most values intact for response */
	msg->qr = 1; /* this is a response */
	msg->aa = 1; /* this server is authoritative */
	msg->ra = 0; /* no recursion available - we don't ask other dns servers */
	msg->rcode = Ok_ResponseType;
	msg->anCount = 1;
	msg->nsCount = 0;
	msg->arCount = 0;

	/* Set A Resource Record */
	if( nodeaddr->ss_family == AF_INET ) {
		rr->name = qu->qName;
		rr->type = A_Resource_RecordType;
		rr->class = qu->qClass;
		rr->ttl = 0; /* no caching */
		rr->rd_length = 4;

		memcpy( rr->rd_data.a_record.addr, &((IP4 *)nodeaddr)->sin_addr, 4 );
	}

	/* Set AAAA Resource Record */
	if( nodeaddr->ss_family == AF_INET6 ) {
		rr->name = qu->qName;
		rr->type = AAAA_Resource_RecordType;
		rr->class = qu->qClass;
		rr->ttl = 0; /* no caching */
		rr->rd_length = 16;

		memcpy( rr->rd_data.aaaa_record.addr, &((IP6 *)nodeaddr)->sin6_addr, 16 );
	}
}

void dns_handler( int rc, int sock ) {
	int n;
	struct message msg;
	IP clientaddr, nodeaddr;
	socklen_t addrlen_ret;

	UCHAR buffer[1500];
	UCHAR node_id[SHA_DIGEST_LENGTH];
	char hexbuf[HEX_LEN+1];
	char addrbuf1[FULL_ADDSTRLEN+1];
	char addrbuf2[FULL_ADDSTRLEN+1];
	const char *hostname;

	if( rc == 0 ) {
		return;
	}

	addrlen_ret = sizeof(IP);
	n = recvfrom( sock, buffer, sizeof(buffer), 0, (struct sockaddr *) &clientaddr, &addrlen_ret );
	if( n < 0 ) {
		return;
	}

	log_debug( "DNS: Received query from: %s",  str_addr( &clientaddr, addrbuf1 ) );

	if( dns_decode_query( &msg, buffer, n ) < 0 ) {
		return;
	}

	hostname = msg.question.qName;

	/* Validate hostname */
	if ( hostname == NULL || !str_isValidHostname( (char*) hostname, strlen( hostname ) ) ) {
		log_warn( "DNS: Invalid hostname for lookup: '%s'", hostname );
		return;
	}

	/* That is the lookup key */
	id_compute( node_id, hostname );
	log_debug( "DNS: Lookup '%s' as '%s'.", hostname, str_id( node_id, hexbuf ) );

	if( dns_lookup( node_id, &nodeaddr ) != 0 ) {
		log_debug( "DNS: Hostname not found." );
		return;
	}

	dns_reply_msg( &msg, &nodeaddr );

	UCHAR* p = dns_code_response( &msg, buffer );

	if( p ) {
		int buflen = p - buffer;
		log_debug( "DNS: Send address %s to %s. Packet has %d bytes.",
			str_addr( &nodeaddr, addrbuf1 ),
			str_addr( &clientaddr, addrbuf2 ),
			buflen
		);

		sendto( sock, buffer, buflen, 0, (struct sockaddr*) &clientaddr, sizeof(IP) );
	}
}

void dns_setup( void ) {
	int sock;

	if( str_isZero( gstate->dns_port ) ) {
		return;
	}

	sock = net_bind( "DNS", "::1", gstate->dns_port, NULL, IPPROTO_UDP, AF_INET6 );
	net_add_handler( sock, &dns_handler );
}
