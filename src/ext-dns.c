
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#include "main.h"
#include "conf.h"
#include "log.h"
#include "utils.h"
#include "kad.h"
#include "net.h"
#include "ext-dns.h"

#define MAX_ADDR_RECORDS 32

/*
* DNS-Server interface for KadNode.
*/

/* DNS Header Masks */
enum {
	QR_MASK = 0x8000,
	OPCODE_MASK = 0x7800,
	AA_MASK = 0x0400,
	TC_MASK = 0x0200,
	RD_MASK = 0x0100,
	RA_MASK = 0x8000,
	RCODE_MASK = 0x000F
};

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
	AAAA_Resource_RecordType = 28,
	SRV_Resource_RecordType = 33
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
struct Question {
	const char *qName;
	unsigned short qType;
	unsigned short qClass;
};

/* Data part of a Resource Record */
union ResourceData {
	struct {
		const char *txt_data;
	} txt_record;
	struct {
		unsigned char addr[4];
	} a_record;
	struct {
		const char *name;
	} name_server_record;
	struct {
		const char name;
	} cname_record;
	struct {
		const char *name;
	} ptr_record;
	struct {
		unsigned short preference;
		const char *exchange;
	} mx_record;
	struct {
		unsigned char addr[16];
	} aaaa_record;
	struct {
		unsigned short priority;
		unsigned short weight;
		unsigned short port;
		const char *target;
	} srv_record;
};

/* Resource Record Section */
struct ResourceRecord {
	const char *name;
	unsigned short type;
	unsigned short class;
	unsigned short ttl;
	unsigned short rd_length;
	union ResourceData rd_data;
};

struct Message {
	unsigned short id; /* Identifier */

	/* Flags */
	unsigned short qr; /* Query/Response Flag */
	unsigned short opcode; /* Operation Code */
	unsigned short aa; /* Authoritative Answer Flag */
	unsigned short tc; /* Truncation Flag */
	unsigned short rd; /* Recursion Desired */
	unsigned short ra; /* Recursion Available */
	unsigned short rcode; /* Response Code */

	unsigned short qdCount; /* Question Count */
	unsigned short anCount; /* Answer Record Count */
	unsigned short nsCount; /* Authority Record Count */
	unsigned short arCount; /* Additional Record Count */

	/* We only handle one question and multiple answers */
	struct Question question;
	struct ResourceRecord answers[MAX_ADDR_RECORDS*2];

	/* Buffer for the qName part */
	char qName_buffer[300];
};

/* Placeholder names to link together SRV and A/AAAA records */
static const char g_names[MAX_ADDR_RECORDS][3] = {
	"01", "02", "03", "04", "05", "06", "07", "08",
	"09", "10", "11", "12", "13", "14", "15", "16",
	"17", "18", "19", "20", "21", "22", "23", "24",
	"25", "26", "27", "28", "29", "30", "31", "32"
};

/*
* Basic memory operations.
*/
size_t get16bits( const UCHAR** buffer ) {
	unsigned short value;

	value = ntohs( *((unsigned short *) *buffer) );
	*buffer += 2;

	return value;
}

void put16bits( UCHAR** buffer, unsigned short value ) {
	*((unsigned short *) *buffer) = htons( value );
	*buffer += 2;
}

void put32bits( UCHAR** buffer, unsigned long long value ) {
	*((unsigned long long *) *buffer) = htonl( value );
	*buffer += 4;
}


/*
* Decoding/Encoding functions
*/

/* 3foo3bar3com0 => foo.bar.com */
int dns_decode_domain( char *domain, const UCHAR** buffer, size_t size ) {
	const UCHAR *p = *buffer;
	size_t i = 0;
	size_t len = 0;

	while( *p != '\0' ) {

		if( i != 0 ) {
			domain[i] = '.';
			i += 1;
		}

		len = *p;
		p += 1;

		if( (i + len) >= size ) {
			return -1;
		}

		memcpy( domain + i, p, len );
		p += len;
		i += len;
	}

	domain[i] = '\0';

	/* also jump over the last 0 */
	*buffer = p + 1;

	return 1;
}

/* foo.bar.com => 3foo3bar3com0 */
int dns_encode_domain( UCHAR** buffer, const char *domain ) {
	char *buf = (char*) *buffer;
	const char *beg = domain;
	const char *pos = NULL;
	size_t len = strlen( domain );
	size_t plen = 0;
	size_t i = 0;

	while( (pos = strchr(beg, '.')) != NULL ) {
		plen = pos - beg;
		buf[i] = plen;
		i += 1;
		memcpy( buf + i, beg, plen );
		i += plen;

		beg = pos + 1;
	}

	plen = len - (beg - domain);

	buf[i] = plen;
	i += 1;

	memcpy( buf + i, beg, plen );
	i += plen;

	buf[i] = '\0';
	i += 1;

	*buffer += i;

	return 1;
}

int dns_encode_header( UCHAR** buffer, const struct Message *msg ) {
	size_t fields;

	put16bits( buffer, msg->id );

	/* Set Flags - Most fields are omitted */
	fields = 0;
	fields |= (msg->qr << 15) & QR_MASK;
	fields |= (msg->rcode << 0) & RCODE_MASK;
	put16bits( buffer, fields );

	put16bits( buffer, msg->qdCount );
	put16bits( buffer, msg->anCount );
	put16bits( buffer, msg->nsCount );
	put16bits( buffer, msg->arCount );

	return 1;
}

int dns_decode_header( struct Message *msg, const UCHAR** buffer ) {
	size_t fields;

	msg->id = get16bits( buffer );
	fields = get16bits( buffer );
	msg->qr = (fields & QR_MASK) >> 15;
	msg->opcode = (fields & OPCODE_MASK) >> 11;
	msg->aa = (fields & AA_MASK) >> 10;
	msg->tc = (fields & TC_MASK) >> 9;
	msg->rd = (fields & RD_MASK) >> 8;
	msg->ra = (fields & RA_MASK) >> 7;
	msg->rcode = (fields & RCODE_MASK) >> 0;

	msg->qdCount = get16bits( buffer );
	msg->anCount = get16bits( buffer );
	msg->nsCount = get16bits( buffer );
	msg->arCount = get16bits( buffer );

	return 1;
}

/* Decode the message from a byte array into a message structure */
int dns_decode_msg( struct Message *msg, const UCHAR *buffer ) {
	size_t i;

	if( dns_decode_header( msg, &buffer ) < 0 ) {
		return -1;
	}

	/* Parse questions - but stop after the first question we can handle */
	for( i = 0; i < msg->qdCount; ++i ) {
		if( dns_decode_domain( msg->qName_buffer, &buffer, 300 ) < 0 ) {
			return -1;
		}

		int qType = get16bits( &buffer );
		int qClass = get16bits( &buffer );

		if( qType == A_Resource_RecordType
			|| qType == AAAA_Resource_RecordType
			|| qType == SRV_Resource_RecordType
			|| qType == PTR_Resource_RecordType
		) {
			msg->question.qName = msg->qName_buffer;
			msg->question.qType = qType;
			msg->question.qClass = qClass;
			return 1;
		}
	}

	log_warn( "DNS: No question for A, AAAA, SRV or PTR resource found in query." );
	return -1;
}

/* Encode the message structure into a byte array */
int dns_encode_msg( UCHAR *buffer, size_t size, const struct Message *msg ) {
	const size_t qName_offset = 12;
	const struct ResourceRecord *rr;
	UCHAR *beg;
	size_t i;

	beg = buffer;
	if( dns_encode_header( &buffer, msg ) < 0 ) {
		return -1;
	}

	/* Attach a single question section. */
	if( dns_encode_domain( &buffer, msg->question.qName ) < 0 ) {
		return -1;
	}

	put16bits( &buffer, msg->question.qType );
	put16bits( &buffer, msg->question.qClass );

	/* Attach multiple resource records. */
	const size_t count = msg->anCount + msg->nsCount + msg->arCount;
	for( i = 0; i < count; i++ ) {
		rr = &msg->answers[i];

		if( msg->question.qName == rr->name ) {
			/* Reference qName in question section (message compression) */
			put16bits( &buffer, (3 << 14) + qName_offset );
		} else {
			if( dns_encode_domain( &buffer, rr->name ) < 0 ) {
				return -1;
			}
		}

		put16bits( &buffer, rr->type );
		put16bits( &buffer, rr->class );
		put32bits( &buffer, rr->ttl );
		put16bits( &buffer, rr->rd_length ); /* already accounts for encoded data */

		if( rr->type == SRV_Resource_RecordType ) {
			put16bits( &buffer, rr->rd_data.srv_record.priority );
			put16bits( &buffer, rr->rd_data.srv_record.weight );
			put16bits( &buffer, rr->rd_data.srv_record.port );
			if( dns_encode_domain( &buffer, rr->rd_data.srv_record.target ) < 0 ) {
				return -1;
			}
		} else if( rr->type == PTR_Resource_RecordType ) {
			if( dns_encode_domain( &buffer, rr->rd_data.ptr_record.name ) < 0 ) {
				return -1;
			}
		} else {
			/* Assume A/AAAA address record data */
			memcpy( buffer, &rr->rd_data, rr->rd_length );
			buffer += rr->rd_length;
		}
	}

	return (buffer - beg);
}

int dns_lookup_addr( const char hostname[], IP addr[], size_t addr_num ) {

	/* Start lookup for one address */
	if( kad_lookup_value( hostname, addr, &addr_num ) >= 0 && addr_num > 0 ) {
		return addr_num;
	} else {
		return 0;
	}
}

const char* dns_lookup_ptr( const char ptr_name[] ) {
	typedef struct {
		const char* ptr_name;
		const char* hostname;
	} Entry;

	static const Entry entries[] = {
		{ "1.0.0.127.in-addr.arpa", "localhost" },
		{ "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", "localhost" }
	};

	size_t i;
	for( i = 0; i < (sizeof(entries) / sizeof(entries[0])); i++ ) {
		if( strcmp( ptr_name, entries[i].ptr_name )  == 0 ) {
			return entries[i].hostname;
		}
	}

	return NULL;
}

void setAddressRecord( struct ResourceRecord *rr, const char name[], const IP *addr ) {

	if( addr->ss_family == AF_INET ) {
		rr->name = name;
		rr->type = A_Resource_RecordType;
		rr->class = 1;
		rr->ttl = 0; /* no caching */
		rr->rd_length = 4;

		memcpy( rr->rd_data.a_record.addr, &((IP4 *)addr)->sin_addr, 4 );
	} else {
		rr->name = name;
		rr->type = AAAA_Resource_RecordType;
		rr->class = 1;
		rr->ttl = 0; /* no caching */
		rr->rd_length = 16;

		memcpy( rr->rd_data.aaaa_record.addr, &((IP6 *)addr)->sin6_addr, 16 );
	}
}

void setServiceRecord( struct ResourceRecord *rr, const char name[], const char target[], int port ) {
	rr->name = name;
	rr->type = SRV_Resource_RecordType;
	rr->class = 1;
	rr->ttl = 0; /* no caching */
	rr->rd_length = 6 + strlen( target ) + 2; /* encoded target will be +2 longer */

	rr->rd_data.srv_record.priority = 0;
	rr->rd_data.srv_record.weight = 0;
	rr->rd_data.srv_record.port = port;
	rr->rd_data.srv_record.target = target;
}

void setPointerRecord( struct ResourceRecord *rr, const char name[], const char domain[] ) {
	rr->name = name;
	rr->type = PTR_Resource_RecordType;
	rr->class = 1;
	rr->ttl = 0; /* no caching */
	rr->rd_length = strlen( domain ) + 2; /* encoded target will be +2 longer */

	rr->rd_data.ptr_record.name = domain;
}

int dns_setup_msg( struct Message *msg, IP addrs[], size_t addrs_num, const char* hostname ) {
	const char *qName;
	size_t i, c;

	/* Header: leave most values intact for response */
	msg->qr = 1; /* this is a response */
	msg->aa = 1; /* this server is authoritative */
	msg->ra = 0; /* no recursion available - we don't ask other DNS servers */
	msg->rcode = Ok_ResponseType;

	msg->qdCount = 1;
	msg->anCount = 0;
	msg->nsCount = 0;
	msg->arCount = 0;

	c = 0;
	qName = msg->question.qName;
	if( msg->question.qType == SRV_Resource_RecordType ) {
		for( i = 0; i < addrs_num; i++, c++ ) {
			int port = addr_port( &addrs[i] );
			setServiceRecord( &msg->answers[c], qName, g_names[i], port );
			msg->anCount++;
		}

		for( i = 0; i < addrs_num; i++, c++ ) {
			setAddressRecord( &msg->answers[c], g_names[i], &addrs[i] );
			msg->arCount++;
		}
	} else if( msg->question.qType == PTR_Resource_RecordType ) {
		setPointerRecord( &msg->answers[c], qName, hostname );
		msg->anCount++;
		c++;
	} else {
		/* Assume AAAA or A Record Type */
		for( i = 0; i < addrs_num; i++, c++ ) {
			setAddressRecord( &msg->answers[c], qName, &addrs[i] );
			msg->arCount++;
		}
	}

	return (c == 0) ? -1 : 1;
}

/* Get a small string representation of the query type */
const char* qtype_str( int qType ) {
	switch( qType ) {
		case A_Resource_RecordType:
			return "A";
		case AAAA_Resource_RecordType:
			return "AAAA";
		case SRV_Resource_RecordType:
			return "SRV";
		case PTR_Resource_RecordType:
			return "PTR";
		default:
			return "???";
	}
}

void dns_handler( int rc, int sock ) {
	ssize_t buflen;
	struct Message msg;
	IP clientaddr;
	IP addrs[MAX_ADDR_RECORDS];
	size_t addrs_num;
	socklen_t addrlen_ret;

	UCHAR buffer[1472];
	char addrbuf[FULL_ADDSTRLEN+1];
	const char *hostname;
	const char *domain;

	if( rc == 0 ) {
		return;
	}

	memset( buffer, 0, sizeof(buffer) );
	addrlen_ret = sizeof(IP);
	buflen = recvfrom( sock, buffer, sizeof(buffer), 0, (struct sockaddr *) &clientaddr, &addrlen_ret );
	if( buflen < 0 ) {
		return;
	}

	/* Decode message */
	if( dns_decode_msg( &msg, buffer ) < 0 ) {
		return;
	}

	if( msg.question.qType == A_Resource_RecordType && gconf->af != AF_INET ) {
		return;
	}

	if( msg.question.qType == AAAA_Resource_RecordType && gconf->af != AF_INET6 ) {
		return;
	}

	hostname = msg.question.qName;

	if ( hostname == NULL ) {
		log_warn( "DNS: Empty hostname in question record." );
		return;
	}

	if ( !str_isValidHostname( hostname ) ) {
		log_warn( "DNS: Invalid hostname for lookup: '%s'", hostname );
		return;
	}

	log_debug( "DNS: Received %s query from %s for: %s",
		qtype_str( msg.question.qType ),
		str_addr( &clientaddr, addrbuf ),
		hostname
	);

	if( msg.question.qType == PTR_Resource_RecordType ) {
		if( !is_suffix( hostname, ".arpa" )) {
			return;
		}

		if( (domain = dns_lookup_ptr( hostname )) == NULL ) {
			log_debug( "DNS: No domain found for PTR question." );
			return;
		}

		if( dns_setup_msg( &msg, NULL, 0, domain ) < 0 ) {
			return;
		}

		log_debug( "DNS: Send back hostname '%s' to: %s",
			domain, str_addr( &clientaddr, addrbuf )
		);
	} else {
		/* Check if ends with .p2p */
		if( !is_suffix( hostname, gconf->query_tld ) ) {
			return;
		}

		if( (addrs_num = dns_lookup_addr( hostname, addrs, MAX_ADDR_RECORDS )) == 0 ) {
			log_debug( "DNS: Failed to resolve hostname: %s", hostname );
			return;
		}

		if( dns_setup_msg( &msg, &addrs[0], addrs_num, NULL ) < 0 ) {
			return;
		}

		log_debug( "DNS: Send back %ul addresses to: %s",
			addrs_num, str_addr( &clientaddr, addrbuf )
		);
	}

	/* Encode message */
	buflen = dns_encode_msg( buffer, sizeof(buffer), &msg );

	if( buflen > 0 ) {
		sendto( sock, buffer, buflen, 0, (struct sockaddr*) &clientaddr, sizeof(IP) );
	} else {
		log_err( "DNS: Failed not create a response packet." );
	}
}

void dns_setup( void ) {
	int sock;

	if( str_isZero( gconf->dns_port ) ) {
		return;
	}

	sock = net_bind( "DNS", "localhost", gconf->dns_port, NULL, IPPROTO_UDP, AF_UNSPEC );
	net_add_handler( sock, &dns_handler );
}

void dns_free( void ) {
	/* Nothing to do */
}
