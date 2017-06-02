
#ifndef _EXT_FILTER_H_
#define _EXT_FILTER_H_

void filter_setup( void );
void filter_free( void );

void filter_on_result( const uint8_t id[SHA1_BIN_LENGTH], const IP addr );

#endif /* _EXT_FILTER_H_ */
