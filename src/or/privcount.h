#ifndef TOR_PRIVCOUNT_H
#define TOR_PRIVCOUNT_H

#include "or.h"
#include "config.h"

void privcount_dns_resolved(edge_connection_t *exitconn,
                            or_circuit_t *oncirc);
void privcount_stream_data_xferred(edge_connection_t *conn,
                                   uint64_t amt, int outbound);
void privcount_stream_ended(edge_connection_t *conn);
void privcount_circuit_ended(or_circuit_t *orcirc);
void privcount_connection_ended(or_connection_t *orconn);

#endif /* !defined(TOR_PRIVCOUNT_H) */
