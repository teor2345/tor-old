/**
 * \file privcount.c
 * \brief Privacy-preserving data collection
 **/

#include "sys/socket.h"
#include "sys/types.h"
#include "netinet/in.h"
#include "netdb.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "unistd.h"
#include "errno.h"
#include "arpa/inet.h"
#include "channel.h"
#include "channeltls.h"
#include "circuitlist.h"
#include "connection_or.h"
#include "control.h"
#include "privcount.h"

void
privcount_dns_resolved(edge_connection_t *exitconn, or_circuit_t *oncirc) {
    if(!get_options()->EnablePrivCount || !EVENT_IS_INTERESTING(EVENT_PRIVCOUNT_DNS_RESOLVED)) {
        return;
    }

    if(!oncirc || !oncirc->p_chan || !exitconn) {
        return;
    }

    send_control_event(EVENT_PRIVCOUNT_DNS_RESOLVED,
                       "650 PRIVCOUNT_DNS_RESOLVED %" PRIu64 " %" PRIu32 " %s\r\n",
                       oncirc->p_chan->global_identifier,
                       oncirc->p_circ_id,
                       exitconn->base_.address);
}

void
privcount_stream_data_xferred(edge_connection_t *conn, uint64_t amt,
                              int outbound) {
    if(!get_options()->EnablePrivCount || !EVENT_IS_INTERESTING(EVENT_PRIVCOUNT_STREAM_BYTES_TRANSFERRED)) {
        return;
    }

    if(!conn || conn->base_.type != CONN_TYPE_EXIT) {
        return;
    }

    /* if the circuit started here, this is our own stream and we can ignore it */
    circuit_t* circ = circuit_get_by_edge_conn(conn);
    or_circuit_t *orcirc = NULL;
    if(circ) {
        if(CIRCUIT_IS_ORIGIN(circ)) {
            return;
        }
        /* now we know its an or_circuit_t */
        orcirc = TO_OR_CIRCUIT(circ);
    }

    struct timeval now;
    tor_gettimeofday(&now);

    /* ChanID, CircID, StreamID, BW, Direction, Time */
    send_control_event(EVENT_PRIVCOUNT_STREAM_BYTES_TRANSFERRED,
            "650 PRIVCOUNT_STREAM_BYTES_TRANSFERRED %"PRIu64" %"PRIu32" %"PRIu16" %s %"PRIu64" %ld.%06ld\r\n",
            orcirc && orcirc->p_chan ? orcirc->p_chan->global_identifier : 0,
            orcirc ? orcirc->p_circ_id : 0,
            conn->stream_id,
            (outbound == 1) ? "outbound" : "inbound",
            amt,
            (long)now.tv_sec, (long)now.tv_usec);
}

void
privcount_stream_ended(edge_connection_t *conn) {
    if(!get_options()->EnablePrivCount || !EVENT_IS_INTERESTING(EVENT_PRIVCOUNT_STREAM_ENDED)) {
        return;
    }

    if(!conn) {
        return;
    }

    /* if the circuit started here, this is our own stream and we can ignore it */
    circuit_t* circ = circuit_get_by_edge_conn(conn);
    or_circuit_t *orcirc = NULL;
    if(circ) {
        if(CIRCUIT_IS_ORIGIN(circ)) {
            return;
        }
        /* now we know its an or_circuit_t */
        orcirc = TO_OR_CIRCUIT(circ);
    }

    /* to exclude hidden-service "server" circuits, use this */
    //CIRCUIT_PURPOSE_IS_CLIENT(circ->purpose)

    /* only collect stream info from exits to legitimate client-bound destinations.
     * this means we wont get hidden-service related info */
    if(conn->base_.type != CONN_TYPE_EXIT) {
        return;
    }
    int is_dns = conn->is_dns_request; // means a dns lookup
    int is_dir = (conn->dirreq_id != 0 || conn->base_.port == 1) ? 1 : 0; // means a dir request
    //int is_dir = (conn->base_.type == CONN_TYPE_DIR) ? 1 : 0;

    struct timeval now;
    tor_gettimeofday(&now);

    /* ChanID, CircID, StreamID, ExitPort, ReadBW, WriteBW, TimeStart, TimeEnd, isDNS, isDir */
    send_control_event(EVENT_PRIVCOUNT_STREAM_ENDED,
            "650 PRIVCOUNT_STREAM_ENDED %"PRIu64" %"PRIu32" %"PRIu16" %"PRIu16" %"PRIu64" %"PRIu64" %ld.%06ld %ld.%06ld %d %d\r\n",
            orcirc && orcirc->p_chan ? orcirc->p_chan->global_identifier : 0,
            orcirc ? orcirc->p_circ_id : 0,
            conn->stream_id, conn->base_.port,
            conn->privcount_n_read, conn->privcount_n_written,
            (long)conn->base_.timestamp_created_tv.tv_sec, (long)conn->base_.timestamp_created_tv.tv_usec,
            (long)now.tv_sec, (long)now.tv_usec,
            is_dns, is_dir);
}

void
privcount_circuit_ended(or_circuit_t *orcirc) {
    if(!get_options()->EnablePrivCount || !EVENT_IS_INTERESTING(EVENT_PRIVCOUNT_CIRCUIT_ENDED)) {
        return;
    }

    if(!orcirc || orcirc->privcount_event_emitted) {
        return;
    }

    /* only collect circuit info from first hops on circuits that were actually used
     * we already know this is not an origin circ since we have a or_circuit_t struct */
    int prev_is_client = 0, prev_is_relay = 0;
    if(orcirc->p_chan) {
        if(connection_or_digest_is_known_relay(orcirc->p_chan->identity_digest)) {
            prev_is_relay = 1;
        } else if(orcirc->p_chan->is_client) {
            prev_is_client = 1;
        }
    }

    int next_is_client = 0, next_is_relay = 0;
    if(orcirc->base_.n_chan) {
        if(connection_or_digest_is_known_relay(orcirc->base_.n_chan->identity_digest)) {
            next_is_relay = 1;
        } else if(orcirc->base_.n_chan->is_client) {
            next_is_client = 1;
        }
    }

    orcirc->privcount_event_emitted = 1;

    struct timeval now;
    tor_gettimeofday(&now);

    /* ChanID, CircID, nCellsIn, nCellsOut, ReadBWDNS, WriteBWDNS, ReadBWExit, WriteBWExit, TimeStart, TimeEnd, PrevIP, prevIsClient, prevIsRelay, NextIP, nextIsClient, nextIsRelay */
    send_control_event(EVENT_PRIVCOUNT_CIRCUIT_ENDED,
            "650 PRIVCOUNT_CIRCUIT_ENDED %"PRIu64" %"PRIu32" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %ld.%06ld %ld.%06ld %s %d %d %s %d %d\r\n",
            orcirc->p_chan ? orcirc->p_chan->global_identifier : 0, orcirc->p_circ_id,
            orcirc->privcount_n_cells_in, orcirc->privcount_n_cells_out,
            orcirc->privcount_n_read_dns, orcirc->privcount_n_written_dns,
            orcirc->privcount_n_read_exit, orcirc->privcount_n_written_exit,
            (long)orcirc->base_.timestamp_created.tv_sec, (long)orcirc->base_.timestamp_created.tv_usec,
            (long)now.tv_sec, (long)now.tv_usec,
            orcirc->p_chan ? channel_get_actual_remote_address(orcirc->p_chan) : "0.0.0.0",
            prev_is_client, prev_is_relay,
            orcirc->base_.n_chan ? channel_get_actual_remote_address(orcirc->base_.n_chan) : "0.0.0.0",
            next_is_client, next_is_relay);
}

void
privcount_connection_ended(or_connection_t *orconn) {
    if(!get_options()->EnablePrivCount || !EVENT_IS_INTERESTING(EVENT_PRIVCOUNT_CONNECTION_ENDED)) {
        return;
    }

    if(!orconn) {
        return;
    }

    channel_t* p_chan = (channel_t*)orconn->chan;

    int is_client = 0, is_relay = 0;
    if(p_chan) {
        if(connection_or_digest_is_known_relay(p_chan->identity_digest)) {
            is_relay = 1;
        } else if(p_chan->is_client) {
            is_client = 1;
        }
    }

    struct timeval now;
    tor_gettimeofday(&now);

    /* ChanID, TimeStart, TimeEnd, IP, isClient, isRelay */
    send_control_event(EVENT_PRIVCOUNT_CONNECTION_ENDED,
            "650 PRIVCOUNT_CONNECTION_ENDED %"PRIu64" %ld.%06ld %ld.%06ld %s %d %d\r\n",
            p_chan ? p_chan->global_identifier : 0,
            (long)orconn->base_.timestamp_created_tv.tv_sec, (long)orconn->base_.timestamp_created_tv.tv_usec,
            (long)now.tv_sec, (long)now.tv_usec,
            p_chan ? channel_get_actual_remote_address(p_chan) : "0.0.0.0",
            is_client, is_relay);
}
