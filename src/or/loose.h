/*
 * Copyright (c) 2015, Isis Lovecruft
 * Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file loose.h
 * \brief Header file for loose.c.
 **/

#ifndef TOR_LOOSE_H
#define TOR_LOOSE_H

#include "onion.h"
#include "testsupport.h"

extern char loose_circuits_are_possible;

/** Functions and variables for storing state on whether or not we believe we
 * can create loose circuits. */
#ifdef LOOSE_PRIVATE
STATIC char loose_have_completed_a_circuit(void);
STATIC void loose_note_that_we_completed_a_circuit(void);
STATIC void loose_note_that_we_maybe_cant_complete_circuits(void);
#endif

/** Functions for creating loose circuits. */
#ifdef LOOSE_PRIVATE
STATIC loose_or_circuit_t* loose_or_circuit_init(circid_t circ_id,
                                                 channel_t *p_chan,
                                                 uint8_t purpose,
                                                 int flags);
#endif
loose_or_circuit_t* loose_circuit_establish_circuit(circid_t circ_id,
                                                    channel_t *p_chan,
                                                    extend_info_t *entry,
                                                    int len,
                                                    uint8_t purpose,
                                                    int flags);

/** Functions for choosing additional hops in a loose-source routed circuit. */
#ifdef LOOSE_PRIVATE
STATIC extend_info_t*
loose_circuit_pick_cpath_entry(loose_or_circuit_t *loose_circ,
                               extend_info_t *entry);
STATIC int loose_circuit_extend_cpath(loose_or_circuit_t *loose_circ,
                                      extend_info_t *entry);
STATIC int loose_circuit_populate_cpath(loose_or_circuit_t *loose_circ,
                                        extend_info_t *entry);
STATIC void loose_circuit_clear_cpath(loose_or_circuit_t *loose_circ);
#endif

/** Functions for getting or logging information about a loose circuit. */
#ifdef LOOSE_PRIVATE
STATIC void loose_circuit_log_path(int severity, unsigned int domain,
                                   const loose_or_circuit_t *loose_circ);
#endif

/** Function for freeing loose circuits.  Used in circuit_free(). */
void loose_circuit_free(loose_or_circuit_t *loose_circ);

/** Function for handling extra tasks when a loose circuit has completed. */
#ifdef LOOSE_PRIVATE
STATIC void loose_circuit_has_opened(loose_or_circuit_t *loose_circ);
#endif

/* Functions for handling specific cell types on a loose circuit. */
#ifdef LOOSE_PRIVATE
STATIC int loose_circuit_handle_first_hop(loose_or_circuit_t *loose_circ);
STATIC int loose_circuit_finish_handshake(loose_or_circuit_t *loose_circ,
                                          const created_cell_t *reply);
STATIC int loose_circuit_make_create_cell(loose_or_circuit_t *loose_circ);
STATIC int loose_circuit_send_create_cell(loose_or_circuit_t *loose_circ);
STATIC int loose_circuit_extend(loose_or_circuit_t *loose_circ);
STATIC int loose_circuit_extend_to_next_hop(loose_or_circuit_t *loose_circ);
#endif
void loose_circuit_answer_create_cell(loose_or_circuit_t *loose_circ,
                                      cell_t *cell);
int loose_circuit_process_created_cell(loose_or_circuit_t *loose_circ,
                                       created_cell_t *created_cell);
int loose_circuit_process_relay_cell(loose_or_circuit_t *loose_circ,
                                     crypt_path_t *layer_hint,
                                     cell_t *cell,
                                     cell_direction_t cell_direction,
                                     char recognized);
MOCK_DECL(int, loose_circuit_send_next_onion_skin,
          (loose_or_circuit_t *loose_circ));

#endif
