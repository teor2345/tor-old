/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file rendcommon.h
 * \brief Header file for rendcommon.c.
 **/

#ifndef TOR_RENDCOMMON_H
#define TOR_RENDCOMMON_H

typedef enum rend_intro_point_failure_t {
  INTRO_POINT_FAILURE_GENERIC     = 0,
  INTRO_POINT_FAILURE_TIMEOUT     = 1,
  INTRO_POINT_FAILURE_UNREACHABLE = 2,
} rend_intro_point_failure_t;

/** Free all storage associated with <b>data</b> */
static inline void
rend_data_free(rend_data_t *data)
{
  if (!data) {
    return;
  }
  /* Cleanup the HSDir identity digest. */
  SMARTLIST_FOREACH(data->hsdirs_fp, char *, d, tor_free(d));
  smartlist_free(data->hsdirs_fp);
  tor_free(data);
}

int rend_cmp_service_ids(const char *one, const char *two);

void rend_process_relay_cell(circuit_t *circ, const crypt_path_t *layer_hint,
                             int command, size_t length,
                             const uint8_t *payload);

void rend_service_descriptor_free(rend_service_descriptor_t *desc);
int rend_get_service_id(crypto_pk_t *pk, char *out);
void rend_encoded_v2_service_descriptor_free(
                               rend_encoded_v2_service_descriptor_t *desc);
void rend_intro_point_free(rend_intro_point_t *intro);

int rend_valid_service_id(const char *query);
int rend_valid_descriptor_id(const char *query);
int rend_encode_v2_descriptors(smartlist_t *descs_out,
                               rend_service_descriptor_t *desc, time_t now,
                               uint8_t period, rend_auth_type_t auth_type,
                               crypto_pk_t *client_key,
                               smartlist_t *client_cookies);
int rend_compute_v2_desc_id(char *desc_id_out, const char *service_id,
                            const char *descriptor_cookie,
                            time_t now, uint8_t replica);
int rend_id_is_in_interval(const char *a, const char *b, const char *c);
void rend_get_descriptor_id_bytes(char *descriptor_id_out,
                                  const char *service_id,
                                  const char *secret_id_part);

rend_data_t *rend_data_dup(const rend_data_t *data);
rend_data_t *rend_data_client_create(const char *onion_address,
                                     const char *desc_id,
                                     const char *cookie,
                                     rend_auth_type_t auth_type);
rend_data_t *rend_data_service_create(const char *onion_address,
                                      const char *pk_digest,
                                      const uint8_t *cookie,
                                      rend_auth_type_t auth_type);

int rend_allow_direct_connection(const or_options_t *options);
int rend_reveal_startup_time(const or_options_t *options);

/* Make sure that tor only builds one-hop circuits when they would not
 * compromise user anonymity.
 *
 * One-hop circuits are permitted:
 *  - for directory connections, or
 *  - in Tor2web or RSOS modes.
 * Otherwise, assert that the circuit is not one-hop.
 *
 * Tor2web and RSOS modes are allowed to make multi-hop circuits.
 * For example, RSOS HSDir circuits are 3-hop to prevent denial of service.
 */
#define assert_circ_onehop_ok(circ, is_dir, options) \
  STMT_BEGIN \
    tor_assert((options)); \
    tor_assert((circ)); \
    tor_assert((circ)->build_state); \
    tor_assert((is_dir) || rend_allow_direct_connection((options)) || \
               (circ)->build_state->onehop_tunnel == 0); \
  STMT_END

#endif

