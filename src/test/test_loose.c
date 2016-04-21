/*
 * Copyright (c) 2015, Isis Lovecruft
 * Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define TOR_CHANNEL_INTERNAL_   /* Needed for channel_init() */
#define CIRCUITLIST_PRIVATE     /* Needed for circuit_free() */
#define LOOSE_PRIVATE

#include "or.h"
#include "test.h"
#include "testsupport.h"
#include "channel.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "command.h"
#include "loose.h"
#include "onion_fast.h"
#include "onion_ntor.h"
#include "relay.h"

/*****************************************************************************
 * The following are all stolen verbatim from test_circuitlist.c, because I
 * wasn't sure if it was okay to include functions from another test_* file.
 * -isis
 *****************************************************************************/
#define GOT_CMUX_ATTACH(mux_, circ_, dir_) do {  \
    tt_int_op(cam.ncalls, OP_EQ, 1);             \
    tt_ptr_op(cam.cmux, OP_EQ, (mux_));          \
    tt_ptr_op(cam.circ, OP_EQ, (circ_));         \
    tt_int_op(cam.dir, OP_EQ, (dir_));           \
    memset(&cam, 0, sizeof(cam));                \
  } while (0)

#define GOT_CMUX_DETACH(mux_, circ_) do {        \
    tt_int_op(cdm.ncalls, OP_EQ, 1);             \
    tt_ptr_op(cdm.cmux, OP_EQ, (mux_));          \
    tt_ptr_op(cdm.circ, OP_EQ, (circ_));         \
    memset(&cdm, 0, sizeof(cdm));                \
  } while (0)

static channel_t *
new_fake_channel(void)
{
  channel_t *chan = tor_malloc_zero(sizeof(channel_t));
  channel_init(chan);
  chan->cmux = circuitmux_alloc();
  return chan;
}

static void
free_fake_channel(channel_t *chan)
{
  if (chan && chan->cmux)
    tor_free(chan->cmux);
  if (chan)
    tor_free(chan);
}

static struct {
  int ncalls;
  void *cmux;
  void *circ;
  cell_direction_t dir;
} cam;

static void
circuitmux_attach_mock(circuitmux_t *cmux, circuit_t *circ,
                       cell_direction_t dir)
{
  ++cam.ncalls;
  cam.cmux = cmux;
  cam.circ = circ;
  cam.dir = dir;
}

static struct {
  int ncalls;
  void *cmux;
  void *circ;
} cdm;

static void
circuitmux_detach_mock(circuitmux_t *cmux, circuit_t *circ)
{
  ++cdm.ncalls;
  cdm.cmux = cmux;
  cdm.circ = circ;
}
/************************** END PLAGIARISED CODE *****************************/

/*****************************************************************************
 *                           MOCKED FUNCTIONS
 *****************************************************************************/

/**
 * Mocked version of loose_circuit_send_next_onion_skin() which does nothing
 * and always returns success.
 */
static int
mock_loose_circuit_send_next_onion_skin_success(loose_or_circuit_t *loose_circ)
{
  (void)loose_circ;
  return 0;
}

/**
 * Mocked version of loose_circuit_send_next_onion_skin() which does nothing
 * and always returns -END_CIRC_REASON_INTERNAL.
 */
static int
mock_loose_circuit_send_next_onion_skin_failure(loose_or_circuit_t *loose_circ)
{
  (void)loose_circ;
  return -END_CIRC_REASON_INTERNAL;
}

static const node_t *choice = NULL;

/**
 * Pretend that choose_good_entry_server() couldn't find a suitable entry node.
 */
static const node_t *
mock_choose_good_entry_server_null(uint8_t purpose, cpath_build_state_t *state)
{
  (void)purpose; (void)state; return choice;
}

/**
 * Version of choose_good_entry_server() which returns the same mocked entry
 * node every time.
 */
static const node_t *
mock_choose_good_entry_server(uint8_t purpose, cpath_build_state_t *state)
{
  static node_t mock_node;
  static routerstatus_t mock_rs;
  static routerinfo_t mock_ri;
  curve25519_public_key_t mock_curve25519;

  (void)purpose; (void)state;

  memset(&mock_node, 0, sizeof(node_t));
  memset(&mock_rs, 0, sizeof(routerstatus_t));
  memset(&mock_ri, 0, sizeof(routerinfo_t));
  memset(&mock_curve25519.public_key, 0, sizeof(mock_curve25519.public_key));

  strlcpy(mock_rs.nickname, "TestOR", sizeof(mock_rs.nickname));
  mock_node.rs = &mock_rs;

  mock_ri.addr = 123456789u;
  mock_ri.or_port = 9001;
  mock_node.ri = &mock_ri;
  mock_node.ri->onion_curve25519_pkey = &mock_curve25519;

  memcpy(mock_node.identity,
         "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
         "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA",
         DIGEST_LEN);

  return &mock_node;
}

/**
 * Pretend that choose_good_middle_server() couldn't find a suitable middle
 * node.
 */
static const node_t *
mock_choose_good_middle_server_null(uint8_t purpose,
                                    cpath_build_state_t *state,
                                    crypt_path_t *head, int cur_len)

{
  (void)purpose; (void)state; (void)head; (void)cur_len; return choice;
}

/**
 * Version of choose_good_middle_server() which returns the same mocked middle
 * node every time.
 */
static const node_t *
mock_choose_good_middle_server(uint8_t purpose, cpath_build_state_t *state,
                               crypt_path_t *head, int cur_len)
{
  static node_t mock_node;
  static routerstatus_t mock_rs;
  static routerinfo_t mock_ri;
  curve25519_public_key_t mock_curve25519;

  (void)purpose; (void)state; (void)head; (void)cur_len;

  memset(&mock_node, 0, sizeof(node_t));
  memset(&mock_rs, 0, sizeof(routerstatus_t));
  memset(&mock_ri, 0, sizeof(routerinfo_t));

  /* We need need ri.onion_pkey or ri.onion_curve25519_pkey in order for
   * extend_info_from_node() and extend_info_new() to be happy, and zomg…
   * don't want to mock an openssl rsa_st… */
  memset(&mock_curve25519.public_key, 1, sizeof(mock_curve25519.public_key));

  strlcpy(mock_rs.nickname, "TestORMiddle", sizeof(mock_rs.nickname));
  mock_node.rs = &mock_rs;

  mock_ri.addr = 987654321u;
  mock_ri.or_port = 9001;
  mock_ri.onion_curve25519_pkey = &mock_curve25519;
  mock_node.ri = &mock_ri;

  memcpy(mock_node.identity,
         "\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB"
         "\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB\xBB", DIGEST_LEN);

  return &mock_node;
}

/**
 * Mocked command_answer_create_cell() that always returns success.
 */
static int
mock_command_answer_create_cell_success(circuit_t *circ, channel_t *chan,
                                        cell_t *cell)
{ (void)circ; (void)chan; (void)cell; return 0; }

/**
 * Mocked command_answer_create_cell() that always returns
 * -END_CIRC_REASON_INTERNAL.
 */
static int
mock_command_answer_create_cell_failure(circuit_t *circ, channel_t *chan,
                                        cell_t *cell)
{ (void)circ; (void)chan; (void)cell; return -END_CIRC_REASON_INTERNAL; }

/**
 * Mocked circuit_deliver_create_cell() that always returns success.
 */
static int
mock_circuit_deliver_create_cell_success(circuit_t *circ,
                                         const create_cell_t *create_cell,
                                         int relayed)
{
  (void)circ; (void)create_cell; (void)relayed;
  return 0;
}

/**
 * Mocked circuit_deliver_create_cell() that always returns
 * -END_CIRC_REASON_INTERNAL.
 */
static int
mock_circuit_deliver_create_cell_failure(circuit_t *circ,
                                         const create_cell_t *create_cell,
                                         int relayed)
{
  (void)circ; (void)create_cell; (void)relayed;
  return -END_CIRC_REASON_INTERNAL;
}

/**
 * Mocked channel_connect_for_circuit() which always returns a statically
 * allocated channel.
 */
static channel_t *
mock_channel_connect_for_circuit_success(const tor_addr_t *addr,
                                         uint16_t port, const char *id_digest)
{
  static channel_t *chan;
  (void)addr; (void)port; (void)id_digest;
  chan = new_fake_channel();
  return chan;
}

/**
 * Mocked channel_connect_for_circuit() which always returns failure.
 */
static channel_t *
mock_channel_connect_for_circuit_failure(const tor_addr_t *addr,
                                         uint16_t port, const char *id_digest)
{
  static channel_t *chan = NULL;
  (void)addr; (void)port; (void)id_digest;
  return chan;
}

/**
 * Mocked channel_get_for_extend() which always returns a statically allocated
 * channel.
 */
static channel_t *
mock_channel_get_for_extend_success(const char *digest,
                                    const tor_addr_t *target_addr,
                                    const char **msg_out,
                                    int *launch_out)
{
  static channel_t *chan;
  (void)digest; (void)target_addr; (void)msg_out; (void)launch_out;
  chan = new_fake_channel();
  return chan;
}

/**
 * Mocked channel_get_for_extend() which always returns failure.
 */
static channel_t *
mock_channel_get_for_extend_failure(const char *digest,
                                    const tor_addr_t *target_addr,
                                    const char **msg_out,
                                    int *launch_out)
{
  static channel_t *chan = NULL;
  (void)digest; (void)target_addr; (void)msg_out; (void)launch_out;
  return chan;
}

/**
 * Mocked append_cell_to_circuit_queue() which does nothing.
 */
static void
mock_append_cell_to_circuit_queue(circuit_t *circ, channel_t *chan,
                                  cell_t *cell, cell_direction_t direction,
                                  streamid_t fromstream)
{ (void)circ; (void)chan; (void)cell; (void)direction; (void)fromstream; }

/*****************************************************************************/
/*                             UTILITIES                                     */
/*****************************************************************************/

/** Make a create cell. */
static create_cell_t
make_create_cell(extend_info_t *extend_info,
                 onion_handshake_state_t *handshake_state)
{
  create_cell_t create;

  memset(&create, 0, sizeof(create_cell_t));

  create.cell_type = CELL_CREATE_FAST;
  create.handshake_type = ONION_HANDSHAKE_TYPE_FAST;
  create.handshake_len = CREATE_FAST_LEN;
  onion_skin_create(create.handshake_type, extend_info,
                    handshake_state, create.onionskin);
  return create;
}

/** Make a created cell, given a create cell. */
static created_cell_t
make_created_cell(create_cell_t *create)
{
  created_cell_t created;
  uint8_t keys[CPATH_KEY_MATERIAL_LEN];
  uint8_t rend_whatevs[DIGEST_LEN];
  int len;

  memset(&created, 0, sizeof(created_cell_t));

  /* What create_cell_parse() and create_cell_init() would do. */
  len = onion_skin_server_handshake(ONION_HANDSHAKE_TYPE_FAST,
                                    create->onionskin,
                                    create->handshake_len,
                                    NULL, created.reply,
                                    keys, CPATH_KEY_MATERIAL_LEN,
                                    rend_whatevs);
  created.cell_type = CELL_CREATED_FAST;
  created.handshake_len = len;

  return created;
}

/****************************************************************************/
/*                             UNITTESTS                                    */
/****************************************************************************/

/**
 * Simple exercises for the functionality of loose_have_completed_a_circuit(),
 * loose_note_that_we_completed_a_circuit(), and
 * loose_note_that_we_maybe_cant_complete_circuits().
 */
static void
test_loose_can_complete_circuits(void *arg)
{
  (void)arg;

  /* Should start out false. */
  tt_int_op(loose_have_completed_a_circuit(), OP_EQ, 0);

  /* Setting it to true should make it true. */
  loose_note_that_we_completed_a_circuit();
  tt_int_op(loose_have_completed_a_circuit(), OP_EQ, 1);

  /* Setting it to false should make it false. */
  loose_note_that_we_maybe_cant_complete_circuits();
  tt_int_op(loose_have_completed_a_circuit(), OP_EQ, 0);

 done:
  ;
}

/**
 * Calling loose_circuit_init() should initialise a new loose_circuit_t.
 */
static void
test_loose_circuit_init(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = new_fake_channel();

  (void)arg;

  loose_circuits_are_possible = 1;
  loose_circ = loose_or_circuit_init(circ_id, p_chan, CIRCUIT_PURPOSE_OR, 0);

  tt_assert(loose_circ);
  tt_assert(LOOSE_TO_CIRCUIT(loose_circ)->state == CIRCUIT_STATE_CHAN_WAIT);
  tt_assert(LOOSE_TO_OR_CIRCUIT(loose_circ)->p_chan);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  free_fake_channel(p_chan);
}

/**
 * Test casting between loose_circuit_t and other circuit types.
 */
static void
test_loose_circuit_casts(void *arg)
{
  loose_or_circuit_t *loose_circ;
  or_circuit_t *or_circ;
  circuit_t *circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = new_fake_channel();

  (void)arg;

  loose_circuits_are_possible = 1;
  loose_circ = loose_or_circuit_init(circ_id, p_chan, CIRCUIT_PURPOSE_OR, 0);

  tt_assert(loose_circ);

  or_circ = LOOSE_TO_OR_CIRCUIT(loose_circ);
  tt_assert(or_circ);
  tt_ptr_op(OR_TO_LOOSE_CIRCUIT(or_circ), OP_EQ, loose_circ);

  circ = LOOSE_TO_CIRCUIT(loose_circ);
  tt_assert(circ);
  tt_ptr_op(TO_LOOSE_CIRCUIT(circ), OP_EQ, loose_circ);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  free_fake_channel(p_chan);
}

/**
 * Calling loose_circuit_free() with NULL should log a warning and do nothing.
 */
static void
test_loose_circuit_free(void *arg)
{
  loose_or_circuit_t *loose_circ = NULL;

  (void)arg;
  loose_circuit_free(loose_circ);
}

/**
 * Calling loose_circuit_log_path() should log some info about the cpath.
 */
static void
test_loose_circuit_log_path(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;
  extend_info_t *entry = NULL;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(channel_get_for_extend, mock_channel_get_for_extend_success);

  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);
  loose_circuit_log_path(LOG_WARN, LD_CIRC, loose_circ);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(channel_get_for_extend);
}

/**
 * Calling loose_circuit_extend_cpath() should add additional hops to
 * loose_circ->cpath.
 */
static void
test_loose_circuit_extend_cpath_multihop(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;
  extend_info_t *entry = NULL;
  int result;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(choose_good_middle_server, mock_choose_good_middle_server);

  /* Initialise a loose circuit, and set it's desired path length to 2. */
  loose_circ = loose_or_circuit_init(circ_id, p_chan, CIRCUIT_PURPOSE_OR, 0);
  loose_circ->build_state->desired_path_len = 2;
  entry = loose_circuit_pick_cpath_entry(loose_circ, entry);

  tt_assert(entry);
  tt_assert(loose_circ);
  tt_int_op(cpath_get_len(loose_circ->cpath), OP_EQ, 0);
  tt_int_op(loose_circ->build_state->desired_path_len, OP_EQ, 2);

  result = loose_circuit_extend_cpath(loose_circ, entry);
  tt_int_op(result, OP_EQ, 0);
  tt_int_op(cpath_get_len(loose_circ->cpath), OP_EQ, 1);
  tt_int_op(loose_circ->build_state->desired_path_len, OP_EQ, 2);

  result = loose_circuit_extend_cpath(loose_circ, entry);
  tt_int_op(result, OP_EQ, 0);
  tt_int_op(cpath_get_len(loose_circ->cpath), OP_EQ, 2);
  tt_int_op(loose_circ->build_state->desired_path_len, OP_EQ, 2);

  tt_assert(!loose_circ->build_state->chosen_exit);

  result = loose_circuit_extend_cpath(loose_circ, entry);
  tt_int_op(result, OP_EQ, 1);  // returns 1 when finished
  tt_int_op(cpath_get_len(loose_circ->cpath), OP_EQ, 2);
  tt_int_op(loose_circ->build_state->desired_path_len, OP_EQ, 2);

  tt_assert(loose_circ->build_state->chosen_exit);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  UNMOCK(choose_good_entry_server);
  UNMOCK(choose_good_middle_server);
}

/**
 * Call loose_circuit_populate_cpath() with a desired path length of 2, and
 * pretend that one of our nodes has already supports ntor.  The returned
 * result should be 0.
 */
static void
test_loose_circuit_populate_cpath_multihop(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;
  extend_info_t *entry = NULL;
  int result;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(choose_good_middle_server, mock_choose_good_middle_server);

  /* Initialise a loose circuit, and set it's desired path length to 2. */
  loose_circ = loose_or_circuit_init(circ_id, p_chan, CIRCUIT_PURPOSE_OR, 0);
  loose_circ->build_state->desired_path_len = 2;
  entry = loose_circuit_pick_cpath_entry(loose_circ, entry);

  tt_assert(entry);
  tt_assert(loose_circ);
  tt_int_op(cpath_get_len(loose_circ->cpath), OP_EQ, 0);
  tt_int_op(loose_circ->build_state->desired_path_len, OP_EQ, 2);

  result = loose_circuit_populate_cpath(loose_circ, entry);
  tt_int_op(result, OP_EQ, 0);
  tt_int_op(cpath_get_len(loose_circ->cpath), OP_EQ, 2);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  UNMOCK(choose_good_entry_server);
  UNMOCK(choose_good_middle_server);
}

/**
 * Call loose_circuit_populate_cpath() with a desired path length of 2, and
 * pretend that one of our nodes has already supports ntor.  The returned
 * result should be 0.
 */
static void
test_loose_circuit_populate_cpath_multihop_ntor(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;
  extend_info_t *entry = NULL;
  int result;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(choose_good_middle_server, mock_choose_good_middle_server);
  MOCK(channel_get_for_extend, mock_channel_get_for_extend_success);

  /* Create a default-length loose circuit. */
  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);

  /* Change the desired path length to two hops. */
  loose_circ->build_state->desired_path_len = 2;
  /* And pretend that the first hop supports ntor. */
  memset(loose_circ->cpath->extend_info->curve25519_onion_key.public_key, 1,
      sizeof(loose_circ->cpath->extend_info->curve25519_onion_key.public_key));
  /* Now populate the path again. */
  result = loose_circuit_populate_cpath(loose_circ, NULL);
  tt_int_op(result, OP_EQ, 0);

  /* Reset the path and try without any nodes which "support" ntor. */
  loose_circuit_clear_cpath(loose_circ);
  result = loose_circuit_populate_cpath(loose_circ, entry);
  tt_int_op(result, OP_EQ, -1);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(choose_good_middle_server);
  UNMOCK(channel_get_for_extend);
}

/**
 * Call loose_circuit_populate_cpath() with a desired path length of 42, and
 * mocking choose_good_middle_server() to always return NULL.  Since we fail
 * to find a suitable second through forty-second hops, the returned result
 * should be -1.
 */
static void
test_loose_circuit_populate_cpath_multihop_null(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;
  extend_info_t *entry = NULL;
  int result;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(choose_good_middle_server, mock_choose_good_middle_server_null);

  loose_circ = loose_or_circuit_init(circ_id, p_chan, CIRCUIT_PURPOSE_OR, 0);
  loose_circ->build_state->desired_path_len = 42;
  entry = loose_circuit_pick_cpath_entry(loose_circ, entry);

  tt_assert(entry);
  tt_assert(loose_circ);
  tt_int_op(cpath_get_len(loose_circ->cpath), OP_EQ, 0);
  tt_int_op(loose_circ->build_state->desired_path_len, OP_EQ, 42);

 /* Should fail and hit the "Generating cpath hop failed." log message. */
  result = loose_circuit_populate_cpath(loose_circ, entry);
  tt_int_op(result, OP_EQ, -1);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  UNMOCK(choose_good_entry_server);
  UNMOCK(choose_good_middle_server);
}

/**
 * It should be safe to call loose_circuit_clear_cpath() when
 * loose_circ->cpath == NULL (i.e., calling it twice in a row should be okay.
 */
static void
test_loose_circuit_clear_cpath_null(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;

  (void)arg;

  loose_circuits_are_possible = 1;
  loose_circ = loose_or_circuit_init(circ_id, p_chan, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);

  loose_circuit_clear_cpath(loose_circ);
  loose_circuit_clear_cpath(loose_circ);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
}

/**
 * Calling loose_circuit_establish_circuit() when loose_circuits_are_possible
 * is false should return NULL.
 */
static void
test_loose_circuit_establish_circuit_not_possible(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;
  extend_info_t *entry = NULL;

  (void)arg;

  loose_circuits_are_possible = 0;
  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(!loose_circ);
  tt_assert(loose_circ == NULL);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
}

/**
 * Calling loose_circuit_establish_circuit() when loose_circuits_are_possible
 * is true should allocate and construct a loose_or_circuit_t.
 */
static void
test_loose_circuit_establish_circuit_unattached(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;
  extend_info_t *entry = NULL;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(circuit_deliver_create_cell, mock_circuit_deliver_create_cell_success);
  MOCK(channel_get_for_extend, mock_channel_get_for_extend_success);

  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);
  tt_assert(loose_circ->cpath);
  tt_assert(loose_circ->build_state);
  tt_assert(! (LOOSE_TO_CIRCUIT(loose_circ)->marked_for_close));

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(circuit_deliver_create_cell);
  UNMOCK(channel_get_for_extend);
}

/**
 * Calling loose_circuit_establish_circuit() when loose_circuits_are_possible
 * is true, but no suitable entry server is available, should mark the
 * loose_circuit_t for close and return NULL.
 */
static void
test_loose_circuit_establish_circuit_unattached_no_entry(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;
  extend_info_t *entry = NULL;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(choose_good_entry_server, mock_choose_good_entry_server_null);

  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(!loose_circ);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  UNMOCK(choose_good_entry_server);
}

/**
 * Calling loose_circuit_establish_circuit() when
 * loose_circuit_handle_first_hop() returns failure (because
 * channnel_connect_for_circuit() is mocked to fail) should mark the circuit
 * for close and return NULL.
 */
static void
test_loose_circuit_establish_circuit_connection_failure(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;
  extend_info_t *entry = NULL;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(channel_connect_for_circuit, mock_channel_connect_for_circuit_failure);

  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(!loose_circ);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  UNMOCK(choose_good_entry_server);
  UNMOCK(channel_connect_for_circuit);
}

/**
 * Calling loose_circuit_establish_circuit() with a specified length of 2
 * should add two additional hops to the loose-source routed circuit.
 */
static void
test_loose_circuit_establish_circuit_unattached_multihop(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;
  extend_info_t *entry = NULL;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(choose_good_middle_server, mock_choose_good_middle_server);
  MOCK(channel_get_for_extend, mock_channel_get_for_extend_success);

  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               2, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(choose_good_middle_server);
  UNMOCK(channel_get_for_extend);
}

/**
 * Calling loose_circuit_establish_circuit() when loose_circuits_are_possible
 * is true should allocate and construct a loose_or_circuit_t.  Since circ_id
 * and p_chan are passed in, the circuit should be successfully attached to a
 * circuitmux.
 *
 * Mostly plagiarised from test_clist_maps() in test_circuitlist.c.
 */
static void
test_loose_circuit_establish_circuit_attached(void *arg)
{
  loose_or_circuit_t *loose_circ1 = NULL;
  loose_or_circuit_t *loose_circ2 = NULL;
  circuit_t *circ1, *circ2;
  extend_info_t *entry = NULL;
  circid_t circ_id = 100;
  channel_t *ch1 = new_fake_channel();
  channel_t *ch2 = new_fake_channel();
  channel_t *ch3 = new_fake_channel();

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(circuit_deliver_create_cell, mock_circuit_deliver_create_cell_success);
  MOCK(channel_get_for_extend, mock_channel_get_for_extend_failure);
  MOCK(channel_connect_for_circuit, mock_channel_connect_for_circuit_success);

  memset(&cam, 0, sizeof(cam));
  memset(&cdm, 0, sizeof(cdm));

  tt_assert(ch1);
  tt_assert(ch2);
  tt_assert(ch3);

  /* Set up the first circuit */
  loose_circ1 = loose_circuit_establish_circuit(circ_id, ch1, entry,
                                                0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ1);
  tt_assert(loose_circ1->cpath);
  tt_assert(loose_circ1->build_state);
  tt_int_op(LOOSE_TO_CIRCUIT(loose_circ1)->marked_for_close, OP_EQ, 0);

  GOT_CMUX_ATTACH(ch1->cmux, loose_circ1, CELL_DIRECTION_IN);
  tt_int_op(LOOSE_TO_OR_CIRCUIT(loose_circ1)->p_circ_id, OP_EQ, 100);
  tt_ptr_op(LOOSE_TO_OR_CIRCUIT(loose_circ1)->p_chan, OP_EQ, ch1);

  /* Set up the second circuit */
  loose_circ2 = loose_circuit_establish_circuit(circ_id, ch2, entry,
                                                0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ2);
  tt_assert(loose_circ2->cpath);
  tt_assert(loose_circ2->build_state);
  tt_int_op(LOOSE_TO_CIRCUIT(loose_circ2)->marked_for_close, OP_EQ, 0);

  GOT_CMUX_ATTACH(ch2->cmux, loose_circ2, CELL_DIRECTION_IN);
  tt_int_op(LOOSE_TO_OR_CIRCUIT(loose_circ2)->p_circ_id, OP_EQ, 100);
  tt_ptr_op(LOOSE_TO_OR_CIRCUIT(loose_circ2)->p_chan, OP_EQ, ch2);

  circ1 = LOOSE_TO_CIRCUIT(loose_circ1);
  circ2 = LOOSE_TO_CIRCUIT(loose_circ2);

  circuit_set_n_circid_chan(circ1, 200, ch2);
  GOT_CMUX_ATTACH(ch2->cmux, loose_circ1, CELL_DIRECTION_OUT);

  circuit_set_n_circid_chan(circ2, 200, ch1);
  GOT_CMUX_ATTACH(ch1->cmux, loose_circ2, CELL_DIRECTION_OUT);

  /* Check that we can retrieve them from the global circuitlist. */
  tt_ptr_op(circuit_get_by_circid_channel(200, ch1), OP_EQ, circ2);
  tt_ptr_op(circuit_get_by_circid_channel(200, ch2), OP_EQ, circ1);
  tt_ptr_op(circuit_get_by_circid_channel(100, ch2), OP_EQ, circ2);
  /* Try the same thing again, to test the "fast" path. */
  tt_ptr_op(circuit_get_by_circid_channel(100, ch2), OP_EQ, circ2);
  tt_assert(circuit_id_in_use_on_channel(100, ch2));
  tt_assert(! circuit_id_in_use_on_channel(101, ch2));

  /* Try changing the circuitid and channel of that circuit. */
  circuit_set_p_circid_chan(LOOSE_TO_OR_CIRCUIT(loose_circ1), 500, ch3);
  GOT_CMUX_DETACH(ch1->cmux, circ1);
  GOT_CMUX_ATTACH(ch3->cmux, circ1, CELL_DIRECTION_IN);
  tt_ptr_op(circuit_get_by_circid_channel(100, ch1), OP_EQ, NULL);
  tt_assert(! circuit_id_in_use_on_channel(100, ch1));
  tt_ptr_op(circuit_get_by_circid_channel(500, ch3), OP_EQ, circ1);

  /* Now let's see about destroy handling. */
  tt_assert(! circuit_id_in_use_on_channel(205, ch2));
  tt_assert(circuit_id_in_use_on_channel(200, ch2));
  channel_note_destroy_pending(ch1, 200);
  channel_note_destroy_pending(ch1, 205);
  channel_note_destroy_pending(ch2, 100);
  tt_assert(circuit_id_in_use_on_channel(205, ch1))
  tt_assert(circuit_id_in_use_on_channel(200, ch2));
  tt_assert(circuit_id_in_use_on_channel(100, ch2));

  tt_assert(LOOSE_TO_CIRCUIT(loose_circ2)->n_delete_pending != 0);
  tt_ptr_op(circuit_get_by_circid_channel(200, ch1), OP_EQ, circ2);
  tt_ptr_op(circuit_get_by_circid_channel(100, ch2), OP_EQ, circ2);

  /* Okay, now free ch2 and make sure that the circuit ID is STILL not
   * usable, because we haven't declared the destroy to be nonpending */
  tt_int_op(cdm.ncalls, OP_EQ, 0);
  circuit_free(LOOSE_TO_CIRCUIT(loose_circ2));
  loose_circ2 = NULL; /* prevent free */
  tt_int_op(cdm.ncalls, OP_EQ, 2);
  memset(&cdm, 0, sizeof(cdm));
  tt_assert(circuit_id_in_use_on_channel(200, ch1));
  tt_assert(circuit_id_in_use_on_channel(100, ch2));
  tt_ptr_op(circuit_get_by_circid_channel(200, ch1), OP_EQ, NULL);
  tt_ptr_op(circuit_get_by_circid_channel(100, ch2), OP_EQ, NULL);

  /* Now say that the destroy is nonpending */
  channel_note_destroy_not_pending(ch1, 200);
  tt_ptr_op(circuit_get_by_circid_channel(200, ch1), OP_EQ, NULL);
  channel_note_destroy_not_pending(ch2, 100);
  tt_ptr_op(circuit_get_by_circid_channel(100, ch2), OP_EQ, NULL);
  tt_assert(! circuit_id_in_use_on_channel(200, ch1));
  tt_assert(! circuit_id_in_use_on_channel(100, ch2));

 done:
  if (loose_circ1)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ1));
  if (loose_circ2)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ2));
  free_fake_channel(ch1);
  free_fake_channel(ch2);
  free_fake_channel(ch3);

  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(circuit_deliver_create_cell);
  UNMOCK(channel_get_for_extend);
  UNMOCK(channel_connect_for_circuit);
}

/**
 * Calling loose_circuit_establish_circuit() when loose_circuits_are_possible
 * is true should allocate and construct a loose_or_circuit_t.  Since circ_id
 * and p_chan are passed in, the circuit should be successfully attached to a
 * circuitmux.
 */
static void
test_loose_circuit_establish_circuit_attached_multihop(void *arg)
{
  loose_or_circuit_t *loose_circ1 = NULL;
  extend_info_t *entry = NULL;
  circid_t circ_id = 100;
  channel_t *ch1 = new_fake_channel();
  channel_t *ch2 = new_fake_channel();

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(choose_good_middle_server, mock_choose_good_middle_server);
  MOCK(circuit_deliver_create_cell, mock_circuit_deliver_create_cell_success);
  MOCK(command_answer_create_cell, mock_command_answer_create_cell_success);
  MOCK(channel_get_for_extend, mock_channel_get_for_extend_success);

  memset(&cam, 0, sizeof(cam));
  memset(&cdm, 0, sizeof(cdm));

  tt_assert(ch1);
  tt_assert(ch2);

  /* Set up a two hop loose circuit. */
  loose_circ1 = loose_circuit_establish_circuit(circ_id, ch1, entry,
                                                2, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ1);

  GOT_CMUX_ATTACH(ch1->cmux, loose_circ1, CELL_DIRECTION_IN);
  tt_int_op(LOOSE_TO_OR_CIRCUIT(loose_circ1)->p_circ_id, OP_EQ, 100);
  tt_ptr_op(LOOSE_TO_OR_CIRCUIT(loose_circ1)->p_chan, OP_EQ, ch1);

  circuit_set_n_circid_chan(LOOSE_TO_CIRCUIT(loose_circ1), 200, ch2);
  GOT_CMUX_ATTACH(ch2->cmux, loose_circ1, CELL_DIRECTION_OUT);

  /* Check that we can retrieve it from the global circuitlist. */
  tt_ptr_op(circuit_get_by_circid_channel(200, ch2),
            OP_EQ, LOOSE_TO_CIRCUIT(loose_circ1));

  /* Check the circuit lengths */
  tt_int_op(loose_circ1->build_state->desired_path_len, OP_EQ, 2);
  tt_int_op(cpath_get_len(loose_circ1->cpath), OP_EQ, 2);

 done:
  if (loose_circ1)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ1));
  free_fake_channel(ch1);
  free_fake_channel(ch2);

  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(choose_good_middle_server);
  UNMOCK(circuit_deliver_create_cell);
  UNMOCK(command_answer_create_cell);
  UNMOCK(channel_get_for_extend);
}

/**
 * Calling loose_circuit_pick_cpath_entry() should pick a valid entry (guard)
 * node.
 */
static void
test_loose_circuit_pick_cpath_entry(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;
  extend_info_t *entry = NULL;

  (void)arg;

  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  loose_circ = loose_or_circuit_init(circ_id, p_chan, CIRCUIT_PURPOSE_OR, 0);
  entry = loose_circuit_pick_cpath_entry(loose_circ, entry);
  tt_assert(entry);

 done:
  extend_info_free(entry);
  UNMOCK(choose_good_entry_server);
}

/**
 * Calling loose_circuit_pick_cpath_entry(), when choose_good_entry_server()
 * can't find a suitable entry node, should return NULL.
 */
static void
test_loose_circuit_pick_cpath_entry_null(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;
  extend_info_t *entry = NULL;

  (void)arg;

  MOCK(choose_good_entry_server, mock_choose_good_entry_server_null);
  loose_circ = loose_or_circuit_init(circ_id, p_chan, CIRCUIT_PURPOSE_OR, 0);
  entry = loose_circuit_pick_cpath_entry(loose_circ, entry);
  tt_ptr_op(entry, OP_EQ, NULL);

 done:
  UNMOCK(choose_good_entry_server);
}

/**
 * Calling loose_circuit_pick_cpath_entry(), when an entry node is already
 * chosen should simply return the extend_info_t for the chosen node.
 */
static void
test_loose_circuit_pick_cpath_entry_chosen(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;
  const node_t *chosen_node;
  extend_info_t *entry, *chosen_entry = NULL;

  (void)arg;

  chosen_node = mock_choose_good_entry_server(0, NULL);
  chosen_entry = extend_info_from_node(chosen_node, 0);
  tt_want(chosen_node);
  tt_want(chosen_entry);

  MOCK(choose_good_entry_server, mock_choose_good_entry_server_null);
  loose_circ = loose_or_circuit_init(circ_id, p_chan, CIRCUIT_PURPOSE_OR, 0);
  entry = loose_circuit_pick_cpath_entry(loose_circ, chosen_entry);

  tt_ptr_op(entry, OP_EQ, chosen_entry);
  tt_str_op(entry->nickname, OP_EQ, chosen_entry->nickname);
  tt_str_op(entry->identity_digest, OP_EQ, chosen_entry->identity_digest);
  tt_mem_op(entry->identity_digest, OP_EQ,
            "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
            "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA", DIGEST_LEN);

 done:
  UNMOCK(choose_good_entry_server);
}

/**
 * When loose_circuit_send_next_onion_skin() is mocked to fail,
 * loose_circuit_handle_first_hop() should return a negative integer specifying
 * the reason why the circuit should be marked for close.
 */
static void
test_loose_circuit_handle_first_hop(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = 100;
  channel_t *p_chan = new_fake_channel();
  extend_info_t *entry = NULL;
  int ret = 0;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(command_answer_create_cell, mock_command_answer_create_cell_success);
  MOCK(circuit_deliver_create_cell, mock_circuit_deliver_create_cell_success);
  MOCK(channel_get_for_extend, mock_channel_get_for_extend_success);
  MOCK(loose_circuit_send_next_onion_skin,
       mock_loose_circuit_send_next_onion_skin_failure);

  /* Do all the steps that loose_circuit_establish_circuit() would do, so that
   * we can test what happens when loose_circuit_handle_first_hop() fails. */
  loose_circ = loose_or_circuit_init(circ_id, p_chan, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);
  loose_circ->build_state->desired_path_len = 1;
  entry = loose_circuit_pick_cpath_entry(loose_circ, entry);
  tt_assert(entry);
  ret = loose_circuit_populate_cpath(loose_circ, entry);
  tt_int_op(ret, OP_GE, 0);

  ret = loose_circuit_handle_first_hop(loose_circ);
  tt_int_op(ret, OP_EQ, -END_CIRC_REASON_INTERNAL);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  free_fake_channel(p_chan);
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(command_answer_create_cell);
  UNMOCK(circuit_deliver_create_cell);
  UNMOCK(channel_get_for_extend);
  UNMOCK(loose_circuit_send_next_onion_skin);
}

/**
 * Calling loose_circuit_answer_create_cell() should respond to the OP's
 * CREATE cell successfully (when command_answer_create_cell() is mocked with
 * mock_command_answer_create_cell_success()) and mark the loose circuit for
 * close when unsuccessful (i.e. when command_answer_create_cell() is mocked
 * with mock_command_answer_create_cell_failure()).
 */
static void
test_loose_circuit_answer_create_cell(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = 100;
  channel_t *p_chan = new_fake_channel();
  extend_info_t *entry = NULL;
  create_cell_t create;
  cell_t cell;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(command_answer_create_cell, mock_command_answer_create_cell_success);
  MOCK(circuit_deliver_create_cell, mock_circuit_deliver_create_cell_success);
  MOCK(channel_get_for_extend, mock_channel_get_for_extend_success);

  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);

  memset(&cell, 0, sizeof(cell_t));

  /* Make a create cell. */
  create = make_create_cell(loose_circ->cpath->extend_info,
                            &loose_circ->cpath->handshake_state);
  /* Pack it into the cell_t… */
  tt_int_op(create_cell_format(&cell, &create), OP_GE, 0);

  /* The circuit should not have be marked for close this time. */
  loose_circuit_answer_create_cell(loose_circ, &cell);
  tt_int_op(LOOSE_TO_CIRCUIT(loose_circ)->marked_for_close, OP_EQ, 0);

  /* But it should get marked for close this time. */
  UNMOCK(command_answer_create_cell);
  MOCK(command_answer_create_cell, mock_command_answer_create_cell_failure);
  loose_circuit_answer_create_cell(loose_circ, &cell);
  tt_int_op(LOOSE_TO_CIRCUIT(loose_circ)->marked_for_close, OP_NE, 0);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  free_fake_channel(p_chan);

  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(command_answer_create_cell);
  UNMOCK(circuit_deliver_create_cell);
  UNMOCK(channel_get_for_extend);
}

/**
 * Calling loose_circuit_send_create_cell() should construct a create_cell_t
 * and send it to the first additional hop.
 *
 * When circuit_deliver_create_cell() is mocked to always return failure, the
 * loose circuit should be in state CIRCUIT_STATE_CHAN_WAIT, and the returned
 * result should be -END_CIRC_REASON_RESOURCELIMIT.
 *
 * When circuit_deliver_create_cell() is mocked to always return success, the
 * loose circuit should be in state CIRCUIT_STATE_BUILDING, and the first hop
 * in loose_circ-&gt;cpath should be in state CPATH_STATE_AWAITING_KEYS.
 */
static void
test_loose_circuit_send_create_cell(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = 100;
  channel_t *p_chan = new_fake_channel();
  channel_t *n_chan = new_fake_channel();
  extend_info_t *entry = NULL;
  int result;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(channel_get_for_extend, mock_channel_get_for_extend_success);
  MOCK(circuit_deliver_create_cell, mock_circuit_deliver_create_cell_success);

  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);

  /* Fake the n_chan so that circuit_deliver_create_cell() doesn't break. */
  LOOSE_TO_CIRCUIT(loose_circ)->n_chan = n_chan;

  /* Should fail because the create cell could not be sent, due to being
   * unable to establish a connection. */
  UNMOCK(circuit_deliver_create_cell);
  MOCK(circuit_deliver_create_cell, mock_circuit_deliver_create_cell_failure);
  result = loose_circuit_send_create_cell(loose_circ);
  tt_int_op(result, OP_EQ, -END_CIRC_REASON_RESOURCELIMIT);

  /* Now it should succeed, and set the circuit state and cpath state. */
  UNMOCK(circuit_deliver_create_cell);
  MOCK(circuit_deliver_create_cell, mock_circuit_deliver_create_cell_success);
  result = loose_circuit_send_create_cell(loose_circ);
  tt_int_op(result, OP_EQ, 0);
  tt_int_op(loose_circ->cpath->state, OP_EQ, CPATH_STATE_AWAITING_KEYS);
  tt_int_op(LOOSE_TO_CIRCUIT(loose_circ)->state, OP_EQ,
            CIRCUIT_STATE_BUILDING);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  free_fake_channel(p_chan);
  free_fake_channel(n_chan);
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(channel_get_for_extend);
  UNMOCK(circuit_deliver_create_cell);
}

/**
 * Calling loose_circuit_finish_handshake() when the cpath is in state
 * CPATH_STATE_CLOSED should result in a handshake failure.  After the state
 * changes to CPATH_STATE_AWAITING_KEYS, the handshake should succeed.  If
 * called after all the hops in the cpath are in CPATH_STATE_OPEN, then
 * loose_circuit_finish_handshake() should return -END_CIRC_REASON_TORPROTOCOL.
 */
static void
test_loose_circuit_finish_handshake(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = 100;
  channel_t *p_chan = new_fake_channel();
  extend_info_t *entry = NULL;
  create_cell_t create;
  created_cell_t created;
  cell_t created_cell;
  int result;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(choose_good_middle_server, mock_choose_good_middle_server);
  MOCK(loose_circuit_send_next_onion_skin,
       mock_loose_circuit_send_next_onion_skin_success);

  loose_circ = loose_or_circuit_init(circ_id, p_chan, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);

  loose_circ->build_state->desired_path_len = 2;
  entry = loose_circuit_pick_cpath_entry(loose_circ, entry);
  result = loose_circuit_populate_cpath(loose_circ, entry);
  tt_int_op(result, OP_EQ, 0); /* should be successful */

  create = make_create_cell(loose_circ->cpath->extend_info,
                            &loose_circ->cpath->handshake_state);
  created = make_created_cell(&create);
  memset(&created_cell, 0, sizeof(cell_t));
  tt_int_op(created_cell_format(&created_cell, &created), OP_GE, 0);

  /* The handshake should fail. */
  result = loose_circuit_finish_handshake(loose_circ, &created);
  tt_int_op(result, OP_EQ, -END_CIRC_REASON_TORPROTOCOL);

  /* And this one should succeed, since it's in the right state. */
  loose_circ->cpath->state = CPATH_STATE_AWAITING_KEYS;
  result = loose_circuit_finish_handshake(loose_circ, &created);
  tt_int_op(result, OP_EQ, 0);

  /* Set all hops to CPATH_STATE_OPEN.  The next handshake should fail. */
  loose_circ->cpath->state = CPATH_STATE_OPEN;
  loose_circ->cpath->next->state = CPATH_STATE_OPEN;
  result = loose_circuit_finish_handshake(loose_circ, &created);
  tt_int_op(result, OP_EQ, -END_CIRC_REASON_TORPROTOCOL);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  free_fake_channel(p_chan);

  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(loose_circuit_send_next_onion_skin);
}

/**
 * Calling loose_circuit_process_created_cell() should call
 * loose_circuit_finish_handshake() and complete both successfully.
 *
 * If loose_circuit_process_created_cell() is called a second time for the
 * same circuit, then we should hit the "We got an extended when loose-source
 * routed circuit was already built? Closing." error in
 * loose_circuit_finish_handshake() and return -END_CIRC_REASON_TORPROTOCOL.
 */
static void
test_loose_circuit_process_created_cell(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = 100;
  channel_t *p_chan = new_fake_channel();
  extend_info_t *entry = NULL;
  create_cell_t create;
  created_cell_t created;
  cell_t created_cell;
  int result;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(channel_get_for_extend, mock_channel_get_for_extend_success);
  MOCK(circuit_deliver_create_cell, mock_circuit_deliver_create_cell_success);
  MOCK(loose_circuit_send_next_onion_skin,
       mock_loose_circuit_send_next_onion_skin_success);

  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);
  create = make_create_cell(loose_circ->cpath->extend_info,
                            &loose_circ->cpath->handshake_state);
  created = make_created_cell(&create);

  /* And pack it into the cell_t… */
  memset(&created_cell, 0, sizeof(cell_t));
  tt_int_op(created_cell_format(&created_cell, &created), OP_GE, 0);

  /* The handshake be successful. */
  loose_circ->cpath->state = CPATH_STATE_AWAITING_KEYS;
  result = loose_circuit_process_created_cell(loose_circ, &created);
  tt_int_op(result, OP_EQ, 0);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  free_fake_channel(p_chan);
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(channel_get_for_extend);
  UNMOCK(circuit_deliver_create_cell);
  UNMOCK(loose_circuit_send_next_onion_skin);
}

/**
 * Calling loose_circuit_process_created_cell(), when loose_circ->cpath->state
 * is not CPATH_STATE_AWAITING_KEYS, should return
 * -END_CIRC_REASON_TORPROTOCOL.
 */
static void
test_loose_circuit_process_created_cell_bad_created_cell(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = 100;
  channel_t *p_chan = new_fake_channel();
  extend_info_t *entry = NULL;
  created_cell_t created;
  int result;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(channel_get_for_extend, mock_channel_get_for_extend_success);
  MOCK(circuit_deliver_create_cell, mock_circuit_deliver_create_cell_success);
  MOCK(loose_circuit_send_next_onion_skin,
       mock_loose_circuit_send_next_onion_skin_success);

  memset(&created, 0, sizeof(created_cell_t));
  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);

  /* The handshake should have failed this time, since there's nothing in
   * the cell_t. */
  result = loose_circuit_process_created_cell(loose_circ, &created);
  tt_int_op(result, OP_EQ, -END_CIRC_REASON_TORPROTOCOL);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  free_fake_channel(p_chan);
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(channel_get_for_extend);
  UNMOCK(circuit_deliver_create_cell);
  UNMOCK(loose_circuit_send_next_onion_skin);
}

/**
 * Calling loose_circuit_has_opened() should set the circuit state to
 * CIRCUIT_STATE_OPEN and call loose_note_that_we_have_complete_a_circuit().
 */
static void
test_loose_circuit_has_opened(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = 100;
  channel_t *p_chan = new_fake_channel();
  extend_info_t *entry = NULL;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(channel_get_for_extend, mock_channel_get_for_extend_success);
  MOCK(circuit_deliver_create_cell, mock_circuit_deliver_create_cell_success);

  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);
  tt_int_op(loose_have_completed_a_circuit(), OP_EQ, 0);

  loose_circuit_has_opened(loose_circ);
  tt_int_op(loose_have_completed_a_circuit(), OP_EQ, 1);
  tt_int_op(LOOSE_TO_CIRCUIT(loose_circ)->state, OP_EQ, CIRCUIT_STATE_OPEN);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  free_fake_channel(p_chan);
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(channel_get_for_extend);
  UNMOCK(circuit_deliver_create_cell);
}

/**
 * Calling loose_circuit_extend() when the cpath has already been completely
 * extended to should just call loose_circuit_has_opened() and return 0.
 */
static void
test_loose_circuit_extend_no_cpath_next(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = 100;
  channel_t *p_chan = new_fake_channel();
  extend_info_t *entry = NULL;
  int result;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(channel_get_for_extend, mock_channel_get_for_extend_success);
  MOCK(circuit_deliver_create_cell, mock_circuit_deliver_create_cell_success);

  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);

  result = loose_circuit_extend(loose_circ);
  tt_int_op(result, OP_EQ, 0);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  free_fake_channel(p_chan);
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(channel_get_for_extend);
  UNMOCK(circuit_deliver_create_cell);
}

/**
 * Calling loose_circuit_extend() when the cpath hasn't been completely
 * extended to should call loose_circuit_extend_to_next_hop() as many times as
 * is necessary before returning success.  If called a second time, it should
 * detect that the circuit is already completely constructed, and return
 * success.
 */
static void
test_loose_circuit_extend_multihop(void *arg)
{
  loose_or_circuit_t *loose_circ = NULL;
  extend_info_t *entry = NULL;
  circid_t circ_id = 100;
  channel_t *ch1 = new_fake_channel();
  int result;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(choose_good_middle_server, mock_choose_good_middle_server);
  MOCK(channel_get_for_extend, mock_channel_get_for_extend_success);
  MOCK(circuit_deliver_create_cell, mock_circuit_deliver_create_cell_success);

  memset(&cam, 0, sizeof(cam));
  memset(&cdm, 0, sizeof(cdm));

  tt_assert(ch1);
  ch1->cmux = tor_malloc(1);

  /* Create a loose circuit, set its desired path length to 2, and populate
   * its cpath. */
  loose_circ = loose_or_circuit_init(circ_id, ch1, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);
  loose_circ->build_state->desired_path_len = 2;
  entry = loose_circuit_pick_cpath_entry(loose_circ, NULL);
  tt_assert(entry);
  loose_circuit_populate_cpath(loose_circ, entry);

  /* Send the create cell to the first hop. */
  result = loose_circuit_send_create_cell(loose_circ);
  tt_int_op(result, OP_EQ, 0);

  /* Now extend it. */
  result = loose_circuit_extend(loose_circ);
  tt_int_op(result, OP_EQ, 0);
  result = loose_circuit_extend(loose_circ);
  tt_int_op(result, OP_EQ, 0);
  result = loose_circuit_extend(loose_circ);
  tt_int_op(result, OP_EQ, 0);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  free_fake_channel(ch1);
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(choose_good_middle_server);
  UNMOCK(channel_get_for_extend);
  UNMOCK(circuit_deliver_create_cell);
}

/**
 * Calling loose_circuit_extend_to_next_hop() when the cpath hasn't been
 * completely extended to should DOCDOC
 */
static void
test_loose_circuit_extend_to_next_hop(void *arg)
{
  loose_or_circuit_t *loose_circ = NULL;
  extend_info_t *entry = NULL;
  circid_t circ_id = 100;
  channel_t *ch1 = new_fake_channel();
  int result;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(choose_good_middle_server, mock_choose_good_middle_server);
  MOCK(channel_get_for_extend, mock_channel_get_for_extend_success);
  MOCK(circuit_deliver_create_cell, mock_circuit_deliver_create_cell_success);

  memset(&cam, 0, sizeof(cam));
  memset(&cdm, 0, sizeof(cdm));

  tt_assert(ch1);
  ch1->cmux = tor_malloc(1);

  /* Create a loose circuit, set its desired path length to 2, and populate
   * its cpath. */
  loose_circ = loose_or_circuit_init(circ_id, ch1, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);
  loose_circ->build_state->desired_path_len = 2;
  entry = loose_circuit_pick_cpath_entry(loose_circ, NULL);
  tt_assert(entry);
  loose_circuit_populate_cpath(loose_circ, entry);

  /* Send the create cell to the first hop. */
  result = loose_circuit_send_create_cell(loose_circ);
  tt_int_op(result, OP_EQ, 0);

  /* Fake the path state being open. */
  loose_circ->cpath->state = CPATH_STATE_OPEN;

  /* Now extend it. */
  result = loose_circuit_extend_to_next_hop(loose_circ);
  tt_int_op(result, OP_EQ, 0);
  tt_int_op(LOOSE_TO_CIRCUIT(loose_circ)->marked_for_close, OP_EQ, 0);
  result = loose_circuit_extend_to_next_hop(loose_circ);
  tt_int_op(result, OP_EQ, 0);
  tt_int_op(LOOSE_TO_CIRCUIT(loose_circ)->marked_for_close, OP_EQ, 0);
  result = loose_circuit_extend_to_next_hop(loose_circ);
  tt_int_op(result, OP_EQ, 0);
  tt_int_op(LOOSE_TO_CIRCUIT(loose_circ)->marked_for_close, OP_EQ, 0);
  result = loose_circuit_extend_to_next_hop(loose_circ);
  tt_int_op(result, OP_EQ, 0);
  tt_int_op(LOOSE_TO_CIRCUIT(loose_circ)->marked_for_close, OP_EQ, 0);
  result = loose_circuit_extend_to_next_hop(loose_circ);
  tt_int_op(result, OP_EQ, 0);
  tt_int_op(LOOSE_TO_CIRCUIT(loose_circ)->marked_for_close, OP_EQ, 0);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  free_fake_channel(ch1);
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(choose_good_middle_server);
  UNMOCK(channel_get_for_extend);
  UNMOCK(circuit_deliver_create_cell);
}

/**
 * DOCDOC
 */
static void
test_loose_circuit_process_relay_cell(void *arg)
{
  loose_or_circuit_t *loose_circ = NULL;
  extend_info_t *entry = NULL;
  circid_t circ_id = 100;
  channel_t *ch1 = new_fake_channel();
  crypt_path_t *hop;
  create_cell_t create;
  extend_cell_t extend;
  cell_t relay_cell;
  relay_header_t rh;
  int result;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(choose_good_middle_server, mock_choose_good_middle_server);
  MOCK(channel_get_for_extend, mock_channel_get_for_extend_success);
  MOCK(circuit_deliver_create_cell, mock_circuit_deliver_create_cell_success);
  MOCK(append_cell_to_circuit_queue, mock_append_cell_to_circuit_queue);

  memset(&cam, 0, sizeof(cam));
  memset(&cdm, 0, sizeof(cdm));

  tt_assert(ch1);

  /* Create a loose circuit, set its desired path length to 2, and populate
   * its cpath. */
  loose_circ = loose_circuit_establish_circuit(circ_id, ch1, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);

  /* Send the create cell to the first hop. */
  result = loose_circuit_send_create_cell(loose_circ);
  tt_int_op(result, OP_EQ, 0);

  /* Now extend it. */
  result = loose_circuit_extend(loose_circ);
  tt_int_op(result, OP_EQ, 0);

  /* Make an extend_cell_t containing a create_cell_t to our own first
   * additional hop.  (Whatever, it doesn't matter if we're just testing
   * relaying functionality.) */
  memset(&extend, 0, sizeof(extend_cell_t));
  hop = loose_circ->cpath;
  create = make_create_cell(hop->extend_info, &hop->handshake_state);
  extend.create_cell = create;
  extend.cell_type = RELAY_COMMAND_EXTEND;
  extend.create_cell.cell_type = CELL_CREATE;
  extend.create_cell.handshake_type = ONION_HANDSHAKE_TYPE_NTOR;
  extend.create_cell.handshake_len = NTOR_ONIONSKIN_LEN;
  tor_addr_copy(&extend.orport_ipv4.addr, &hop->extend_info->addr);
  extend.orport_ipv4.port = hop->extend_info->port;
  tor_addr_make_unspec(&extend.orport_ipv6.addr);
  memcpy(extend.node_id, hop->extend_info->identity_digest, DIGEST_LEN);

  uint8_t command = 0;
  uint16_t payload_len = 0;
  uint8_t payload[RELAY_PAYLOAD_SIZE];

  result = extend_cell_format(&command, &payload_len, payload, &extend);
  tt_int_op(result, OP_GE, 0);

  /* Create a relay_cell containing the extend_cell_t as its payload. */
  memset(&relay_cell, 0, sizeof(cell_t));
  relay_cell.command = CELL_RELAY;

  memset(&rh, 0, sizeof(relay_header_t));
  rh.command = command;
  rh.stream_id = 0;
  tt_int_op(payload_len, OP_LE, RELAY_PAYLOAD_SIZE);
  rh.length = payload_len;
  relay_header_pack(relay_cell.payload, &rh);
  memcpy(relay_cell.payload + RELAY_HEADER_SIZE, payload, payload_len);

  relay_cell.command = CELL_RELAY;

  hop->b_digest = crypto_digest_new();
  hop->f_digest = crypto_digest_new();
  hop->b_crypto = crypto_cipher_new(NULL);
  hop->f_crypto = crypto_cipher_new(NULL);

  LOOSE_TO_OR_CIRCUIT(loose_circ)->n_digest = crypto_digest_new();
  LOOSE_TO_OR_CIRCUIT(loose_circ)->p_digest = crypto_digest_new();
  LOOSE_TO_OR_CIRCUIT(loose_circ)->n_crypto = crypto_cipher_new(NULL);
  LOOSE_TO_OR_CIRCUIT(loose_circ)->p_crypto = crypto_cipher_new(NULL);

  /* Recognized incoming relay cell.  This one should fail with
   * -END_CIRC_REASON_TORPROTOCOL in loose_circuit_relay_cell_incoming(), due
   * to loose_circ->cpath->state not being set to CPATH_STATE_OPEN. */
  tt_int_op(hop->state, OP_NE, CPATH_STATE_OPEN);
  result = loose_circuit_process_relay_cell(loose_circ, NULL, &relay_cell,
                                            CELL_DIRECTION_IN, 1);
  tt_int_op(result, OP_EQ, -END_CIRC_REASON_TORPROTOCOL);

  loose_circ->cpath->state = CPATH_STATE_OPEN;
  /* If we pretend the circuit hasn't opened, then an outgoing relay_cell
   * should get stored as loose_circ->p_chan_relay_cell. */
  loose_circ->has_opened = 0;
  result = loose_circuit_process_relay_cell(loose_circ, NULL, &relay_cell,
                                            CELL_DIRECTION_OUT, 1);
  tt_int_op(result, OP_EQ, 0);
  /* Still pretending the circuit hasn't opened, a recognized incoming relay
   * cell should get dropped (which means that "success" is returned) in
   * loose_circuit_process_relay_cell() because we shouldn't be receiving
   * incoming relay cells before the circuit is fully constructed. */
  result = loose_circuit_process_relay_cell(loose_circ, NULL, &relay_cell,
                                            CELL_DIRECTION_IN, 1);
  tt_int_op(result, OP_EQ, 0);
  /* Still pretending the circuit hasn't opened, if we send an additional
   * outgoing relay_cell before the one stored in loose_circ->p_chan_relay_cell
   * has sent, -END_CIRC_REASON_TORPROTOCOL should be returned. */
  result = loose_circuit_process_relay_cell(loose_circ, NULL, &relay_cell,
                                            CELL_DIRECTION_OUT, 1);
  tt_int_op(result, OP_EQ, -END_CIRC_REASON_TORPROTOCOL);
  /* Now, if we pretend the circuit has opened, then
   * loose_circuit_process_relay_cell() should send the previously stored cell
   * outwards. */
  loose_circ->has_opened = 1;
  result = loose_circuit_process_relay_cell(loose_circ, NULL, NULL,
                                            CELL_DIRECTION_OUT, 1);
  tt_int_op(result, OP_EQ, 0);
  /* Same as before, but, if we give the relay cell a stream_id and change the
   * relay command to one of the ones listed in
   * loose_circuit_check_relay_cell_header(), then then the cell should be
   * dropped (which means that "success" is returned). */
  rh.stream_id = 0;
  rh.command = RELAY_COMMAND_RESOLVE;
  relay_header_pack(relay_cell.payload, &rh);
  result = loose_circuit_process_relay_cell(loose_circ, NULL, &relay_cell,
                                            CELL_DIRECTION_OUT, 1);
                                            tt_int_op(result, OP_EQ, 0);
  /* Still pretending that the circuit is open, and reseting the command and
   * stream_id to their original values. The current relay_cell should now be
   * sent. */
  rh.stream_id = 1;
  rh.command = command; /* Reset to the original command value.*/
  relay_header_pack(relay_cell.payload, &rh);
  result = loose_circuit_process_relay_cell(loose_circ, NULL, &relay_cell,
                                            CELL_DIRECTION_OUT, 1);
  tt_int_op(result, OP_EQ, 0);

  /* Unsetting reconized in the relay header on an incoming cell. */
  rh.recognized = 0;
  relay_header_pack(relay_cell.payload, &rh);
  result = loose_circuit_process_relay_cell(loose_circ, NULL, &relay_cell,
                                            CELL_DIRECTION_IN, 1);
  tt_int_op(result, OP_EQ, 0);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  free_fake_channel(ch1);
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(choose_good_middle_server);
  UNMOCK(channel_get_for_extend);
  UNMOCK(circuit_deliver_create_cell);
  UNMOCK(append_cell_to_circuit_queue);
}

/**
 * If the cpath->state of the first additional hop in a loose circuit is
 * CPATH_STATE_CLOSED, then loose_circuit_send_next_onion_skin() should call
 * loose_circuit_send_create_cell(), otherwise, it should call
 * loose_circuit_extend().
 */
static void
test_loose_circuit_send_next_onion_skin(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = 100;
  channel_t *p_chan = new_fake_channel();
  extend_info_t *entry = NULL;
  int result;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(channel_get_for_extend, mock_channel_get_for_extend_success);
  MOCK(circuit_deliver_create_cell, mock_circuit_deliver_create_cell_success);

  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);

  result = loose_circuit_send_next_onion_skin(loose_circ);
  tt_int_op(result, OP_EQ, 0);
  result = loose_circuit_send_next_onion_skin(loose_circ);
  tt_int_op(result, OP_EQ, 0);
  result = loose_circuit_send_next_onion_skin(loose_circ);
  tt_int_op(result, OP_EQ, 0);

 done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  free_fake_channel(p_chan);
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(channel_get_for_extend);
  UNMOCK(circuit_deliver_create_cell);
}

#define TEST_LOOSE(name, flags) \
  { #name, test_loose_##name, (flags), NULL, NULL }

struct testcase_t loose_tests[] = {
  TEST_LOOSE(can_complete_circuits, 0),
  TEST_LOOSE(circuit_init, 0),
  TEST_LOOSE(circuit_casts, 0),
  TEST_LOOSE(circuit_free, 0),
  TEST_LOOSE(circuit_log_path, TT_FORK),
  TEST_LOOSE(circuit_extend_cpath_multihop, TT_FORK),
  TEST_LOOSE(circuit_populate_cpath_multihop, TT_FORK),
  TEST_LOOSE(circuit_populate_cpath_multihop_ntor, TT_FORK),
  TEST_LOOSE(circuit_populate_cpath_multihop_null, TT_FORK),
  TEST_LOOSE(circuit_clear_cpath_null, TT_FORK),
  TEST_LOOSE(circuit_establish_circuit_not_possible, 0),
  TEST_LOOSE(circuit_establish_circuit_unattached, TT_FORK),
  TEST_LOOSE(circuit_establish_circuit_unattached_no_entry, TT_FORK),
  TEST_LOOSE(circuit_establish_circuit_connection_failure, TT_FORK),
  TEST_LOOSE(circuit_establish_circuit_unattached_multihop, TT_FORK),
  TEST_LOOSE(circuit_establish_circuit_attached, TT_FORK),
  TEST_LOOSE(circuit_establish_circuit_attached_multihop, TT_FORK),
  TEST_LOOSE(circuit_pick_cpath_entry, TT_FORK),
  TEST_LOOSE(circuit_pick_cpath_entry_null, TT_FORK),
  TEST_LOOSE(circuit_pick_cpath_entry_chosen, TT_FORK),
  TEST_LOOSE(circuit_handle_first_hop, TT_FORK),
  TEST_LOOSE(circuit_answer_create_cell, TT_FORK),
  TEST_LOOSE(circuit_send_create_cell, TT_FORK),
  TEST_LOOSE(circuit_finish_handshake, TT_FORK),
  TEST_LOOSE(circuit_process_created_cell, TT_FORK),
  TEST_LOOSE(circuit_process_created_cell_bad_created_cell, TT_FORK),
  TEST_LOOSE(circuit_has_opened, TT_FORK),
  TEST_LOOSE(circuit_extend_no_cpath_next, TT_FORK),
  TEST_LOOSE(circuit_extend_multihop, TT_FORK),
  TEST_LOOSE(circuit_extend_to_next_hop, TT_FORK),
  TEST_LOOSE(circuit_process_relay_cell, TT_FORK),
  TEST_LOOSE(circuit_send_next_onion_skin, TT_FORK),
  END_OF_TESTCASES
};
