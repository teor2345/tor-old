/* Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file shared_random.c
 *
 * \brief Functions and data structure needed to accomplish the shared
 * random protocol as defined in proposal #250.
 *
 * \details
 *
 * This file implements the dirauth-only commit-and-reveal protocol specified
 * by proposal #250. The protocol has two phases (sr_phase_t): the commitment
 * phase and the reveal phase (see get_sr_protocol_phase()).
 *
 * During the protocol, directory authorities keep state in memory (using
 * sr_state_t) and in disk (using sr_disk_state_t). The synchronization between
 * these two data structures happens in disk_state_update() and
 * disk_state_parse().
 *
 * Here is a rough protocol outline:
 *
 *      1) In the beginning of the commitment phase, dirauths generate a
 *         commitment/reveal value for the current protocol run (see
 *         new_protocol_run() and sr_generate_our_commit()).
 *
 *      2) During voting, dirauths publish their commits in their votes
 *         depending on the current phase.  Dirauths also include the two
 *         latest shared random values (SRV) in their votes.
 *         (see sr_get_string_for_vote())
 *
 *      3) Upon receiving a commit from a vote, authorities parse it, verify
 *         it, and attempt to save any new commitment or reveal information in
 *         their state file (see extract_shared_random_commits() and
 *         sr_handle_received_commits()).  They also parse SRVs from votes to
 *         decide which SRV should be included in the final consensus (see
 *         extract_shared_random_srvs()).
 *
 *      3) After voting is done, we count the SRVs we extracted from the votes,
 *         to find the one voted by the majority of dirauths which should be
 *         included in the final consensus (see get_majority_srv_from_votes()).
 *         If an appropriate SRV is found, it is embedded in the consensus (see
 *         sr_get_string_for_consensus()).
 *
 *      4) At the end of the reveal phase, dirauths compute a fresh SRV for the
 *         day using the active commits (see sr_compute_srv()).  This new SRV
 *         is embedded in the votes as described above.
 *
 * Some more notes:
 *
 * - To support rebooting authorities and to avoid double voting, each dirauth
 *   saves the current state of the protocol on disk so that it can resume
 *   normally in case of reboot. The disk state (sr_disk_state_t) is managed by
 *   shared_random_state.c:state_query() and we go to extra lengths to ensure
 *   that the state is flushed on disk everytime we receive any useful
 *   information like commits or SRVs.
 *
 * - When we receive a commit from a vote, we examine it to see if it's useful
 *   to us and whether it's appropriate to receive it according to the current
 *   phase of the protocol (see should_keep_commit()). If the commit is useful
 *   to us, we save it in our disk state using save_commit_to_state().  When we
 *   receive the reveal information corresponding to a commitment, we verify
 *   that they indeed match using verify_commit_and_reveal().
 *
 * - We treat consensuses as the ground truth, so everytime we generate a new
 *   consensus we update our SR state accordingly even if our local view was
 *   different (see sr_act_post_consensus()).
 *
 * - After a consensus has been composed, the SR protocol state gets prepared
 *   for the next voting session using sr_state_update(). That function takes
 *   care of housekeeping and also rotates the SRVs and commits in case a new
 *   protocol run is coming up. We also call sr_state_update() on bootup (in
 *   sr_state_init()), to prepare the state for the very first voting session.
 *
 * Terminology:
 *
 * - "Commitment" is the commitment value of the commit-and-reveal protocol.
 *
 * - "Reveal" is the reveal value of the commit-and-reveal protocol.
 *
 * - "Commit" is a struct (sr_commit_t) that contains a commitment value and
 *    optionally also a corresponding reveal value.
 *
 * - "SRV" is the Shared Random Value that gets generated as the result of the
 *   commit-and-reveal protocol.
 **/

#define SHARED_RANDOM_PRIVATE

#include "or.h"
#include "shared_random.h"
#include "config.h"
#include "confparse.h"
#include "dirvote.h"
#include "networkstatus.h"
#include "routerkeys.h"
#include "router.h"
#include "routerlist.h"
#include "shared_random_state.h"

/* String prefix of shared random values in votes/consensuses. */
static const char *previous_srv_str = "shared-rand-previous-value";
static const char *current_srv_str = "shared-rand-current-value";
static const char *commit_ns_str = "shared-rand-commit";

/* Return a heap allocated copy of the SRV <b>orig</b>. */
STATIC sr_srv_t *
srv_dup(const sr_srv_t *orig)
{
  sr_srv_t *dup = NULL;

  if (!orig) {
    return NULL;
  }

  dup = tor_malloc_zero(sizeof(sr_srv_t));
  dup->num_reveals = orig->num_reveals;
  memcpy(dup->value, orig->value, sizeof(dup->value));
  return dup;
}

/* Allocate a new commit object and initializing it with <b>identity</b>
 * that MUST be provided. The digest algorithm is set to the default one
 * that is supported. The rest is uninitialized. This never returns NULL. */
static sr_commit_t *
commit_new(const char *rsa_identity_fpr)
{
  sr_commit_t *commit;

  tor_assert(rsa_identity_fpr);

  commit = tor_malloc_zero(sizeof(*commit));
  commit->alg = SR_DIGEST_ALG;
  strlcpy(commit->rsa_identity_fpr, rsa_identity_fpr,
          sizeof(commit->rsa_identity_fpr));
  return commit;
}

/* Issue a log message describing <b>commit</b>. */
static void
commit_log(const sr_commit_t *commit)
{
  tor_assert(commit);

  log_debug(LD_DIR, "SR: Commit from %s", commit->rsa_identity_fpr);

  if (commit->commit_ts >= 0) {
    log_debug(LD_DIR, "SR: Commit: [TS: %ld] [Encoded: %s]",
              commit->commit_ts, commit->encoded_commit);
  }

  if (commit->reveal_ts >= 0) {
    log_debug(LD_DIR, "SR: Reveal: [TS: %ld] [Encoded: %s]",
              commit->reveal_ts, safe_str(commit->encoded_reveal));
  } else {
    log_debug(LD_DIR, "SR: Reveal: UNKNOWN");
  }
}

/* Make sure that the commitment and reveal information in <b>commit</b>
 * match. If they match return 0, return -1 otherwise. This function MUST be
 * used everytime we receive a new reveal value. */
STATIC int
verify_commit_and_reveal(const sr_commit_t *commit)
{
  tor_assert(commit);

  log_debug(LD_DIR, "SR: Validating commit from authority %s",
            commit->rsa_identity_fpr);

  /* Check that the timestamps match. */
  if (commit->commit_ts != commit->reveal_ts) {
    log_warn(LD_BUG, "SR: Commit timestamp %ld doesn't match reveal "
                     "timestamp %ld", commit->commit_ts, commit->reveal_ts);
    goto invalid;
  }

  /* Verify that the hashed_reveal received in the COMMIT message, matches
   * the reveal we just received. */
  {
    /* We first hash the reveal we just received. */
    char received_hashed_reveal[sizeof(commit->hashed_reveal)];

    /* Only sha3-256 is supported. */
    if (commit->alg != SR_DIGEST_ALG) {
      goto invalid;
    }

    /* Use the invariant length since the encoded reveal variable has an
     * extra byte for the NUL terminated byte. */
    if (crypto_digest256(received_hashed_reveal, commit->encoded_reveal,
                         SR_REVEAL_BASE64_LEN, commit->alg)) {
      /* Unable to digest the reveal blob, this is unlikely. */
      goto invalid;
    }

    /* Now compare that with the hashed_reveal we received in COMMIT. */
    if (fast_memneq(received_hashed_reveal, commit->hashed_reveal,
                    sizeof(received_hashed_reveal))) {
      log_warn(LD_BUG, "SR: Received reveal value from authority %s "
                       "does't match the commit value.",
               commit->rsa_identity_fpr);
      goto invalid;
    }
  }

  return 0;
 invalid:
  return -1;
}

/* Return true iff the commit contains an encoded reveal value. */
STATIC int
commit_has_reveal_value(const sr_commit_t *commit)
{
  return !tor_mem_is_zero(commit->encoded_reveal,
                          sizeof(commit->encoded_reveal));
}

/* Parse the encoded commit. The format is:
 *    base64-encode( TIMESTAMP || H(REVEAL) )
 *
 * If successfully decoded and parsed, commit is updated and 0 is returned.
 * On error, return -1. */
STATIC int
commit_decode(const char *encoded, sr_commit_t *commit)
{
  int decoded_len = 0;
  size_t offset = 0;
  /* XXX: Needs two extra bytes for the base64 decode calculation matches
   * the binary length once decoded. #17868. */
  char b64_decoded[SR_COMMIT_LEN + 2];

  tor_assert(encoded);
  tor_assert(commit);

  if (strlen(encoded) > SR_COMMIT_BASE64_LEN) {
    /* This means that if we base64 decode successfully the reveiced commit,
     * we'll end up with a bigger decoded commit thus unusable. */
    goto error;
  }

  /* Decode our encoded commit. Let's be careful here since _encoded_ is
   * coming from the network in a dirauth vote so we expect nothing more
   * than the base64 encoded length of a commit. */
  decoded_len = base64_decode(b64_decoded, sizeof(b64_decoded),
                              encoded, strlen(encoded));
  if (decoded_len < 0) {
    log_warn(LD_BUG, "SR: Commit from authority %s can't be decoded.",
             commit->rsa_identity_fpr);
    goto error;
  }

  if (decoded_len < SR_COMMIT_LEN) {
    log_warn(LD_BUG, "SR: Commit from authority %s decoded length is "
                     "too small (%d vs %d).",
             commit->rsa_identity_fpr, decoded_len, SR_COMMIT_LEN);
    goto error;
  }

  /* First is the timestamp (8 bytes). */
  commit->commit_ts = (time_t) tor_ntohll(get_uint64(b64_decoded));
  offset += sizeof(uint64_t);
  /* Next is hashed reveal. */
  memcpy(commit->hashed_reveal, b64_decoded + offset,
         sizeof(commit->hashed_reveal));
  /* Copy the base64 blob to the commit. Useful for voting. */
  strncpy(commit->encoded_commit, encoded, sizeof(commit->encoded_commit));

  return 0;

 error:
  return -1;
}

/* Parse the b64 blob at <b>encoded</b> containing reveal information and
 * store the information in-place in <b>commit</b>. Return 0 on success else
 * a negative value. */
STATIC int
reveal_decode(const char *encoded, sr_commit_t *commit)
{
  int decoded_len = 0;
  /* XXX: Needs two extra bytes for the base64 decode calculation matches
   * the binary length once decoded. #17868. */
  char b64_decoded[SR_REVEAL_LEN + 2];

  tor_assert(encoded);
  tor_assert(commit);

  if (strlen(encoded) > SR_REVEAL_BASE64_LEN) {
    /* This means that if we base64 decode successfully the received reveal
     * value, we'll end up with a bigger decoded value thus unusable. */
    goto error;
  }

  /* Decode our encoded reveal. Let's be careful here since _encoded_ is
   * coming from the network in a dirauth vote so we expect nothing more
   * than the base64 encoded length of our reveal. */
  decoded_len = base64_decode(b64_decoded, sizeof(b64_decoded),
                              encoded, strlen(encoded));
  if (decoded_len < 0) {
    log_warn(LD_BUG, "SR: Reveal from authority %s can't be decoded.",
             commit->rsa_identity_fpr);
    goto error;
  }

  if (decoded_len < SR_REVEAL_LEN) {
    log_warn(LD_BUG, "SR: Reveal from authority %s decoded length is "
             "too small.",
             commit->rsa_identity_fpr);
    goto error;
  }

  commit->reveal_ts = (time_t) tor_ntohll(get_uint64(b64_decoded));
  /* Copy the last part, the random value. */
  memcpy(commit->random_number, b64_decoded + 8,
         sizeof(commit->random_number));
  /* Also copy the whole message to use during verification */
  strncpy(commit->encoded_reveal, encoded, sizeof(commit->encoded_reveal));

  return 0;

 error:
  return -1;
}

/* Encode a reveal element using a given commit object to dst which is a
 * buffer large enough to put the base64-encoded reveal construction. The
 * format is as follow:
 *     REVEAL = base64-encode( TIMESTAMP || H(RN) )
 * Return base64 encoded length on success else a negative value.
 */
STATIC int
reveal_encode(const sr_commit_t *commit, char *dst, size_t len)
{
  int ret;
  size_t offset = 0;
  char buf[SR_REVEAL_LEN] = {0};

  tor_assert(commit);
  tor_assert(dst);

  set_uint64(buf, tor_htonll((uint64_t) commit->reveal_ts));
  offset += 8;
  memcpy(buf + offset, commit->random_number,
         sizeof(commit->random_number));

  /* Let's clean the buffer and then b64 encode it. */
  memset(dst, 0, len);
  ret = base64_encode(dst, len, buf, sizeof(buf), 0);
  /* Wipe this buffer because it contains our random value. */
  memwipe(buf, 0, sizeof(buf));
  return ret;
}

/* Encode the given commit object to dst which is a buffer large enough to
 * put the base64-encoded commit. The format is as follow:
 *     COMMIT = base64-encode( TIMESTAMP || H(H(RN)) )
 * Return base64 encoded length on success else a negative value.
 */
STATIC int
commit_encode(const sr_commit_t *commit, char *dst, size_t len)
{
  size_t offset = 0;
  char buf[SR_COMMIT_LEN] = {0};

  tor_assert(commit);
  tor_assert(dst);

  /* First is the timestamp (8 bytes). */
  set_uint64(buf, tor_htonll((uint64_t) commit->commit_ts));
  offset += sizeof(uint64_t);
  /* and then the hashed reveal. */
  memcpy(buf + offset, commit->hashed_reveal,
         sizeof(commit->hashed_reveal));

  /* Clean the buffer and then b64 encode it. */
  memset(dst, 0, len);
  return base64_encode(dst, len, buf, sizeof(buf), 0);
}

/* Cleanup both our global state and disk state. */
static void
sr_cleanup(void)
{
  sr_state_free();
}

/* Using <b>commit</b>, return a newly allocated string containing the commit
 * information that should be used during SRV calculation. It's the caller
 * responsibility to free the memory. Return NULL if this is not a commit to be
 * used for SRV calculation. */
static char *
get_srv_element_from_commit(const sr_commit_t *commit)
{
  char *element;
  tor_assert(commit);

  if (!commit_has_reveal_value(commit)) {
    return NULL;
  }

  tor_asprintf(&element, "%s%s", commit->rsa_identity_fpr,
               commit->encoded_reveal);
  return element;
}

/* Return a srv object that is built with the construction:
 *    SRV = SHA3-256("shared-random" | INT_8(reveal_num) |
 *                   INT_8(version) | HASHED_REVEALS | previous_SRV)
 * This function cannot fail. */
static sr_srv_t *
generate_srv(const char *hashed_reveals, uint8_t reveal_num,
             const sr_srv_t *previous_srv)
{
  char msg[DIGEST256_LEN + SR_SRV_MSG_LEN] = {0};
  size_t offset = 0;
  sr_srv_t *srv;

  tor_assert(hashed_reveals);

  /* Add the invariant token. */
  memcpy(msg, SR_SRV_TOKEN, SR_SRV_TOKEN_LEN);
  offset += SR_SRV_TOKEN_LEN;
  set_uint8(msg + offset, reveal_num);
  offset += 1;
  set_uint8(msg + offset, SR_PROTO_VERSION);
  offset += 1;
  memcpy(msg + offset, hashed_reveals, DIGEST256_LEN);
  offset += DIGEST256_LEN;
  if (previous_srv != NULL) {
    memcpy(msg + offset, previous_srv->value, sizeof(previous_srv->value));
  }

  /* Ok we have our message and key for the HMAC computation, allocate our
   * srv object and do the last step. */
  srv = tor_malloc_zero(sizeof(*srv));
  crypto_digest256((char *) srv->value, msg, sizeof(msg), SR_DIGEST_ALG);
  srv->num_reveals = reveal_num;

  {
    /* Debugging. */
    char srv_hash_encoded[SR_SRV_VALUE_BASE64_LEN + 1];
    sr_srv_encode(srv_hash_encoded, srv);
    log_debug(LD_DIR, "SR: Generated SRV: %s", srv_hash_encoded);
  }
  return srv;
}

/* Compare reveal values and return the result. This should exclusively be used
 * by smartlist_sort(). */
static int
compare_reveal_(const void **_a, const void **_b)
{
  const sr_commit_t *a = *_a, *b = *_b;
  return fast_memcmp(a->hashed_reveal, b->hashed_reveal,
                     sizeof(a->hashed_reveal));
}

/* Given <b>commit</b> give the line that we should place in our votes.
 * It's the responsibility of the caller to free the string. */
static char *
get_vote_line_from_commit(const sr_commit_t *commit)
{
  char *vote_line = NULL;
  sr_phase_t current_phase = sr_state_get_phase();

  switch (current_phase) {
  case SR_PHASE_COMMIT:
    tor_asprintf(&vote_line, "%s %s %s %s\n",
                 commit_ns_str,
                 crypto_digest_algorithm_get_name(commit->alg),
                 commit->rsa_identity_fpr,
                 commit->encoded_commit);
    break;
  case SR_PHASE_REVEAL:
  {
    /* Send a reveal value for this commit if we have one. */
    const char *reveal_str = commit->encoded_reveal;
    if (tor_mem_is_zero(commit->encoded_reveal,
                        sizeof(commit->encoded_reveal))) {
      reveal_str = "";
    }
    tor_asprintf(&vote_line, "%s %s %s %s %s\n",
                 commit_ns_str,
                 crypto_digest_algorithm_get_name(commit->alg),
                 commit->rsa_identity_fpr,
                 commit->encoded_commit, reveal_str);
    break;
  }
  default:
    tor_assert(0);
  }

  log_debug(LD_DIR, "SR: Commit vote line: %s", vote_line);
  return vote_line;
}

/* Return a heap allocated string that contains the given <b>srv</b> string
 * representation formatted for a networkstatus document using the
 * <b>key</b> as the start of the line. This doesn't return NULL. */
static char *
srv_to_ns_string(const sr_srv_t *srv, const char *key)
{
  char *srv_str;
  char srv_hash_encoded[SR_SRV_VALUE_BASE64_LEN + 1];
  tor_assert(srv);
  tor_assert(key);

  sr_srv_encode(srv_hash_encoded, srv);
  tor_asprintf(&srv_str, "%s %d %s\n", key,
               srv->num_reveals, srv_hash_encoded);
  log_debug(LD_DIR, "SR: Consensus SRV line: %s", srv_str);
  return srv_str;
}

/* Given the previous SRV and the current SRV, return a heap allocated
 * string with their data that could be put in a vote or a consensus. Caller
 * must free the returned string.  Return NULL if no SRVs were provided. */
static char *
get_ns_str_from_sr_values(const sr_srv_t *prev_srv, const sr_srv_t *cur_srv)
{
  smartlist_t *chunks = NULL;
  char *srv_str;

  if (!prev_srv && !cur_srv) {
    return NULL;
  }

  chunks = smartlist_new();

  if (prev_srv) {
    char *srv_line = srv_to_ns_string(prev_srv, previous_srv_str);
    smartlist_add(chunks, srv_line);
  }

  if (cur_srv) {
    char *srv_line = srv_to_ns_string(cur_srv, current_srv_str);
    smartlist_add(chunks, srv_line);
  }

  /* Join the line(s) here in one string to return. */
  srv_str = smartlist_join_strings(chunks, "", 0, NULL);
  SMARTLIST_FOREACH(chunks, char *, s, tor_free(s));
  smartlist_free(chunks);

  return srv_str;
}

/* Return 1 iff the two commits have the same commitment values. This
 * function does not care about reveal values. */
STATIC int
commitments_are_the_same(const sr_commit_t *commit_one,
                         const sr_commit_t *commit_two)
{
  tor_assert(commit_one);
  tor_assert(commit_two);

  if (strcmp(commit_one->encoded_commit, commit_two->encoded_commit)) {
    return 0;
  }
  return 1;
}

/* We just received a commit from the vote of authority with
 * <b>identity_digest</b>. Return 1 if this commit is authorititative that
 * is, it belongs to the authority that voted it. Else return 0 if not. */
STATIC int
commit_is_authoritative(const sr_commit_t *commit,
                        const char *voter_key)
{
  tor_assert(commit);
  tor_assert(voter_key);

  return !strcmp(commit->rsa_identity_fpr, voter_key);
}

/* Decide if the newly received <b>commit</b> should be kept depending on the
 * current phase and state of the protocol. Return 1 if the commit should be
 * added to our state or 0 if not. */
STATIC int
should_keep_commit(const sr_commit_t *commit, const char *voter_key)
{
  sr_commit_t *saved_commit;

  tor_assert(commit);
  tor_assert(voter_key);

  log_debug(LD_DIR, "SR: Inspecting commit from %s (voter: %s)?",
            commit->rsa_identity_fpr, voter_key);

  /* For a commit to be considered, it needs to be authoritative (it should
   * be the voter's own commit). */
  if (!commit_is_authoritative(commit, voter_key)) {
    log_debug(LD_DIR, "SR: Ignoring non-authoritative commit.");
    goto ignore;
  }

  /* Check if the authority that voted for <b>commit</b> has already posted
   * a commit before. */
  saved_commit = sr_state_get_commit(commit->rsa_identity_fpr);

  switch (sr_state_get_phase()) {
  case SR_PHASE_COMMIT:
    /* Already having a commit for an authority so ignore this one. */
    if (saved_commit) {
      log_debug(LD_DIR, "SR: Ignoring known commit during COMMIT phase.");
      goto ignore;
    }

    /* A commit with a reveal value during commitment phase is very wrong. */
    if (commit_has_reveal_value(commit)) {
      log_warn(LD_DIR, "SR: Commit from authority %s has a reveal value "
                       "during COMMIT phase. (voter: %s)",
               commit->rsa_identity_fpr, voter_key);
      goto ignore;
    }
    break;
  case SR_PHASE_REVEAL:
    /* We are now in reveal phase. We keep a commit if and only if:
     *
     * - We have already seen a commit by this auth, AND
     * - the saved commit has the same commitment value as this one, AND
     * - the saved commit has no reveal information, AND
     * - this commit does have reveal information, AND
     * - the reveal & commit information are matching.
     *
     * If all the above are true, then we are interested in this new commit
     * for its reveal information. */

    if (!saved_commit) {
      log_debug(LD_DIR, "SR: Ignoring commit first seen in reveal phase.");
      goto ignore;
    }

    if (!commitments_are_the_same(commit, saved_commit)) {
      log_warn(LD_DIR, "SR: Commit from authority %s is different from "
                       "previous commit in our state (voter: %s)",
               commit->rsa_identity_fpr, voter_key);
      goto ignore;
    }

    if (commit_has_reveal_value(saved_commit)) {
      log_debug(LD_DIR, "SR: Ignoring commit with known reveal info.");
      goto ignore;
    }

    if (!commit_has_reveal_value(commit)) {
      log_debug(LD_DIR, "SR: Ignoring commit without reveal value.");
      goto ignore;
    }

    if (verify_commit_and_reveal(commit) < 0) {
      log_warn(LD_BUG, "SR: Commit from authority %s has an invalid "
                       "reveal value. (voter: %s)",
               commit->rsa_identity_fpr, voter_key);
      goto ignore;
    }
    break;
  default:
    tor_assert(0);
  }

  return 1;

 ignore:
  return 0;
}

/* We are in reveal phase and we found <b>commit</b> in a vote that contains
 * reveal values that we could use. Update the commit we have in our state. */
STATIC void
save_commit_during_reveal_phase(const sr_commit_t *commit)
{
  sr_commit_t *saved_commit;

  tor_assert(commit);

  /* Get the commit from our state. */
  saved_commit = sr_state_get_commit(commit->rsa_identity_fpr);
  tor_assert(saved_commit);
  /* Safety net. They can not be different commitments at this point. */
  int same_commits = commitments_are_the_same(commit, saved_commit);
  tor_assert(same_commits);

  /* Copy reveal information to our saved commit. */
  sr_state_copy_reveal_info(saved_commit, commit);
}

/* Save <b>commit</b> to our persistent state. Depending on the current phase,
 * different actions are taken. Steals reference of <b>commit</b>. */
STATIC void
save_commit_to_state(sr_commit_t *commit)
{
  sr_phase_t phase = sr_state_get_phase();

  switch (phase) {
  case SR_PHASE_COMMIT:
    /* During commit phase, just save any new authoritative commit */
    sr_state_add_commit(commit);
    break;
  case SR_PHASE_REVEAL:
    save_commit_during_reveal_phase(commit);
    sr_commit_free(commit);
    break;
  default:
    tor_assert(0);
  }
}

/* Return the number of required participants of the SR protocol. This is based
 * on a consensus params. */
static int
get_n_voters_for_srv_agreement(void)
{
  int num_dirauths = get_n_authorities(V3_DIRINFO);
  /* If the params is not found, default value should always be the maximum
   * number of trusted authorities. Let's not take any chances. */
  return networkstatus_get_param(NULL, "AuthDirNumSRVAgreements",
                                 num_dirauths, 1, num_dirauths);
}

/* Return 1 if we should we keep an SRV voted by <b>n_agreements</b> auths.
 * Return 0 if we should ignore it. */
static int
should_keep_srv(int n_agreements)
{
  /* Check if the most popular SRV has reached majority. */
  int n_voters = get_n_authorities(V3_DIRINFO);
  int votes_required_for_majority = (n_voters / 2) + 1;

  /* We need at the very least majority to keep a value. */
  if (n_agreements < votes_required_for_majority) {
    log_notice(LD_DIR, "SR: SRV didn't reach majority [%d/%d]!",
               n_agreements, votes_required_for_majority);
    return 0;
  }

  /* When we just computed a new SRV, we need to have super majority in order
   * to keep it. */
  if (sr_state_srv_is_fresh()) {
    /* Check if we have super majority for this new SRV value. */
    int num_required_agreements = get_n_voters_for_srv_agreement();

    if (n_agreements < num_required_agreements) {
      log_notice(LD_DIR, "SR: New SRV didn't reach agreement [%d/%d]!",
                 n_agreements, num_required_agreements);
      return 0;
    }
  }

  return 1;
}

/** Helper: compare two DIGEST256_LEN digests. */
static int
compare_srvs_(const void **_a, const void **_b)
{
  const sr_srv_t *a = *_a, *b = *_b;
  return tor_memcmp(a->value, b->value, sizeof(a->value));
}

/** Return the most frequent member of the sorted list of DIGEST256_LEN
 * digests in <b>sl</b> with the count of that most frequent element. */
static sr_srv_t *
smartlist_get_most_frequent_srv(smartlist_t *sl, int *count_out)
{
  return smartlist_get_most_frequent_(sl, compare_srvs_, count_out);
}

/* Using a list of <b>votes</b>, return the SRV object from them that has been
 * voted by the majority of dirauths. If <b>current</b> is set, we look for the
 * current SRV value else the previous one. NULL is returned if no appropriate
 * value could be found. */
STATIC sr_srv_t *
get_majority_srv_from_votes(const smartlist_t *votes, unsigned int current)
{
  int count = 0;
  sr_srv_t *most_frequent_srv = NULL;
  sr_srv_t *the_srv = NULL;
  smartlist_t *srv_list;

  tor_assert(votes);

  srv_list = smartlist_new();

  /* Walk over votes and register any SRVs found. */
  SMARTLIST_FOREACH_BEGIN(votes, networkstatus_t *, v) {
    sr_srv_t *srv_tmp = NULL;

    if (!v->sr_info.participate) {
      /* Ignore vote that do not participate. */
      continue;
    }
    /* Do we want previous or current SRV? */
    srv_tmp = current ? v->sr_info.current_srv : v->sr_info.previous_srv;
    if (!srv_tmp) {
      continue;
    }

    smartlist_add(srv_list, srv_tmp);
  } SMARTLIST_FOREACH_END(v);

  most_frequent_srv = smartlist_get_most_frequent_srv(srv_list, &count);
  if (!most_frequent_srv) {
    goto end;
  }

  /* Was this SRV voted by enough auths for us to keep it? */
  if (!should_keep_srv(count)) {
    goto end;
  }

  /* We found an SRV that we can use! Habemus SRV! */
  the_srv = most_frequent_srv;

  {
    /* Debugging */
    char encoded[SR_SRV_VALUE_BASE64_LEN + 1];
    sr_srv_encode(encoded, the_srv);
    log_debug(LD_DIR, "SR: Chosen SRV by majority: %s (%d votes)", encoded,
              count);
  }

 end:
  /* We do not free any sr_srv_t values, we don't have the ownership. */
  smartlist_free(srv_list);
  return the_srv;
}

/* Encode the given shared random value and put it in dst. Destination
 * buffer must be at least SR_SRV_VALUE_BASE64_LEN plus the NULL byte. */
void
sr_srv_encode(char *dst, const sr_srv_t *srv)
{
  int ret;
  /* Extra byte for the NULL terminated char. */
  char buf[SR_SRV_VALUE_BASE64_LEN + 1];

  tor_assert(dst);
  tor_assert(srv);

  ret = base64_encode(buf, sizeof(buf), (const char *) srv->value,
                      sizeof(srv->value), 0);
  /* Always expect the full length without the NULL byte. */
  tor_assert(ret == (sizeof(buf) - 1));
  strncpy(dst, buf, sizeof(buf));
}

/* Free a commit object. */
void
sr_commit_free(sr_commit_t *commit)
{
  if (commit == NULL) {
    return;
  }
  /* Make sure we do not leave OUR random number in memory. */
  memwipe(commit->random_number, 0, sizeof(commit->random_number));
  tor_free(commit);
}

/* Generate the commitment/reveal value for the protocol run starting at
 * <b>timestamp</b>. <b>my_rsa_cert</b> is our authority RSA certificate. */
sr_commit_t *
sr_generate_our_commit(time_t timestamp, const authority_cert_t *my_rsa_cert)
{
  sr_commit_t *commit = NULL;
  char fingerprint[FINGERPRINT_LEN+1];

  tor_assert(my_rsa_cert);

  /* Get our RSA identity fingerprint */
  if (crypto_pk_get_fingerprint(my_rsa_cert->identity_key,
                                fingerprint, 0) < 0) {
    goto error;
  }

  /* New commit with our identity key. */
  commit = commit_new(fingerprint);

  /* Generate the reveal random value */
  crypto_strongest_rand(commit->random_number,
                        sizeof(commit->random_number));
  commit->commit_ts = commit->reveal_ts = timestamp;

  /* Now get the base64 blob that corresponds to our reveal */
  if (reveal_encode(commit, commit->encoded_reveal,
                    sizeof(commit->encoded_reveal)) < 0) {
    log_err(LD_DIR, "SR: Unable to encode our reveal value!");
    goto error;
  }

  /* Now let's create the commitment */
  tor_assert(commit->alg == SR_DIGEST_ALG);
  /* The invariant length is used here since the encoded reveal variable
   * has an extra byte added for the NULL terminated byte. */
  if (crypto_digest256(commit->hashed_reveal, commit->encoded_reveal,
                       SR_REVEAL_BASE64_LEN, commit->alg)) {
    goto error;
  }

  /* Now get the base64 blob that corresponds to our commit. */
  if (commit_encode(commit, commit->encoded_commit,
                    sizeof(commit->encoded_commit)) < 0) {
    log_err(LD_DIR, "SR: Unable to encode our commit value!");
    goto error;
  }

  log_debug(LD_DIR, "SR: Generated our commitment:");
  commit_log(commit);
  return commit;

 error:
  sr_commit_free(commit);
  return NULL;
}

/* Compute the shared random value based on the active commits in our state. */
void
sr_compute_srv(void)
{
  size_t reveal_num = 0;
  char *reveals = NULL;
  smartlist_t *chunks, *commits;
  digestmap_t *state_commits;

  /* Computing a shared random value in the commit phase is very wrong. This
   * should only happen at the very end of the reveal phase when a new
   * protocol run is about to start. */
  tor_assert(sr_state_get_phase() == SR_PHASE_REVEAL);
  state_commits = sr_state_get_commits();

  commits = smartlist_new();
  chunks = smartlist_new();

  /* We must make a list of commit ordered by authority fingerprint in
   * ascending order as specified by proposal 250. */
  DIGESTMAP_FOREACH(state_commits, key, sr_commit_t *, c) {
    smartlist_add(commits, c);
  } DIGESTMAP_FOREACH_END;
  smartlist_sort(commits, compare_reveal_);

  /* Now for each commit for that sorted list in ascending order, we'll
   * build the element for each authority that needs to go into the srv
   * computation. */
  SMARTLIST_FOREACH_BEGIN(commits, const sr_commit_t *, c) {
    char *element = get_srv_element_from_commit(c);
    if (element) {
      smartlist_add(chunks, element);
      reveal_num++;
    }
  } SMARTLIST_FOREACH_END(c);
  smartlist_free(commits);

  {
    /* Join all reveal values into one giant string that we'll hash so we
     * can generated our shared random value. */
    sr_srv_t *current_srv;
    char hashed_reveals[DIGEST256_LEN];
    reveals = smartlist_join_strings(chunks, "", 0, NULL);
    SMARTLIST_FOREACH(chunks, char *, s, tor_free(s));
    smartlist_free(chunks);
    if (crypto_digest256(hashed_reveals, reveals, strlen(reveals),
                         SR_DIGEST_ALG)) {
      goto end;
    }
    tor_assert(reveal_num < UINT8_MAX);
    current_srv = generate_srv(hashed_reveals, (uint8_t) reveal_num,
                               sr_state_get_previous_srv());
    sr_state_set_current_srv(current_srv);
    /* We have a fresh SRV, flag our state. */
    sr_state_set_fresh_srv();
  }

 end:
  tor_free(reveals);
}

/* Parse a list of arguments from a SRV value either from a vote, consensus
 * or from our disk state and return a newly allocated srv object. NULL is
 * returned on error.
 *
 * The arguments' order:
 *    num_reveals, value
 */
sr_srv_t *
sr_parse_srv(const smartlist_t *args)
{
  char *value;
  int num_reveals, ok, ret;
  sr_srv_t *srv = NULL;

  tor_assert(args);

  if (smartlist_len(args) < 2) {
    goto end;
  }

  /* First argument is the number of reveal values */
  num_reveals = tor_parse_long(smartlist_get(args, 0),
                               10, 0, INT32_MAX, &ok, NULL);
  if (!ok) {
    goto end;
  }
  /* Second and last argument is the shared random value it self. */
  value = smartlist_get(args, 1);
  if (strlen(value) != SR_SRV_VALUE_BASE64_LEN) {
    goto end;
  }

  srv = tor_malloc_zero(sizeof(*srv));
  srv->num_reveals = num_reveals;
  /* We substract one byte from the srclen because the function ignores the
   * '=' character in the given buffer. This is broken but it's a documented
   * behavior of the implementation. */
  ret = base64_decode((char *) srv->value, sizeof(srv->value), value,
                      SR_SRV_VALUE_BASE64_LEN - 1);
  if (ret != sizeof(srv->value)) {
    tor_free(srv);
    srv = NULL;
    goto end;
  }
 end:
  return srv;
}

/* Parse a commit from a vote or from our disk state and return a newly
 * allocated commit object. NULL is returned on error.
 *
 * The commit's data is in <b>args</b> and the order matters very much:
 *  algname, RSA fingerprint, commit value[, reveal value]
 */
sr_commit_t *
sr_parse_commit(const smartlist_t *args)
{
  char *value;
  digest_algorithm_t alg;
  const char *rsa_identity_fpr;
  sr_commit_t *commit = NULL;

  if (smartlist_len(args) < 3) {
    goto error;
  }

  /* First argument is the algorithm. */
  value = smartlist_get(args, 0);
  alg = crypto_digest_algorithm_parse_name(value);
  if (alg != SR_DIGEST_ALG) {
    log_warn(LD_BUG, "SR: Commit algorithm %s is not recognized.",
             escaped(value));
    goto error;
  }

  /* Second argument is the RSA fingerprint of the auth */
  rsa_identity_fpr = smartlist_get(args, 1);

  /* Allocate commit since we have a valid identity now. */
  commit = commit_new(rsa_identity_fpr);

  /* Third argument is the commitment value base64-encoded. */
  value = smartlist_get(args, 2);
  if (commit_decode(value, commit) < 0) {
    goto error;
  }

  /* (Optional) Fourth argument is the revealed value. */
  if (smartlist_len(args) > 3) {
    value = smartlist_get(args, 3);
    if (reveal_decode(value, commit) < 0) {
      goto error;
    }
  }

  return commit;

 error:
  sr_commit_free(commit);
  return NULL;
}

/* Called when we are done parsing a vote by <b>voter_key</b> that might
 * contain some useful <b>commits</b>. Find if any of them should be kept and
 * update our state accordingly. Once done, the list of commitments will be
 * empty. */
void
sr_handle_received_commits(smartlist_t *commits,
                           crypto_pk_t *voter_key)
{
  char rsa_identity_fpr[FINGERPRINT_LEN + 1];

  tor_assert(voter_key);

  /* It's possible that the vote has _NO_ commits. */
  if (commits == NULL) {
    return;
  }

  /* Get the RSA identity fingerprint of this voter */
  if (crypto_pk_get_fingerprint(voter_key, rsa_identity_fpr, 0) < 0) {
    return;
  }

  SMARTLIST_FOREACH_BEGIN(commits, sr_commit_t *, commit) {
    /* We won't need the commit in this list anymore, kept or not. */
    SMARTLIST_DEL_CURRENT(commits, commit);
    /* Check if this commit is valid and should be stored in our state. */
    if (!should_keep_commit(commit, rsa_identity_fpr)) {
      sr_commit_free(commit);
      continue;
    }
    /* Everything lines up: save this commit to state then! */
    save_commit_to_state(commit);
  } SMARTLIST_FOREACH_END(commit);
}

/* Return a heap-allocated string containing commits that should be put in
 * the votes. It's the responsibility of the caller to free the string.
 * This always return a valid string, either empty or with line(s). */
char *
sr_get_string_for_vote(void)
{
  char *vote_str = NULL;
  digestmap_t *state_commits;
  smartlist_t *chunks = smartlist_new();
  const or_options_t *options = get_options();

  /* Are we participating in the protocol? */
  if (!options->AuthDirSharedRandomness) {
    goto end;
  }

  log_debug(LD_DIR, "SR: Preparing our vote info:");

  /* First line, put in the vote the participation flag. */
  {
    char *sr_flag_line;
    static const char *sr_flag_key = "shared-rand-participate";
    tor_asprintf(&sr_flag_line, "%s\n", sr_flag_key);
    smartlist_add(chunks, sr_flag_line);
  }

  /* In our vote we include every commitment in our permanent state. */
  state_commits = sr_state_get_commits();
  DIGESTMAP_FOREACH(state_commits, key, const sr_commit_t *, commit) {
    char *line = get_vote_line_from_commit(commit);
    smartlist_add(chunks, line);
  } DIGESTMAP_FOREACH_END;

  /* Add the SRV value(s) if any. */
  {
    char *srv_lines = get_ns_str_from_sr_values(sr_state_get_previous_srv(),
                                                sr_state_get_current_srv());
    if (srv_lines) {
      smartlist_add(chunks, srv_lines);
    }
  }

 end:
  vote_str = smartlist_join_strings(chunks, "", 0, NULL);
  SMARTLIST_FOREACH(chunks, char *, s, tor_free(s));
  smartlist_free(chunks);
  return vote_str;
}

/* Return a heap-allocated string that should be put in the consensus and
 * contains the shared randomness values. It's the responsibility of the
 * caller to free the string. NULL is returned if no SRV(s) available.
 *
 * This is called when a consensus (any flavor) is bring created thus it
 * should NEVER change the state nor the state should be changed in between
 * consensus creation. */
char *
sr_get_string_for_consensus(const smartlist_t *votes)
{
  char *srv_str;
  const or_options_t *options = get_options();

  tor_assert(votes);

  /* Not participating, avoid returning anything. */
  if (!options->AuthDirSharedRandomness) {
    log_info(LD_DIR, "SR: Support disabled (AuthDirSharedRandomness %d)",
             options->AuthDirSharedRandomness);
    goto end;
  }

  /* Check the votes and figure out if SRVs should be included in the final
     consensus. */
  sr_srv_t *prev_srv = get_majority_srv_from_votes(votes, 0);
  sr_srv_t *cur_srv = get_majority_srv_from_votes(votes, 1);
  srv_str = get_ns_str_from_sr_values(prev_srv, cur_srv);
  if (!srv_str) {
    goto end;
  }

  return srv_str;
 end:
  return NULL;
}

/* We just computed a new <b>consensus</b>. Update our state with the SRVs from
 * the consensus (might be NULL as well). Register the SRVs in our SR state and
 * prepare for the upcoming protocol round. */
void
sr_act_post_consensus(const networkstatus_t *consensus)
{
  /* Start by freeing the current SRVs since the SRVs we believed during voting
   * do not really matter. Now that all the votes are in, we use the majority's
   * opinion on which are the active SRVs. */
  sr_state_clean_srvs();

  /* Set the majority voted SRVs in our state even if both are NULL. It doesn't
   * matter this is what the majority has decided. */
  if (consensus) {
    sr_state_set_previous_srv(srv_dup(consensus->sr_info.previous_srv));
    sr_state_set_current_srv(srv_dup(consensus->sr_info.current_srv));
  }

  /* Reset the fresh flag of the SRV so we know that from now on we don't
   * have a new SRV to vote for thus no need for super majority. */
  sr_state_unset_fresh_srv();

  /* Update our state with the valid_after time of the next consensus so once
   * the next voting period start we are ready to receive votes. */
  time_t next_consensus_valid_after =
    get_next_valid_after_time(consensus->valid_after);
  sr_state_update(next_consensus_valid_after);
}

/* Initialize shared random subsystem. This MUST be called early in the boot
 * process of tor. Return 0 on success else -1 on error. */
int
sr_init(int save_to_disk)
{
  return sr_state_init(save_to_disk, 1);
}

/* Save our state to disk and cleanup everything. */
void
sr_save_and_cleanup(void)
{
  sr_state_save();
  sr_cleanup();
}
