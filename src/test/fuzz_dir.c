/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"

#define BUFFERS_PRIVATE

#include "or.h"
#include "backtrace.h"
#include "buffers.h"
#include "config.h"
#include "directory.h"
#include "torlog.h"

/* Silence compiler warnings about a missing extern */
extern const char tor_git_revision[];
const char tor_git_revision[] = "";

#define MAX_FUZZ_SIZE (2*MAX_HEADERS_SIZE + MAX_DIR_UL_SIZE)

static int mock_get_options_calls = 0;
static or_options_t *mock_options = NULL;

static void
reset_options(or_options_t *options, int *get_options_calls)
{
  memset(options, 0, sizeof(or_options_t));
  options->TestingTorNetwork = 1;

  *get_options_calls = 0;
}

static const or_options_t *
mock_get_options(void)
{
  ++mock_get_options_calls;
  tor_assert(mock_options);
  return mock_options;
}

static int
mock_directory_handle_command_get(dir_connection_t *conn,
                                      const char *headers,
                                      const char *body,
                                      size_t body_len)
{
  (void)conn;

  printf("Method:\nGET\n");

  if (headers) {
    printf("Header-Length:\n%zu\n", strlen(headers));
    tor_assert(strlen(headers) >= 0);
    tor_assert(strlen(headers) < MAX_FUZZ_SIZE);
    printf("Headers:\n%s\n", headers);
  }

  printf("Body-Length:\n%zu\n", body_len);
  tor_assert(body_len >= 0);
  tor_assert(body_len < MAX_FUZZ_SIZE);
  if (body) {
    tor_assert(strlen(body) >= 0);
    tor_assert(strlen(body) < MAX_FUZZ_SIZE);
    printf("Body:\n%s\n", body);
  }

  /* Always tell the caller we succeeded */
  return 0;
}

static int
mock_directory_handle_command_post(dir_connection_t *conn,
                                       const char *headers,
                                       const char *body,
                                       size_t body_len)
{
  (void)conn;

  printf("Method:\nPOST\n");

  if (headers) {
    printf("Header-Length:\n%zu\n", strlen(headers));
    tor_assert(strlen(headers) >= 0);
    tor_assert(strlen(headers) < MAX_FUZZ_SIZE);
    printf("Headers:\n%s\n", headers);
  }

  printf("Body-Length:\n%zu\n", body_len);
  tor_assert(body_len >= 0);
  tor_assert(body_len < MAX_FUZZ_SIZE);
  if (body) {
    tor_assert(strlen(body) >= 0);
    tor_assert(strlen(body) < MAX_FUZZ_SIZE);
    printf("Body:\n%s\n", body);
  }

  /* Always tell the caller we succeeded */
  return 0;
}

/* Read a directory command (including HTTP headers) from stdin, parse it, and
 * output what tor parsed */
int
main(int c, char** v)
{
  int loglevel = LOG_INFO;

  /* Initialise logging first */
  init_logging(1);
  configure_backtrace_handler(get_version());

  for (int i = 1; i < c; ++i) {
    if (!strcmp(v[i], "--warn")) {
      loglevel = LOG_WARN;
    } else if (!strcmp(v[i], "--notice")) {
      loglevel = LOG_NOTICE;
    } else if (!strcmp(v[i], "--info")) {
      loglevel = LOG_INFO;
    } else if (!strcmp(v[i], "--debug")) {
      loglevel = LOG_DEBUG;
    }
  }

  {
    log_severity_list_t s;
    memset(&s, 0, sizeof(s));
    set_log_severity_config(loglevel, LOG_ERR, &s);
    /* ALWAYS log bug warnings. */
    s.masks[LOG_WARN-LOG_ERR] |= LD_BUG;
    add_stream_log(&s, "", fileno(stdout));
  }

  /* Make BUG() and nonfatal asserts crash */
  tor_set_failed_assertion_callback(abort);

  /* Set up fake variables */
  dir_connection_t dir_conn;
  int rv = -1;
  ssize_t data_size = -1;
  char *stdin_buf = tor_malloc(MAX_FUZZ_SIZE+1);

  /* directory_handle_command checks some tor options
   * just make them all 0 */
  mock_options = tor_malloc(sizeof(or_options_t));
  reset_options(mock_options, &mock_get_options_calls);
  MOCK(get_options, mock_get_options);

  /* Set up the fake handler functions */
  MOCK(directory_handle_command_get, mock_directory_handle_command_get);
  MOCK(directory_handle_command_post, mock_directory_handle_command_post);

  /* Set up the fake connection */
  memset(&dir_conn, 0, sizeof(dir_connection_t));
  dir_conn.base_.type = CONN_TYPE_DIR;

/*
afl extension - loop and reset state after parsing
likely needs to reset the allocation data structures and counts as well
#ifdef __AFL_HAVE_MANUAL_CONTROL
  while (__AFL_LOOP(1000)) {
#endif
*/

  /* Initialise the data structures */
  memset(stdin_buf, 0, MAX_FUZZ_SIZE+1);

  /* Apparently tor sets this before directory_handle_command() is called. */
  dir_conn.base_.address = tor_strdup("replace-this-address.example.com");

#ifdef __AFL_HAVE_MANUAL_CONTROL
  /* Tell AFL to pause and fork here - ignored if not using AFL */
  __AFL_INIT();
#endif

  /* Read the data */
  data_size = read(STDIN_FILENO, stdin_buf, MAX_FUZZ_SIZE);
  tor_assert(data_size != -1);
  tor_assert(data_size <= MAX_FUZZ_SIZE);
  stdin_buf[data_size] = '\0';
  tor_assert(strlen(stdin_buf) >= 0);
  tor_assert(strlen(stdin_buf) <= MAX_FUZZ_SIZE);

  printf("Input-Length:\n%zu\n", data_size);
  printf("Input:\n%s\n", stdin_buf);

  /* Copy the stdin data into the buffer */
  tor_assert(data_size >= 0);
  dir_conn.base_.inbuf = buf_new_with_data(stdin_buf, (size_t)data_size);
  if (!dir_conn.base_.inbuf) {
    printf("Zero-Length-Input\n");
    exit(0);
  }

  /* Parse the headers */
  rv = directory_handle_command(&dir_conn);

  /* TODO: check the output is correctly parsed based on the input */

  /* Report the parsed origin address */
  if (dir_conn.base_.address) {
    printf("Address:\n%s\n", dir_conn.base_.address);
  }

  printf("Result:\n%d\n", rv);

  /* Reset */
  tor_free(dir_conn.base_.address);

  buf_free(dir_conn.base_.inbuf);
  dir_conn.base_.inbuf = NULL;

/*
#ifdef __AFL_HAVE_MANUAL_CONTROL
  }
#endif
*/

  /* Cleanup */
  UNMOCK(directory_handle_command_get);
  UNMOCK(directory_handle_command_post);

  tor_free(mock_options);
  UNMOCK(get_options);

  tor_free(stdin_buf);
}