#! /bin/sh

ECHO_N="/bin/echo -n"
use_coverage_binary=false

until [ -z $1 ]
do
  case $1 in
    --chutney-path)
      export CHUTNEY_PATH="$2"
      shift
    ;;
    --tor-path)
      export TOR_DIR="$2"
      shift
    ;;
    --flavor|--flavour|--network-flavor|--network-flavour)
      export NETWORK_FLAVOUR="$2"
      shift
    ;;
    --delay|--sleep|--bootstrap-time|--time)
      export BOOTSTRAP_TIME="$2"
      shift
    ;;
    --max-delay|--max-sleep|--max-bootstrap-time|--max-time)
      export MAX_BOOTSTRAP_TIME="$2"
      shift
    ;;
    # Environmental variables used by chutney verify performance tests
    # Send this many bytes per client connection (10 KBytes)
    --data|--data-bytes|--data-byte|--bytes|--byte)
      export CHUTNEY_DATA_BYTES="$2"
      shift
    ;;
    # Make this many connections per client (1)
    # Note: If you create 7 or more connections to a hidden service from
    # a single client, you'll likely get a verification failure due to
    # https://trac.torproject.org/projects/tor/ticket/15937
    --connections|--connection|--connection-count|--count)
      export CHUTNEY_CONNECTIONS="$2"
      shift
    ;;
    # Make each client connect to each HS (0)
    # 0 means a single client connects to each HS
    # 1 means every client connects to every HS
    --hs-multi-client|--hs-multi-clients|--hs-client|--hs-clients)
      export CHUTNEY_HS_MULTI_CLIENT="$2"
      shift
      ;;
    --coverage)
      use_coverage_binary=true
      ;;
    --configure|--configures|--reconfigure|--reconfigures)
      CHUTNEY_RECONFIGURES="$2"
      ;;
    *)
      echo "Sorry, I don't know what to do with '$1'."
      exit 2
    ;;
  esac
  shift
done

TOR_DIR="${TOR_DIR:-$PWD}"
NETWORK_FLAVOUR=${NETWORK_FLAVOUR:-"bridges+hs"}
CHUTNEY_NETWORK=networks/$NETWORK_FLAVOUR
myname=$(basename $0)

[ -n "$CHUTNEY_PATH" ] || {
  echo "$myname: \$CHUTNEY_PATH not set, trying $TOR_DIR/../chutney"
  CHUTNEY_PATH="$TOR_DIR/../chutney"
}

[ -d "$CHUTNEY_PATH" ] && [ -x "$CHUTNEY_PATH/chutney" ] || {
  echo "$myname: missing 'chutney' in CHUTNEY_PATH ($CHUTNEY_PATH)"
  echo "$myname: Get chutney: git clone https://git.torproject.org/\
chutney.git"
  echo "$myname: Set \$CHUTNEY_PATH to a non-standard location: export CHUTNEY_PATH=\`pwd\`/chutney"
  exit 1
}

cd "$CHUTNEY_PATH"
# For picking up the right tor binaries.
tor_name=tor
tor_gencert_name=tor-gencert
if test "$use_coverage_binary" = true; then
  tor_name=tor-cov
fi
export CHUTNEY_TOR="${TOR_DIR}/src/or/${tor_name}"
export CHUTNEY_TOR_GENCERT="${TOR_DIR}/src/tools/${tor_gencert_name}"

CHUTNEY_RECONFIGURES=${CHUTNEY_RECONFIGURES:-2}
c=0
while [ $c -lt $CHUTNEY_RECONFIGURES ]; do
  echo "$myname: Configuring and starting network..."
  # bootstrap-network.sh exits with the result of chutney status,
  # which is -1 on failure
  ./tools/bootstrap-network.sh $NETWORK_FLAVOUR
  BOOTSTRAP_EXIT_STATUS=$?

  if [ $BOOTSTRAP_EXIT_STATUS -ne 0 ]; then
    echo "$myname: Retrying configuring and starting network..."
    c=$(expr $c + 1)
    continue
  fi

  # Sleep some, waiting for the network to bootstrap.
  # TODO: Add chutney command 'bootstrap-status' and use that instead.
  BOOTSTRAP_TIME=${BOOTSTRAP_TIME:-20}
  MAX_BOOTSTRAP_TIME=${MAX_BOOTSTRAP_TIME:-60}
  # Trying every 5 seconds seems reasonable, most systems will take 1-2 tries
  # as typical bootstrap times are 20-25 seconds
  VERIFY_INTERVAL=5
  $ECHO_N "$myname: sleeping for $BOOTSTRAP_TIME seconds"
  n=0
  while [ $n -le $MAX_BOOTSTRAP_TIME ]; do
    sleep 1;
    n=$(expr $n + 1);
    $ECHO_N .

    if [ $n -ge $BOOTSTRAP_TIME ]; then
      echo ""
      ./chutney verify $CHUTNEY_NETWORK
      VERIFY_EXIT_STATUS=$?

      if [ $VERIFY_EXIT_STATUS -eq 0 ]; then
        # work around a bug/feature in make -j2 (or more)
        # where make hangs if any child processes are still alive
        ./chutney stop $CHUTNEY_NETWORK
        exit $VERIFY_EXIT_STATUS
      else
        $ECHO_N "$myname: sleeping for $VERIFY_INTERVAL seconds"
        BOOTSTRAP_TIME=$(expr $BOOTSTRAP_TIME + $VERIFY_INTERVAL);
      fi
    fi
  done # while [ $n -le $MAX_BOOTSTRAP_TIME ]
  echo "" 

  # at this point, we have failed by exceeding the maximum bootstrap time
  echo "Maximum bootstrap time ($MAX_BOOTSTRAP_TIME) exceeded."
  echo "Use --max-time N or MAX_BOOTSTRAP_TIME=N to add more time."
  # work around a bug/feature in make -j2 (or more)
  # where make hangs if any child processes are still alive
  ./chutney stop $CHUTNEY_NETWORK
  exit $VERIFY_EXIT_STATUS
done # while [ $c -lt "$try_chutney_configure" ]

# at this point, we have failed by exceeding the configure retries
echo "Maximum number of configuration tries ($CHUTNEY_RECONFIGURES) exceeded."
echo "Use --configure N or CHUTNEY_RECONFIGURES=N to add more attempts."
exit 2
