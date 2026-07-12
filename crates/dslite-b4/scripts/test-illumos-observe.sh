#!/bin/sh

set -eu

TUNNEL=${DSLITE_TEST_TUNNEL:-dslitetst0}
LOCAL_V6=${DSLITE_TEST_LOCAL_V6:?set DSLITE_TEST_LOCAL_V6 to an IPv6 address configured on this host}
REMOTE_V6=${DSLITE_TEST_REMOTE_V6:-2001:db8::2}

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root" >&2
    exit 1
fi

cd "$(dirname "$0")/.."

cleanup()
{
    ipadm disable-if -t "$TUNNEL" >/dev/null 2>&1 || true
    dladm delete-iptun -t "$TUNNEL" >/dev/null 2>&1 || true
}

delete_test_tunnel()
{
    ipadm disable-if -t "$TUNNEL"
    dladm delete-iptun -t "$TUNNEL"
}

run_observe_test()
{
    DSLITE_TEST_TUNNEL=$TUNNEL \
    DSLITE_TEST_LOCAL_V6=$LOCAL_V6 \
    DSLITE_TEST_REMOTE_V6=$REMOTE_V6 \
    DSLITE_TEST_EXPECT=$1 \
        cargo test observes_illumos_tunnel -- --ignored --nocapture
}

run_bring_up_test()
{
    DSLITE_TEST_TUNNEL=$TUNNEL \
    DSLITE_TEST_LOCAL_V6=$LOCAL_V6 \
    DSLITE_TEST_REMOTE_V6=$REMOTE_V6 \
        cargo test brings_up_illumos_tunnel -- --ignored --nocapture
}

trap cleanup EXIT HUP INT TERM
cleanup

dladm create-iptun -t -T ipv6 \
    -a "local=$LOCAL_V6,remote=$REMOTE_V6" \
    "$TUNNEL"
ipadm create-ip -t "$TUNNEL"
ipadm create-addr -t -T static \
    -a local=192.0.0.2,remote=192.0.0.1 \
    "$TUNNEL/test"

run_observe_test present-up

ifconfig "$TUNNEL" down
run_observe_test present-down
run_bring_up_test

delete_test_tunnel
run_observe_test absent
