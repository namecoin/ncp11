#!/usr/bin/env bash
export HOME=~
set -eu

# Adapted from Electrum-NMC.

bitcoin_cli="namecoin-cli -rpcuser=doggman -rpcpassword=donkey -rpcport=18554 -regtest"

function new_blocks()
{
    $bitcoin_cli generatetoaddress "$1" "$($bitcoin_cli getnewaddress)" > /dev/null
}

function assert_equal()
{
    err_msg="$3"

    if [[ "$1" != "$2" ]]; then
        echo "'$1' != '$2'"
        echo "$err_msg"
        return 1
    fi
}

function assert_raises_error()
{
    cmd=$1
    required_err=$2

    if observed_err=$($cmd 2>&1) ; then
        echo "Failed to raise error '$required_err'"
        return 1
    fi
    if [[ "$observed_err" != *"$required_err"* ]]; then
        echo "$observed_err"
        echo "Raised wrong error instead of '$required_err'"
        return 1
    fi
}

function b64_file()
{
    base64 -w0 "$1"
}

function b64url_file()
{
    b64_file "$1" | tr '+/' '-_' | tr -d '='
}

function curl_test()
{
    curl --silent --show-error --fail --connect-timeout 5 --max-time 20 --noproxy "*" "$@"
}

function stop_local_https_server()
{
    if [[ -n "${HTTPS_SERVER_PID:-}" ]]; then
        kill "$HTTPS_SERVER_PID" 2>/dev/null || true
        wait "$HTTPS_SERVER_PID" 2>/dev/null || true
        HTTPS_SERVER_PID=""
    fi
}

function cleanup_local_tests()
{
    stop_local_https_server
    rm -rf "${TEST_TMPDIR:-}"
}

function register_namecoin_name()
{
    name="$1"
    value="$2"

    echo "Pre-register $name"
    name_new_output=$($bitcoin_cli name_new "$name")
    name_txid=$(echo "$name_new_output" | grep -oE '"[0-9a-f]+"' | tr -d '"' | sed -n '1p')
    name_rand=$(echo "$name_new_output" | grep -oE '"[0-9a-f]+"' | tr -d '"' | sed -n '2p')

    echo "Wait for $name pre-registration to mature"
    new_blocks 12

    echo "Register $name"
    $bitcoin_cli name_firstupdate "$name" "$name_rand" "$name_txid"

    echo "Wait for $name registration to confirm"
    new_blocks 1

    echo "Update $name"
    $bitcoin_cli name_update "$name" "$value"

    echo "Wait for $name update to confirm"
    new_blocks 1
}

function generate_leaf_cert()
{
    leaf_domain="$1"
    leaf_parent_ca="$2"
    leaf_parent_key="$3"
    leaf_key="$4"
    leaf_csr="$5"
    leaf_cert="$6"
    leaf_ext="$7"
    leaf_serial="$8"

    openssl ecparam -name prime256v1 -genkey -noout -out "$leaf_key"
    openssl req -new -key "$leaf_key" -subj "/CN=$leaf_domain" -out "$leaf_csr"

    cat > "$leaf_ext" <<EOF
[ext]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$leaf_domain
EOF

    openssl x509 -req -in "$leaf_csr" -CA "$leaf_parent_ca" -CAkey "$leaf_parent_key" -CAcreateserial -CAserial "$leaf_serial" -out "$leaf_cert" -days 3650 -sha256 -extfile "$leaf_ext" -extensions ext
}

function generate_self_signed_leaf_cert()
{
    leaf_domain="$1"
    leaf_key="$2"
    leaf_cert="$3"
    leaf_ext="$4"

    openssl ecparam -name prime256v1 -genkey -noout -out "$leaf_key"
    openssl req -new -x509 -key "$leaf_key" -subj "/CN=$leaf_domain" -out "$leaf_cert" -days 3650 -sha256 -extensions ext -config - <<EOF
[req]
distinguished_name=dn
x509_extensions=ext
prompt=no

[dn]
CN=$leaf_domain

[ext]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$leaf_domain
EOF

    : > "$leaf_ext"
}

function start_local_https_server()
{
    https_cert="$1"
    https_key="$2"

    stop_local_https_server

    mkdir -p "$HTTPS_DOCROOT"
    cat > "$HTTPS_DOCROOT/index.html" <<EOF
<!DOCTYPE html>
<html>
<body>
Namecoin ncp11 local TLS test
</body>
</html>
EOF

    (
        cd "$HTTPS_DOCROOT"
        openssl s_server -accept "$LOCAL_HTTPS_PORT" -cert "$https_cert" -key "$https_key" -WWW
    ) > "$HTTPS_SERVER_LOG" 2>&1 &
    HTTPS_SERVER_PID=$!
    sleep 2

    if ! kill -0 "$HTTPS_SERVER_PID" 2>/dev/null; then
        cat "$HTTPS_SERVER_LOG"
        echo "Local HTTPS server failed to start"
        return 1
    fi
}

function assert_no_tlsa()
{
    test_domain="$1"

    dig_short=$(dig +short -p 5391 @127.0.0.1 TLSA "*.$test_domain")
    assert_equal "$dig_short" "" "$test_domain unexpectedly had authoritative TLSA data"

    dig_short=$(dig +short -p 53 @127.0.0.1 TLSA "*.$test_domain")
    assert_equal "$dig_short" "" "$test_domain unexpectedly had recursive TLSA data"
}

echo "Expire any existing names from previous functional test runs"
new_blocks 35

TEST_TMPDIR=$(mktemp -d)
LOCAL_HTTPS_ADDR=127.0.0.1
LOCAL_HTTPS_PORT=4443
HTTPS_DOCROOT="$TEST_TMPDIR/https-docroot"
HTTPS_SERVER_LOG="$TEST_TMPDIR/https-server.log"
trap cleanup_local_tests EXIT

TESTLS_CA_KEY="$TEST_TMPDIR/testls-ca.key"
TESTLS_CA_PUB_DER="$TEST_TMPDIR/testls-ca-pub.der"

openssl ecparam -name prime256v1 -genkey -noout -out "$TESTLS_CA_KEY"
openssl pkey -in "$TESTLS_CA_KEY" -pubout -outform DER -out "$TESTLS_CA_PUB_DER"
TESTLS_CA_PUB_B64=$(b64_file "$TESTLS_CA_PUB_DER")
TESTLS_VALUE="{\"ip\":\"107.152.38.155\",\"map\":{\"*\":{\"tls\":[[2,1,0,\"$TESTLS_CA_PUB_B64\"]]},\"sub1\":{\"map\":{\"sub2\":{\"map\":{\"sub3\":{\"ip\":\"107.152.38.155\"}}}}},\"_tor\":{\"txt\":\"dhflg7a7etr77hwt4eerwoovhg7b5bivt2jem4366dt4psgnl5diyiyd.onion\"}}}"
register_namecoin_name 'd/testls' "$TESTLS_VALUE"

echo "Query testls.bit via Core"
$bitcoin_cli name_show 'd/testls'

echo "Query testls.bit IPv4 Authoritative via dig"
dig_output=$(dig -p 5391 @127.0.0.1 A testls.bit)
echo "$dig_output"
echo "Checking response correctness"
echo "$dig_output" | grep "107.152.38.155"

echo "Query testls.bit TLS Authoritative via dig"
dig_output=$(dig -p 5391 @127.0.0.1 TLSA "*.testls.bit")
echo "$dig_output"
echo "Checking response correctness"
tlsa_hex="$(xxd -u -ps -c 500 "$TESTLS_CA_PUB_DER")"
echo "$dig_output" | sed 's/ //g' | grep "$tlsa_hex"

echo "Query testls.bit IPv4 Recursive via dig"
dig_output=$(dig -p 53 @127.0.0.1 A testls.bit)
echo "$dig_output"
echo "Checking response correctness"
echo "$dig_output" | grep "107.152.38.155"

echo "Query testls.bit TLS Recursive via dig"
dig_output=$(dig -p 53 @127.0.0.1 TLSA "*.testls.bit")
echo "$dig_output"
echo "Checking response correctness"
tlsa_hex="$(xxd -u -ps -c 500 "$TESTLS_CA_PUB_DER")"
echo "$dig_output" | sed 's/ //g' | grep "$tlsa_hex"

echo "Fetch testls.bit via curl"
curl_test --insecure https://testls.bit/ | grep -i "Cool or nah"

echo "Fetch Root CA via curl"
curl_test http://127.127.127.127/lookup?domain=Namecoin%20Root%20CA | grep -i "BEGIN CERTIFICATE"

echo "Fetch TLD CA via curl"
curl_test http://127.127.127.127/lookup?domain=.bit%20TLD%20CA | grep -i "BEGIN CERTIFICATE"

echo "Fetch testls.bit CA via curl"
curl_test http://127.127.127.127/lookup?domain=testls.bit%20Domain%20AIA%20Parent%20CA | grep -i "BEGIN CERTIFICATE"

FULL_LABEL="ncp11full$(date +%s%N | sha256sum | cut -c1-8)"
FULL_NAME="d/$FULL_LABEL"
FULL_DOMAIN="$FULL_LABEL.bit"
FULL_CA_KEY="$TEST_TMPDIR/full-ca.key"
FULL_CA_PUB_DER="$TEST_TMPDIR/full-ca-pub.der"
FULL_PARENT_CA="$TEST_TMPDIR/full-parent-ca.pem"
FULL_LEAF_KEY="$TEST_TMPDIR/full-leaf.key"
FULL_LEAF_CSR="$TEST_TMPDIR/full-leaf.csr"
FULL_LEAF_CERT="$TEST_TMPDIR/full-leaf.pem"
FULL_LEAF_EXT="$TEST_TMPDIR/full-leaf-ext.cnf"
FULL_LEAF_SERIAL="$TEST_TMPDIR/full-leaf.srl"
BOGUS_LEAF_KEY="$TEST_TMPDIR/bogus-leaf.key"
BOGUS_LEAF_CERT="$TEST_TMPDIR/bogus-leaf.pem"
BOGUS_LEAF_EXT="$TEST_TMPDIR/bogus-leaf-ext.cnf"

STAPLED_LABEL="ncp11stapled$(date +%s%N | sha256sum | cut -c1-8)"
STAPLED_NAME="d/$STAPLED_LABEL"
STAPLED_DOMAIN="$STAPLED_LABEL.bit"
STAPLED_CA_KEY="$TEST_TMPDIR/stapled-ca.key"
STAPLED_CA_PUB_DER="$TEST_TMPDIR/stapled-ca-pub.der"
STAPLED_PARENT_CA="$TEST_TMPDIR/stapled-parent-ca.pem"
STAPLED_LEAF_KEY="$TEST_TMPDIR/stapled-leaf.key"
STAPLED_LEAF_CSR="$TEST_TMPDIR/stapled-leaf.csr"
STAPLED_LEAF_CERT="$TEST_TMPDIR/stapled-leaf.pem"
STAPLED_LEAF_EXT="$TEST_TMPDIR/stapled-leaf-ext.cnf"
STAPLED_LEAF_SERIAL="$TEST_TMPDIR/stapled-leaf.srl"

echo "Generate full-TLSA local test certificate material"
openssl ecparam -name prime256v1 -genkey -noout -out "$FULL_CA_KEY"
openssl pkey -in "$FULL_CA_KEY" -pubout -outform DER -out "$FULL_CA_PUB_DER"
FULL_CA_PUB_B64=$(b64_file "$FULL_CA_PUB_DER")

register_namecoin_name "$FULL_NAME" "{\"ip\":\"$LOCAL_HTTPS_ADDR\",\"map\":{\"*\":{\"tls\":[[2,1,0,\"$FULL_CA_PUB_B64\"]]}}}"

echo "Fetch full-TLSA $FULL_DOMAIN parent CA from Encaya"
curl_test --get --data-urlencode "domain=$FULL_DOMAIN Domain AIA Parent CA" http://127.127.127.127/lookup > "$FULL_PARENT_CA"
grep -i "BEGIN CERTIFICATE" "$FULL_PARENT_CA"

echo "Generate full-TLSA local leaf certificate"
generate_leaf_cert "$FULL_DOMAIN" "$FULL_PARENT_CA" "$FULL_CA_KEY" "$FULL_LEAF_KEY" "$FULL_LEAF_CSR" "$FULL_LEAF_CERT" "$FULL_LEAF_EXT" "$FULL_LEAF_SERIAL"

echo "Generate unrelated self-signed certificate for ncp11 negative test"
generate_self_signed_leaf_cert "$FULL_DOMAIN" "$BOGUS_LEAF_KEY" "$BOGUS_LEAF_CERT" "$BOGUS_LEAF_EXT"

echo "Generate stapled local test certificate material"
openssl ecparam -name prime256v1 -genkey -noout -out "$STAPLED_CA_KEY"
openssl pkey -in "$STAPLED_CA_KEY" -pubout -outform DER -out "$STAPLED_CA_PUB_DER"
STAPLED_CA_PUB_B64=$(b64url_file "$STAPLED_CA_PUB_DER")

register_namecoin_name "$STAPLED_NAME" "{\"ip\":\"$LOCAL_HTTPS_ADDR\"}"
assert_no_tlsa "$STAPLED_DOMAIN"

echo "Create stapled Namecoin certification signature"
STAPLED_BLOCKCHAIN_ADDRESS=$($bitcoin_cli name_show "$STAPLED_NAME" | grep '"address"' | cut -d '"' -f4)
STAPLED_MESSAGE_JSON="{\"address\":\"$STAPLED_BLOCKCHAIN_ADDRESS\",\"domain\":\"$STAPLED_DOMAIN\",\"x509pub\":\"$STAPLED_CA_PUB_B64\"}"
STAPLED_MESSAGE="Namecoin X.509 Stapled Certification: $STAPLED_MESSAGE_JSON"
STAPLED_BLOCKCHAIN_SIG=$($bitcoin_cli signmessage "$STAPLED_BLOCKCHAIN_ADDRESS" "$STAPLED_MESSAGE")
STAPLED_SIGS_JSON="[{\"blockchainaddress\":\"$STAPLED_BLOCKCHAIN_ADDRESS\",\"blockchainsig\":\"$STAPLED_BLOCKCHAIN_SIG\"}]"

echo "Fetch stapled $STAPLED_DOMAIN parent CA from Encaya"
curl_test --get --data-urlencode "domain=$STAPLED_DOMAIN Domain AIA Parent CA" --data-urlencode "pubb64=$STAPLED_CA_PUB_B64" --data-urlencode "sigs=$STAPLED_SIGS_JSON" http://127.127.127.127/lookup > "$STAPLED_PARENT_CA"
grep -i "BEGIN CERTIFICATE" "$STAPLED_PARENT_CA"

echo "Generate stapled local leaf certificate"
generate_leaf_cert "$STAPLED_DOMAIN" "$STAPLED_PARENT_CA" "$STAPLED_CA_KEY" "$STAPLED_LEAF_KEY" "$STAPLED_LEAF_CSR" "$STAPLED_LEAF_CERT" "$STAPLED_LEAF_EXT" "$STAPLED_LEAF_SERIAL"

echo "Fetch Namecoin.org with stock Firefox"
testdata/try-firefox-connect.bash www.namecoin.org success "" || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash missing

echo "Fetch TesTLS.bit with stock Firefox"
testdata/try-firefox-connect.bash testls.bit fail "Certificate error was not overridden" || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash missing

rm -f /etc/firefox/policies/policies.json

echo "Fetch full-TLSA local test domain with stock Firefox"
start_local_https_server "$FULL_LEAF_CERT" "$FULL_LEAF_KEY"
testdata/try-firefox-connect.bash "$FULL_DOMAIN:$LOCAL_HTTPS_PORT" fail "Certificate error was not overridden" || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash missing

echo "Configure Firefox for ncp11"
mkdir -p /etc/firefox/policies
echo "{
  \"policies\": {
    \"SecurityDevices\": {
      \"Namecoin Certificate Trust\": \"$(pwd)/libncp11.so\"
    }
  }
}" > /etc/firefox/policies/policies.json

echo "Fetch Namecoin.org with ncp11 Firefox"
testdata/try-firefox-connect.bash www.namecoin.org success "" || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash missing

echo "Fetch unrelated local test cert with ncp11 Firefox"
start_local_https_server "$BOGUS_LEAF_CERT" "$BOGUS_LEAF_KEY"
testdata/try-firefox-connect.bash "$FULL_DOMAIN:$LOCAL_HTTPS_PORT" fail "Certificate error was not overridden" || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash present

echo "Fetch full-TLSA local test domain with ncp11 Firefox"
start_local_https_server "$FULL_LEAF_CERT" "$FULL_LEAF_KEY"
testdata/try-firefox-connect.bash "$FULL_DOMAIN:$LOCAL_HTTPS_PORT" success "" || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash present

echo "Fetch stapled local test domain with ncp11 Firefox"
start_local_https_server "$STAPLED_LEAF_CERT" "$STAPLED_LEAF_KEY"
testdata/try-firefox-connect.bash "$STAPLED_DOMAIN:$LOCAL_HTTPS_PORT" success "" || testdata/dump-proxy-log-fail.bash
testdata/assert-proxy-log.bash present
