#!/usr/bin/env bash

OUTDIR=$(dirname "$0")/../keystore/testdata
[ -d "$OUTDIR" ] || mkdir -p "$OUTDIR"

password="hunter2"
pwfile="$OUTDIR"/password
echo -n "$password" > "$pwfile"

KEYTOOL="${KEYTOOL:-/usr/bin/keytool}"

rm -f "$OUTDIR"/*.crt "$OUTDIR"/*.jks "$OUTDIR"/*.pem

"$KEYTOOL" -genkeypair -keystore "$OUTDIR"/certs.jks -storetype jks -storepass "$password" \
    -alias rsa2048 -keyalg rsa -keysize 2048 -dname "CN=localhost" -validity 370 -keypass "$password"
"$KEYTOOL" -genkeypair -keystore "$OUTDIR"/certs.jks -storetype jks -storepass "$password" \
    -alias p384 -keyalg ec -keysize 384 -dname "CN=P-384 Root" -validity 370 -keypass "$password"
"$KEYTOOL" -genkeypair -keystore "$OUTDIR"/certs.jks -storetype jks -storepass "$password" \
    -alias p256 -keyalg ec -keysize 256 -dname "CN=www.example.com" -validity 370 -keypass "$password" \
    -signer p384

"$KEYTOOL" -exportcert -keystore "$OUTDIR"/certs.jks -storetype jks -storepass "$password" \
    -alias p384 -file "$OUTDIR"/p384.crt -rfc
"$KEYTOOL" -exportcert -keystore "$OUTDIR"/certs.jks -storetype jks -storepass "$password" \
    -alias p256 -file "$OUTDIR"/p256.crt -rfc
cat "$OUTDIR"/p256.crt "$OUTDIR"/p384.crt >> "$OUTDIR"/chain.pem
"$KEYTOOL" -importcert -keystore "$OUTDIR"/certs.jks -storetype jks -storepass "$password" \
    -alias p256 -file "$OUTDIR"/chain.pem
"$KEYTOOL" -importcert -noprompt -keystore "$OUTDIR"/certs.jks -storetype jks -storepass "$password" \
    -alias p256-certonly -file "$OUTDIR"/p256.crt

"$KEYTOOL" -importkeystore -noprompt \
    -srckeystore  "$OUTDIR"/certs.jks -srcstorepass "$password" \
    -destkeystore "$OUTDIR"/certs-jce.jks -deststoretype jceks -deststorepass "$password"

"$KEYTOOL" -importkeystore -noprompt \
    -srckeystore  "$OUTDIR"/certs.jks -srcstorepass "$password" \
    -destkeystore "$OUTDIR"/certs-and-keys-jce.jks -deststoretype jceks -deststorepass "$password"
"$KEYTOOL" -genseckey -keystore "$OUTDIR"/certs-and-keys-jce.jks -storetype jceks -storepass "$password" \
    -alias aes256 -keyalg aes -keysize 256 -keypass "$password"
"$KEYTOOL" -genseckey -keystore "$OUTDIR"/certs-and-keys-jce.jks -storetype jceks -storepass "$password" \
    -alias aes192 -keyalg aes -keysize 192 -keypass "$password"
"$KEYTOOL" -genseckey -keystore "$OUTDIR"/certs-and-keys-jce.jks -storetype jceks -storepass "$password" \
    -alias aes128 -keyalg aes -keysize 128 -keypass "$password"
"$KEYTOOL" -importpass -keystore "$OUTDIR"/certs-and-keys-jce.jks -storetype jceks -storepass "$password" \
    -alias password -keypass "$password" <<<"monkey123"

"$KEYTOOL" -importkeystore -noprompt \
    -srckeystore  "$OUTDIR"/certs.jks -srcstorepass "$password" \
    -destkeystore "$OUTDIR"/certs-pkcs12.jks -deststoretype pkcs12 -deststorepass "$password"

"$KEYTOOL" -importkeystore -noprompt \
    -srckeystore  "$OUTDIR"/certs-and-keys-jce.jks -srcstorepass "$password" \
    -destkeystore "$OUTDIR"/certs-and-keys-pkcs12.jks -deststoretype pkcs12 -deststorepass "$password"

function keystore_list() {
  "$KEYTOOL" -keystore "$1" -storepass "$password" -list > "$1".list
}

keystore_list "$OUTDIR"/certs.jks
keystore_list "$OUTDIR"/certs-jce.jks
keystore_list "$OUTDIR"/certs-pkcs12.jks
keystore_list "$OUTDIR"/certs-and-keys-jce.jks
keystore_list "$OUTDIR"/certs-and-keys-pkcs12.jks
