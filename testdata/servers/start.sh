#!/usr/bin/env bash
# Starts a Dovecot IMAP server and an SMTP sink for the core's tests, as the
# current user. Prints export lines; use: eval "$(testdata/servers/start.sh)"
#
# Dovecot comes from DOVECOT_ROOT (an unpacked .deb tree, default ~/tools/dovecot
# if it exists) or the system install.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
# State and ports depend on the checkout, so two worktrees don't stop each other.
id=$(printf %s "$here" | cksum | cut -d' ' -f1)
state=${XDG_CACHE_HOME:-$HOME/.cache}/lazymail-servers-$id
base=$((15000 + id % 1500 * 8))
imap_port=${LAZYMAIL_IMAP_PORT:-$base}
imaps_port=${LAZYMAIL_IMAPS_PORT:-$((base + 1))}
smtp_port=${LAZYMAIL_SMTP_PORT:-$((base + 2))}
smtps_port=${LAZYMAIL_SMTPS_PORT:-$((base + 3))}

root=${DOVECOT_ROOT:-}
if [ -z "$root" ] && [ -x "$HOME/tools/dovecot/usr/sbin/dovecot" ]; then
  root=$HOME/tools/dovecot
fi
dovecot=$root/usr/sbin/dovecot
libexec=$root/usr/lib/dovecot
if [ ! -x "$dovecot" ]; then
  echo "dovecot not found (set DOVECOT_ROOT or install dovecot-core and dovecot-imapd)" >&2
  exit 1
fi
export LD_LIBRARY_PATH=$libexec:$libexec/modules/old-stats${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
case $("$dovecot" --version) in
  2.3*) ;;
  *) echo "dovecot.conf.in is written for Dovecot 2.3" >&2; exit 1 ;;
esac

"$here/stop.sh" >/dev/null 2>&1 || true
rm -rf "$state"
mkdir -p "$state/run" "$state/mail" "$state/smtp"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -keyout "$state/key.pem" -out "$state/cert.pem" 2>/dev/null

sed \
  -e "s|@STATE@|$state|g" -e "s|@LIBEXEC@|$libexec|g" -e "s|@HERE@|$here|g" \
  -e "s|@USER@|$(id -un)|g" -e "s|@GROUP@|$(id -gn)|g" \
  -e "s|@UID@|$(id -u)|g" -e "s|@GID@|$(id -g)|g" \
  -e "s|@IMAP_PORT@|$imap_port|g" -e "s|@IMAPS_PORT@|$imaps_port|g" \
  "$here/dovecot.conf.in" > "$state/dovecot.conf"

# An unpacked package still looks for /usr/bin/doveconf and /usr/lib/dovecot/modules
# inside libdovecot; a patched copy of that library points at the unpacked files
# through short symlinks.
if [ ! -x /usr/bin/doveconf ]; then
  mkdir "$state/lib"
  # The libdovecot paths are fixed in length, so the links need fixed names in /tmp.
  for l in lb lm; do
    if [ -e "/tmp/$l" ] && { [ ! -L "/tmp/$l" ] || [ ! -O "/tmp/$l" ]; }; then
      echo "/tmp/$l exists and is not a symlink of yours" >&2
      exit 1
    fi
  done
  ln -sfn "$root/usr/bin" /tmp/lb
  ln -sfn "$libexec" /tmp/lm
  perl -0777 -pe 's|/usr/bin/doveconf|/tmp/lb/doveconf\x00|g; s|/usr/lib/dovecot/modules|/tmp/lm/modules\x00\x00\x00\x00\x00\x00\x00\x00\x00|g' \
    "$libexec/libdovecot.so.0" > "$state/lib/libdovecot.so.0"
  export LD_LIBRARY_PATH=$state/lib:$LD_LIBRARY_PATH
fi

"$dovecot" -c "$state/dovecot.conf" >&2
python3 "$here/smtp_sink.py" "$state/smtp" "$state/cert.pem" "$state/key.pem" \
  "$smtp_port" "$smtps_port" > "$state/smtp.log" 2>&1 &
echo $! > "$state/smtp.pid"

wait_port() {
  for _ in $(seq 100); do
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
    sleep 0.1
  done
  echo "nothing listening on port $1, see $state" >&2
  return 1
}
wait_port "$imap_port"
wait_port "$imaps_port"
wait_port "$smtp_port"
wait_port "$smtps_port"

cat <<ENV | tee "$state/env"
export LAZYMAIL_TEST_IMAP=127.0.0.1:$imap_port
export LAZYMAIL_TEST_IMAPS=127.0.0.1:$imaps_port
export LAZYMAIL_TEST_SMTP=127.0.0.1:$smtp_port
export LAZYMAIL_TEST_SMTPS=127.0.0.1:$smtps_port
export LAZYMAIL_TEST_USER=alice
export LAZYMAIL_TEST_PASS=alice-pass
export LAZYMAIL_TEST_USER2=bob
export LAZYMAIL_TEST_PASS2=bob-pass
export LAZYMAIL_TEST_SMTP_DIR=$state/smtp
ENV
