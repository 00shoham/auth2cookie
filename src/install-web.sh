#!/bin/sh

BIN="auth2cookie\
     test-cgi\
     fetch-html\
     oauth-request\
     oauth-receive\
     form-test"

DOCS="ui.css\
      sign-in-with-yahoo.png\
      sign-in-with-google.png\
      sign-in-with-linkedin.png\
      sign-in-with-facebook.png\
      sign-in-with-github.png"

CGIDIR=/data/cgi-bin
WEBDIR=/data/www
APPWEBDIR=$WEBDIR/auth2cookie
LOGDIR=/var/log/auth2cookie
WEBUSER=www-data

if [ -d "$LOGDIR" ] ; then
  echo "$LOGDIR already exists"
else
  sudo mkdir "$LOGDIR"
  sudo chown $WEBUSER.$WEBUSER "$LOGDIR"
  sudo chgrp $WEBUSER "$LOGDIR"
  sudo chown 755 "$LOGDIR"
fi

sudo install -o root -g root -m 644 oauth-id-map.txt /usr/local/etc/

make clean
make || exit 1

# check that config is okay.
sudo chmod 777 "$LOGDIR"
./config-test || exit 1
sudo chown $WEBUSER.$WEBUSER "$LOGDIR"
sudo chgrp $WEBUSER "$LOGDIR"
sudo chown 755 "$LOGDIR"

if [ -d "$CGIDIR" ] ; then
  echo "$CGIDIR already exists"
else
  sudo mkdir "$CGIDIR"
  sudo chown root.root "$CGIDIR"
  sudo chown 755 "$CGIDIR"
fi

if [ -d "$WEBDIR" ] ; then
  echo "$WEBDIR already exists"
else
  sudo mkdir "$WEBDIR"
  sudo chown root.root "$WEBDIR"
  sudo chown 755 "$WEBDIR"
fi

if [ -d "$APPWEBDIR" ] ; then
  echo "$APPWEBDIR already exists"
else
  sudo mkdir "$APPWEBDIR"
  sudo chown root.root "$APPWEBDIR"
  sudo chown 755 "$APPWEBDIR"
fi

for b in $BIN; do
  if [ -f "$b" ]; then
    if [ -f "$CGIDIR/$b" ]; then
      sudo rm "$CGIDIR/$b"
    fi
    sudo install -o root -g root -m 755 "$b" "$CGIDIR"
  fi
done

for d in $DOCS; do
  if [ -f "$d" ]; then
    if [ -f "$APPWEBDIR/$d" ]; then
      sudo rm "$APPWEBDIR/$d"
    fi
    sudo install -o root -g root -m 755 "$d" "$APPWEBDIR"
  fi
done

sudo install -o root -g root -m 644 config.ini /usr/local/etc/auth2cookie.ini


