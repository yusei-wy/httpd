#!/bin/sh

gcc -Wall httpd.c -o httpd && sudo ./httpd --port 8080 --chroot --user yuro --group yuro .
