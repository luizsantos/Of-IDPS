#!/bin/bash

rm /var/log/snort/*
snort -c /etc/snort/snort.conf &

