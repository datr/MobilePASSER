#!/bin/bash
while :
do
	# I had to do some experimentation with the sp parameter. 10 was slightly
	# to fast and would sometimes cause the password not to be copied into the
	# clipboard.
	cnee --replay -f /tmp/xnee.xns -v -e /tmp/xnee.log -ns -sp 20

	# MobilePass disables the generate password button for 5 seconds after each
	# use so we have to wait for it to become active again.
	sleep 5
done
