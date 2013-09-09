#!/bin/bash

# We use a variable as working out relative paths is difficult at best:
# http://mywiki.wooledge.org/BashFAQ/028 and we can't use a standard location
# as we'll probably want to be sharing this file with Vagrant which is
# relative.
PASSWORDS="/home/dean/Projects/mobilepasser/vagrant/files/passwords.txt"

# Print out the first line.
head -n 1 $PASSWORDS | tr -d '\r\n'

# Remove the first line from the file.
sed -i -e "1d" $PASSWORDS
