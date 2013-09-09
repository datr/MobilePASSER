#!/bin/bash
export DISPLAY=:0.0
cnee --record --events-to-record 1000 --mouse --keyboard -o /tmp/xnee.xns -e /tmp/xnee.log -v
