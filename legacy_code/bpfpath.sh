#!/bin/bash

set -e

rm obj/*_kp_prog.o

KP_FUNCS="kp_funcs.list"
KP_NUM=1

while read KP_NAME KP_FIN; do
	echo $KP_NUM $KP_NAME $KP_FIN
	make KP_NUM=$KP_NUM KP_NAME=$KP_NAME KP_FIN=$KP_FIN kp_prog
	(( KP_NUM++ ))
done < $KP_FUNCS

make kpload
sudo ./kpload

sudo bpftool map update id 1 key 00 00 00 00 value 00 00 00 00 00 00 00 00
