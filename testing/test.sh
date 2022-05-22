#!/bin/bash
set -e

TESTDIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]:-$0}"; )" &> /dev/null && pwd 2> /dev/null; )";
LOGDIR=$TESTDIR/logs
[ -d $LOGDIR ] || mkdir $LOGDIR

:> $LOGDIR/iperf.log

echo -ne "STARTING IPERF SERVER -- "
ip netns exec iperf_ns iperf3 -s -B 10.4.21.2 -p 1337 -F $LOGDIR/iperf.file --logfile $LOGDIR/iperf.log -D -I $LOGDIR/iperf.pid
echo -ne "OK\n"

echo -ne "\n================\n" 
echo -ne "CLEAR RUN\n"
echo -ne "================\n" 
for i in {1..100}; do
	echo -ne "\nCYCLE ${i}\n"
	echo -ne "----------------\n" 

	echo -ne "STARTING SAR -- "
	sar -o $LOGDIR/clean_sar${i}.root 1 20 >/dev/null 2>&1 &
	echo -ne "OK\n"

	sleep 4

	echo -ne "STARTING IPERF CLIENT\n"
	ssh -i /home/mkov/.ssh/id_rsa mkov@10.4.20.11 -t 'iperf3 -p 1337 -i 0 -t 14 -c 10.4.21.2'

	sleep 2
done

echo -ne "\n================\n" 
echo -ne "BPF RUN\n"
echo -ne "================\n" 
for i in {1..100}; do
	echo -ne "\nCYCLE ${i}\n"
	echo -ne "----------------\n" 

	echo -ne "STARTING SAR -- "
	sar -o $LOGDIR/bpf_sar${i}.root 1 20 >/dev/null 2>&1 &
	echo -ne "OK\n"

	sleep 4

	echo -ne "STARTING BPF -- "
	/home/mkov/proj/bpfpath/bpfpath.py --link ens34 --proto tcp --dst 10.4.21.2 --port 1337 -i 1 -t 15 &>$LOGDIR/bpfpath${i}.out &
	echo -ne "OK\n"

	echo -ne "STARTING IPERF CLIENT\n"
	ssh -i /home/mkov/.ssh/id_rsa mkov@10.4.20.11 -t 'iperf3 -p 1337 -i 0 -t 14 -c 10.4.21.2'

	sleep 2
done

echo -ne "\nKILLING IPERF SERVER\n"
kill -15 $(tr -d '\0' <$LOGDIR/iperf.pid)
echo -ne "OK\n"
