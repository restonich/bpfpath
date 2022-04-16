#!/bin/bash
set -e

TESTDIR="/home/mkov/testing"
:> $TESTDIR/iperf.log

echo -ne "STARTING IPERF SERVER -- "
ip netns exec iperf_ns iperf3 -s -B 10.4.21.2 -p 1337 -F $TESTDIR/iperf.file --logfile $TESTDIR/iperf.log -D -I $TESTDIR/iperf.pid
echo -ne "OK\n"

echo -ne "\n================\n" 
echo -ne "CLEAR RUN\n"
echo -ne "================\n" 
for i in {1..3}; do
	echo -ne "\nCYCLE ${i}\n"
	echo -ne "----------------\n" 

	echo -ne "STARTING SAR -- "
	sar -o $TESTDIR/clean_sar${i}.root 1 60 >/dev/null 2>&1 &
	ip netns exec iperf_ns sar -o $TESTDIR/clean_sar${i}.iperf_ns 1 60 >/dev/null 2>&1 &
	echo -ne "OK\n"

	sleep 10

	echo -ne "STARTING IPERF CLIENT\n"
	ssh -i /home/mkov/.ssh/id_rsa mkov@10.4.20.11 -t 'iperf3 -p 1337 -i 0 -t 30 -c 10.4.21.2'

	sleep 25
done

echo -ne "\n================\n" 
echo -ne "BPF RUN\n"
echo -ne "================\n" 
for i in {1..3}; do
	echo -ne "\nCYCLE ${i}\n"
	echo -ne "----------------\n" 

	echo -ne "STARTING SAR -- "
	sar -o $TESTDIR/bpf_sar${i}.root 1 60 >/dev/null 2>&1 &
	ip netns exec iperf_ns sar -o $TESTDIR/bpf_sar${i}.iperf_ns 1 60 >/dev/null 2>&1 &
	echo -ne "OK\n"

	sleep 10

	echo -ne "STARTING BPF -- "
	/home/mkov/proj/bpfpath/main.py --link ens34 --proto tcp --dst 10.4.21.2 --port 1337 -i 1 -t 40 &>$TESTDIR/bpfpath${i}.out &
	echo -ne "OK\n"

	sleep 5

	echo -ne "STARTING IPERF CLIENT\n"
	ssh -i /home/mkov/.ssh/id_rsa mkov@10.4.20.11 -t 'iperf3 -p 1337 -i 0 -t 30 -c 10.4.21.2'

	sleep 20
done

echo -ne "\nKILLING IPERF SERVER\n"
kill -15 $(cat $TESTDIR/iperf.pid)
echo -ne "OK\n"

