#!/usr/bin/python

import os

from bcc import BPF

WORK_DIR=os.path.dirname(os.path.abspath(__file__))

def kp_attach(bpf_obj):
	kprobes = []
	with open(WORK_DIR + '/kprobes.list', 'r') as kprobes_list:
		for line in kprobes_list:
			line = line.rstrip()
			if line != '' and line[0] != '#':
				kprobes.append(line)

	arg1_idx = kprobes.index(':arg1:')
	arg2_idx = kprobes.index(':arg2:')
	arg3_idx = kprobes.index(':arg3:')
	final_idx = kprobes.index(':final:')

	kprobes_arg1 = kprobes[(arg1_idx+1):arg2_idx]
	kprobes_arg2 = kprobes[(arg2_idx+1):arg3_idx]
	kprobes_arg3 = kprobes[(arg3_idx+1):final_idx]
	kprobes_final = kprobes[(final_idx+1):]

	# print("\narg1 probes:")
	# for k in kprobes_arg1:
	# 	print(k)
	# print("\narg2 probes:")
	# for k in kprobes_arg2:
	# 	print(k)
	# print("\narg3 probes:")
	# for k in kprobes_arg3:
	# 	print(k)
	# print("\nfinal probes:")
	# for k in kprobes_final:
	# 	print(k)

	for kprobe in kprobes_arg1:
		bpf_obj.attach_kprobe(event=kprobe, fn_name="probe_arg1")
	for kprobe in kprobes_arg2:
		bpf_obj.attach_kprobe(event=kprobe, fn_name="probe_arg2")
	for kprobe in kprobes_arg3:
		bpf_obj.attach_kprobe(event=kprobe, fn_name="probe_arg3")
	for kprobe in kprobes_final:
		bpf_obj.attach_kprobe(event=kprobe, fn_name="probe_final")
