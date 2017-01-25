package main

import "golang.org/x/sys/unix"

func disableTracing() error {
	const SUID_DUMP_DISABLE = 0
	return unix.Prctl(unix.PR_SET_DUMPABLE, SUID_DUMP_DISABLE, 0, 0, 0)
}
