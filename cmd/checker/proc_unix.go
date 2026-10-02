//go:build !windows

package main

import "syscall"

func sysProcAttrUnix() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

func sysProcAttrWindows() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}
