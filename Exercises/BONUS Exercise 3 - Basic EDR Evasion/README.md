# Bonus Exercise 4 - Basic Enterprise Detection and Response Evasion

## Description

Modify your loader or injector from any of the previous exercises, such that it implements one or more of the mentioned EDR evasion techniques. Test it against EDR if you are able.

## Tips

Remember that EDR looks at the behavior of your malware, and collects telemetry from a variety of sources. This means that you can either focus on avoiding EDR, disguising your malware to be "legitimate enough" not to be detected (hard to do for shellcode injection, unfortunately), finding EDR blind spots, or actively tamper with EDR telemetry collection. A lot of EDR bypasses (such as unhooking or ETW patching) are focused on the latter of these options. The 'References' section contains some nice pointers that include considerations for choosing your preferred EDR bypass method.

### Tips for testing

Getting access to a commercial EDR is not easy for everyone. A good way to test against a (partially) free EDR is [Elastic Endpoint Security](https://www.elastic.co/security/endpoint-security/). Alternatively, you could try free trials of commercial software. Some AV, such as BitDefender, also do API hooking for an "EDR-like" experience.

### Golang tips

The solution in Golang implement direct syscalls thanks to the [`bananaPhone`](https://github.com/C-Sto/BananaPhone) package. This package implements, for now, two techniques to retrieve the syscall ID: Halo's gate and Hell's gate. There is two ways to use this package.

The first one is to get the syscall ID and call it directly.

```go
// Retrieve the syscall ID for NtAllocateVirtualMemory
alloc, err := bp.GetSysID("NtAllocateVirtualMemory")
...
// Call the syscall with the syscall ID and the arguments
_, err = bananaphone.Syscall(
		alloc, //ntallocatevirtualmemory
		thisThread,
		uintptr(unsafe.Pointer(&rPtr)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		uintptr(memCommit|memreserve),
		windows.PAGE_EXECUTE_READWRITE,
	)
...
```

Each argument of `bananaphone.Syscall` is an uintptr.

The second way is to use [`mkdirectwinsyscall`](https://github.com/C-Sto/BananaPhone/tree/master/cmd/mkdirectwinsyscall) to generate a syscall wrapper.
To generate the right input line for `mkdirectwinsyscall`, we need to get the syntax of the function. Fortunately, this one is documented on [Microsoft](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory):

```
__kernel_entry NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(
  [in]      HANDLE    ProcessHandle,
  [in, out] PVOID     *BaseAddress,
  [in]      ULONG_PTR ZeroBits,
  [in, out] PSIZE_T   RegionSize,
  [in]      ULONG     AllocationType,
  [in]      ULONG     Protect
);
```

The corresponding line for `mkwinsyscall` is the following

```golang
//dsys NtAllocateVirtualMemory(processHandle windows.Handle, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType uint64, protect uint64) (err error)
```

This is basically the prototype of the Golang function.
The tricky part is to translate each `C` type into a Golang type. To simplify the process, you can look at the existing lines in Windows package and if something is wrong debug with a tool like [APIMonitor](https://apimonitor.com/) and compare with a working call of the API.

Finally, make sure to add the following line in `syscall.go`
```golang
//go:generate go run github.com/C-Sto/BananaPhone/cmd/mkdirectwinsyscall -output zsyscall_windows.go syscall.go
```

And then, the file `zsyscall_windows.go` can be generated with:
```bash
go generate syscall.go
```

These steps can be time-consuming, but you can find several of the API already implemented in the [bananaWinSyscall](https://github.com/nodauf/bananaWinSyscall) repository.

## References

- [Blinding EDR On Windows](https://synzack.github.io/Blinding-EDR-On-Windows/)
- [A tale of EDR bypass methods](https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/)
- [Lets Create An EDR… And Bypass It!](https://ethicalchaos.dev/2020/05/27/lets-create-an-edr-and-bypass-it-part-1/)

Refer to [Exercise 3](../Exercise%203%20-%20Basic%20AV%20Evasion/) for more references.

## Solution

Example solutions are provided in the [solutions folder](solutions/) ([C#](solutions/csharp/), [Nim](solutions/nim/)). Keep in mind that there is no "right" answer, if you made it work that's a valid solution! 