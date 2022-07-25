# Exercise 2 - Basic Shellcode Injector

## Description

Create a new project that injects your shellcode in a remote process, such as `explorer.exe`.

## Tips

This exercise is actually very similar to [Exercise 1](../Exercise%201%20-%20Basic%20Shellcode%20Loader/) in terms of implementation. The basic approach is comparable to the `VirtualAlloc()` method we saw there, except this time we are using a different API combination: `OpenProcess()` to get a handle on the target process, `VirtualAllocEx()` to allocate executable memory in the remote process, `WriteProcessMemory()` to copy the shellcode into the allocated, and `CreateRemoteThread()` to execute the shellcode as part of the target process.

> 😎 If you're feeling adventurous, you can use the native API (Nt-functions from `NTDLL.dll`) counterparts of these functions instead. Alternatively, look at other ways to expose your shellcode to the target process' memory, such as `NtCreateSection()` and `NtMapViewOfSection()` (example [here](https://www.ired.team/offensive-security/code-injection-process-injection/ntcreatesection-+-ntmapviewofsection-code-injection)).

### Getting a handle

Keep in mind that in order to get a handle, we need to have sufficient privileges over the target process. This generally means that you can only get a handle for a process owned by the current user, and not those owned by other users or managed by the system itself (makes sense right?). However, if you are executing from a privileged context (i.e. running as `SYSTEM` or with the `SeDebugPrivilege` enabled) you can get a handle to any process, including system processes. 

When designing malware that injects remotely, you need to be conscious about the target process that you choose. Choosing the wrong process may cause your malware to fail because the process is not present, or you have insufficient privileges. Furthermore, injecting from a privileged context into a low-privileged process will drop your privileges.

> ℹ **Note:** This is why making the target process configurable and basing it on the target environment is a good idea. You may hardcode the name or process ID of `explorer.exe` for now, we will improve that functionality in [bonus exercise 2](../BONUS%20Exercise%202%20-%20Basic%20Injector%20With%20Dynamic%20Target/).

### Golang tips

The library `golang.org/x/sys/windows` is the official library of Golang that implements the Windows API. However, some unusual APIs that we are using in malware development may be missing from this library. For example, the `VirtualAllocEx` or `CreateRemoteThread` functions are not available.

To implement these functions in our code, we can use the `golang.org/x/sys/windows/mkwinsyscall` package to generate a file (usually [`zsyscall_windows.go`](https://github.com/golang/sys/blob/master/windows/zsyscall_windows.go) generated from [`syscall_windows.go`](https://github.com/golang/sys/blob/c0bba94af5f85fbad9f6dc2e04ed5b8fac9696cf/windows/syscall_windows.go#L168)) that will contain all our Windows APIs implemented in Golang.

To generate the right input line for `mkwinsyscall`, we need to get the syntax of the function. Fortunately, this one is documented on [Microsoft](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethreadex):
```
HANDLE CreateRemoteThread(
  [in]  HANDLE                 hProcess,
  [in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  [in]  SIZE_T                 dwStackSize,
  [in]  LPTHREAD_START_ROUTINE lpStartAddress,
  [in]  LPVOID                 lpParameter,
  [in]  DWORD                  dwCreationFlags,
  [out] LPDWORD                lpThreadId
);
```

The corresponding line for `mkwinsyscall` is the following

```golang
//sys	CreateRemoteThread(process Handle, threadAttributes *SecurityAttributes, stackSize uintptr, startAddress uintptr, lpParameter uintptr, dwCreationFlags uint32, lpThreadId *uint32) (threadHandle windows.Handle, err error) = kernel32.CreateRemoteThread
```

This is basically the prototype of the function with at the end the location of the function in the Windows API, in our case `kernel32.CreateRemoteThread`.
The tricky part is to translate each `C` type into a Golang type. To simplify the process, you can look at the existing lines in Windows package and if something is wrong debug with a tool like [APIMonitor](https://apimonitor.com/) and compare with a working call of the API.

Finally, make sure to add the following line in `syscall_windows.go`
```golang
//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go syscall_windows.go
```

And then, the file `zsyscall_windows.go` can be generated with:
```bash
go generate syscall_windows.go
```

These steps can be time-consuming, but meanwhile the windows package is updated you can find several of the API already implemented in the [go-windows](https://github.com/nodauf/go-windows) repository


## References

### C#

- [A simple Windows code injection example written in C#](https://andreafortuna.org/2019/03/06/a-simple-windows-code-injection-example-written-in-c/)

### Nim

- [shellcode_bin.nim](https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/shellcode_bin.nim)

## Solution

Example solutions are provided in the [solutions folder](solutions/) ([C#](solutions/csharp/), [Nim](solutions/nim/)). Keep in mind that there is no "right" answer, if you made it work that's a valid solution! 