# Exercise 1 - Basic Shellcode Loader

## Description
Use `msfvenom` to generate some shellcode, and write a basic loader that executes it in the current process.

## Tips

This exercise is throwing you in the deep end by design! If you are lost, start by looking at some open-source examples, then try to replicate what they are doing yourself.

> ℹ **Note:** It may be tempting to copy and paste whole examples, but this is not advisable for several reasons:
>
> 1. You learn better by applying the techniques yourself
> 2. Public code is often fingerprinted, doing it your own way will help with evasion
> 3. Some repositories may include malicious code (e.g. bad shellcode) that you may accidentally execute

### msfvenom

With `msfvenom`, you can choose a 'format' (`-f`) to get the bytes as the right format for your language. It has formatters for most languages, which you can verify by running `--list formats`. Relevant formats here are `-f csharp`, `-f nim`, `-f go`, or `-f rust`, but there are others. Here's an example command which generates some shellcode you can use to pop a messagebox (works well as a proof-of-concept!):

```bash
msfvenom -p windows/x64/messagebox TEXT='Task failed successfully!' TITLE='Error!' -f nim
```

### Windows API combinations

Remember the various API calls you can use. There are two combinations that make the most sense for this exercise:

- [copy memory] + `VirtualProtect()` + `CreateThread()`
 
    This is the most straightforward way to get your shellcode to execute. Because the shellcode is already placed in memory the moment you define a variable, you can "skip" the first step and just target the variable with your shellcode with the `VirtualProtect()` call to make it executable. After that, you can use `CreateThread()` to execute the shellcode (or cast a pointer, see below).

- `VirtualAlloc()` + copy memory + `CreateThread()`
 
    This is an alternative to the above, another very popular way of executing shellcode. You can use `VirtualAlloc()` to allocate an executable memory region for the shellcode, and then copy your shellcode into the allocated memory. The result is the same as the first method.

Copying memory can be done without API calls using built-in functions, like `Marshal.copy` for C#, `copyMem` for Nim, `std::ptr::copy` for Rust.

> ⚠ **Note:** Depending on the type of shellcode you are using, you may need to use the `WaitForSingleObject()` API to keep your program alive while it is running your shellcode. This is only required for long-running shellcodes, such as a CobaltStrike beacon.

> 😎 If you're feeling adventurous, you can use the native API (Nt-functions from `NTDLL.dll`) counterparts of these functions instead. See also [bonus exercise 1](../BONUS%20Exercise%201%20-%20Basic%20Loader%20Without%20CreateThread/). There are many more API functions to explore as well, for an overview check out [malapi.io](https://malapi.io/).

### Invoking the Windows API (C# only)

C# doesn't have native support for calling the Windows API, so you will have to define the API functions you want to use yourself. This is called P/Invoke. Luckily, most API functions and how to call them have been well documented, e.g. on [pinvoke.net](https://pinvoke.net/).

Alternatively, you may opt to dynamically resolve the function calls. While harder to implement, this is much more opsec-safe. The [D/Invoke library](https://github.com/TheWover/DInvoke) can be used to implement this.

### Casting pointers - an alternative to `CreateThread()`

Instead of using the `CreateThread()` API, you can use a technique called "casting a pointer" to turn your shellcode memory into a function and execute it in the current thread. You can see examples [here (C#)](https://tbhaxor.com/execute-unmanaged-code-via-c-pinvoke/), [here (Rust)](https://stackoverflow.com/a/46134764), and [here (Nim)](https://github.com/byt3bl33d3r/OffensiveNim/issues/16#issuecomment-757228116). This avoids calling a suspicious API function, but brings problems of its own (such as the thread hanging, or potential program crashes after your shellcode returns).

### Rust tips

There are several 'crates' (libraries) that you can use to call the Windows API from Rust. Microsoft maintains two official crates called [`windows`](https://microsoft.github.io/windows-docs-rs/) and [`windows-sys`](https://docs.rs/windows-sys), the former of which introduces some overhead but allows for more idiomatic programming in Rust, and the latter of which is essentially a library with raw function and type bindings. There are also third-party crates such as `winapi` which achieve essentially the same goal. You can play with the different crates to see which one you like best.

### Golang tips

The library `golang.org/x/sys/windows` is the official library of Golang that implements the Windows API. However, some unusual APIs that we are using in malware development may be missing from this library. For example, the `CreateThread` function is not available.

To implement this function in our code, we can use the `golang.org/x/sys/windows/mkwinsyscall` package to generate a file (usually [`zsyscall_windows.go`](https://github.com/golang/sys/blob/master/windows/zsyscall_windows.go) generated from [`syscall_windows.go`](https://github.com/golang/sys/blob/c0bba94af5f85fbad9f6dc2e04ed5b8fac9696cf/windows/syscall_windows.go#L168)) that will contain all our Windows APIs implemented in Golang.

To generate the right input line for `mkwinsyscall`, we need to get the syntax of the function. Fortunately, this one is documented on [Microsoft](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread):
```
HANDLE CreateThread(
  [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  [in]            SIZE_T                  dwStackSize,
  [in]            LPTHREAD_START_ROUTINE  lpStartAddress,
  [in, optional]  __drv_aliasesMem LPVOID lpParameter,
  [in]            DWORD                   dwCreationFlags,
  [out, optional] LPDWORD                 lpThreadId
);
```

The corresponding line for `mkwinsyscall` is the following

```golang
//sys   CreateThread(lpThreadAttributes *SecurityAttributes, dwStackSize uint32, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags uint32, lpThreadId *uint32)(threadHandle windows.Handle, err error) = kernel32.CreateThread
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

These steps can be time-consuming, but meanwhile the windows package is updated you can find several of the API already implemented in the [go-windows](https://github.com/nodauf/go-windows) repository.


## References

### C#

- [Execute Unmanaged Code via C# P/Invoke](https://tbhaxor.com/execute-unmanaged-code-via-c-pinvoke/)
- [Offensive P/Invoke: Leveraging the Win32 API from Managed Code](https://posts.specterops.io/offensive-p-invoke-leveraging-the-win32-api-from-managed-code-7eef4fdef16d)
- [x64ShellcodeLoader.cs](https://gist.github.com/matterpreter/03e2bd3cf8b26d57044f3b494e73bbea)

### Golang

- [CreateThread/main.go](https://github.com/Ne0nd0g/go-shellcode/blob/master/cmd/CreateThread/main.go)

### Nim

- [shellcode_loader.nim](https://github.com/sh3d0ww01f/nim_shellloader/blob/master/shellcode_loader.nim)
- [Shellcode execution in same thread](https://github.com/byt3bl33d3r/OffensiveNim/issues/16#issuecomment-757228116)

### Rust

- [Shellcode_Local_Inject](https://github.com/trickster0/OffensiveRust/blob/master/Shellcode_Local_inject/src/main.rs)
- [Process_Injection_Self_EnumSystemGeoID](https://github.com/trickster0/OffensiveRust/blob/master/Process_Injection_Self_EnumSystemGeoID/src/main.rs)

## Solution

Example solutions are provided in the [solutions folder](solutions/). Keep in mind that there is no "right" answer, if you made it work that's a valid solution! 