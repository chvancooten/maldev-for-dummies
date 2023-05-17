# Bonus Exercise 2 - Basic Injector With Dynamic Target

## Description

Modify your injector from [Exercise 2](../Exercise%202%20-%20Basic%20Shellcode%20Injector/) such that the target process is configurable, and the program spawns the process if it does not exist already.

## Tips

This is a programming exercise more than anything else. Adding functionality like this is a great way to get better acquainted with chosen programming language! The injector program should prompt the user for a process name via the command line, and resolve that name into a process ID (look into the `CreateToolhelp32Snapshot()` API) if needed, spawning the process if it does not yet exist (for the purposes of this exercise, you may assume that the binary will exist in the user's path). Then, the injector should use this process as a target for injection as before.

## References

### C#

- [C# User Input](https://www.w3schools.com/cs/cs_user_input.php)
- [Process.GetProcessesByName() function](https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.process.getprocessesbyname)

### Golang

- [fmt.Scanln](https://pkg.go.dev/fmt#Scanln)

### Nim

- [commandLineParams](https://nim-lang.org/docs/os.html#commandLineParams)
- [minidump_bin.nim](https://github.com/byt3bl33d3r/OffensiveNim/blob/965c44cec96575758eaa42622f699b6ea0d1041a/src/minidump_bin.nim#L36-L48)

### Rust

- [std::io::Stdin::read_line()](https://doc.rust-lang.org/stable/std/io/struct.Stdin.html#method.read_line)
- [An example implementation of user input in srdi-rs/inject](https://github.com/trickster0/OffensiveRust/blob/master/memN0ps/srdi-rs/inject/src/main.rs#L115-L119)

## Solution

Example solutions are provided in the [solutions folder](solutions/). Keep in mind that there is no "right" answer, if you made it work that's a valid solution! 