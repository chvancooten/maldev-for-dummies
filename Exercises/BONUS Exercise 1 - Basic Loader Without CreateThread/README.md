# Bonus Exercise 1 - Basic Loader Without CreateThread

## Description

Modify your loader from [Exercise 1](../Exercise%201%20-%20Basic%20Shellcode%20Loader/) so that it executes shellcode without calling `CreateThread()`.

## Tips

We discussed some loading methods in the slides and [Exercise 1](../BONUS%20Exercise%201%20-%20Basic%20Loader%20Without%20CreateThread/). To get rid of the `CreateThread()` API call we can either use the technique of "casting a pointer", or we can use the native API `NtCreateThreadEx()` to create our thread instead.

> ℹ **Note:** You may wonder why we used `NtCreateThreadEx()` instead of `NtCreateThread()` for local execution. The answer is that `NtCreateThreadEx()` is much simpler to use: the `NtCreateThread()` function requires us to initialize a full 'Thread Information Block' (TIB) before we can call it, and the `NtCreateThreadEx()` variant does not.

There are plenty of alternatives to the above. Check out [malapi.io](https://malapi.io/) for an excellent overview of Windows API functions that can be used maliciously. Especially the 'Injection' section is relevant here!

> 😎 If you're feeling adventurous, use this opportunity to completely get rid of all high-level API calls and use only the native API. It's harder to write, but using this API will definitely become a vital skill when looking at EDR evasion later on.

## References

Refer to [Exercise 1](../BONUS%20Exercise%201%20-%20Basic%20Loader%20Without%20CreateThread/).

## Solution

Example solutions are provided in the [solutions folder](solutions/). Keep in mind that there is no "right" answer, if you made it work that's a valid solution! 