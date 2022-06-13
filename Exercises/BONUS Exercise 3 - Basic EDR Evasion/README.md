# Bonus Exercise 4 - Basic Enterprise Detection and Response Evasion

## Description

Modify your loader or injector from any of the previous exercises, such that it implements one or more of the mentioned EDR evasion techniques. Test it against EDR if you are able.

## Tips

Remember that EDR looks at the behavior of your malware, and collects telemetry from a variety of sources. This means that you can either focus on avoiding EDR, disguising your malware to be "legitimate enough" not to be detected (hard to do for shellcode injection, unfortunately), finding EDR blind spots, or actively tamper with EDR telemetry collection. A lot of EDR bypasses (such as unhooking or ETW patching) are focused on the latter of these options. The 'References' section contains some nice pointers that include considerations for choosing your preferred EDR bypass method.

### Tips for testing

Getting access to a commercial EDR is not easy for everyone. A good way to test against a (partially) free EDR is [Elastic Endpoint Security](https://www.elastic.co/security/endpoint-security/). Alternatively, you could try free trials of commercial software. Some AV, such as BitDefender, also do API hooking for an "EDR-like" experience.

## References

- [Blinding EDR On Windows](https://synzack.github.io/Blinding-EDR-On-Windows/)
- [A tale of EDR bypass methods](https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/)
- [Lets Create An EDR… And Bypass It!](https://ethicalchaos.dev/2020/05/27/lets-create-an-edr-and-bypass-it-part-1/)

Refer to [Exercise 3](../Exercise%203%20-%20Basic%20AV%20Evasion/) for more references.

## Solution

Example solutions are provided in the [solutions folder](solutions/) ([C#](solutions/csharp/), [Nim](solutions/nim/)). Keep in mind that there is no "right" answer, if you made it work that's a valid solution! 