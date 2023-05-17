# Malware Development for Dummies

*In the age of EDR, red team operators cannot get away with using pre-compiled payloads anymore. As such, malware development is becoming a vital skill for any operator. Getting started with maldev may seem daunting, but is actually very easy. This workshop will show you all you need to get started!*

This repository contains the slides and accompanying exercises for the 'MalDev for Dummies' workshop that has been/will be facilitated at Hack in Paris 2022 and X33fcon 2023. Although the slides were designed to be presented 'in-person', the materials and exercises will remain available here to be completed at your own pace - the learning process should never be rushed! Issues and pull requests to this repo with questions and/or suggestions are welcomed.

> ⚠ **Disclaimer:** Malware development is a skill that can -and should- be used for good, to further the field of (offensive) security and keep our defenses sharp. If you ever use this skillset to perform activities that you have no authorization for, you are a bigger dummy than this workshop is intended for and you should skidaddle on out of here.

## Workshop Description

With antivirus (AV) and Enterprise Detection and Response (EDR) tooling becoming more mature by the minute, the red team is being forced to stay ahead of the curve. Gone are the times of `execute-assembly` and dropping unmodified payloads on disk - if you want your engagements to last longer than a week you will have to step up your payload creation and malware development game. Starting out in this field can be daunting however, and finding the right resources is not always easy.

This workshop is aimed at beginners in the space and will guide you through your first steps as a malware developer. It is aimed primarily at offensive practitioners, but defensive practitioners are also very welcome to attend and broaden their skillset. 

During the workshop we will go over some theory, after which we will set you up with a lab environment. There will be various exercises that you can complete depending on your current skillset and level of comfort with the subject. However, the aim of the workshop is to learn, and explicitly *not* to complete all the exercises. You are free to choose your preferred programming language for malware development, but support during the workshop is provided primarily for the C# and Nim programming languages.

During the workshop, we will discuss the key topics required to get started with building your own malware. This includes (but is not limited to):
- The Windows API
- Filetypes and execution methods
- Shellcode execution and injection
- AV and EDR evasion methods

## Getting Started

To get started with malware development, you will need a dev machine so that you are not bothered by any defensive tooling that may run on your host machine. I prefer Windows for development, but Linux or MacOS will do just as fine. Install your editor/IDE of choice (I use [VS Code](https://code.visualstudio.com/) for almost everything except C#, for which I use [Visual Studio](https://visualstudio.microsoft.com/vs/community/), and then install the toolchains required for your MalDev language of choice:

- **C#**: Visual Studio will give you the option to include the .NET packages you will need to develop C#. If you want to develop without Visual Studio, you can download the [.NET Framework](https://dotnet.microsoft.com/en-us/download/dotnet-framework) separately.
- **Nim lang**: Follow the [download instructions](https://nim-lang.org/install.html). [Choosenim](https://github.com/dom96/choosenim) is a convenient utility that can be used to automate the installation process.
- **Golang** (thanks to @nodauf for the PR): Follow the [download instructions](https://go.dev/doc/install).
- **Rust**: [Rustup](https://www.rust-lang.org/tools/install) can be used to install Rust along with the required toolchains. 

Don't forget to disable Windows Defender or add the appropriate exclusions, so your hard work doesn't get quarantined! Later on, we can test on a separate machine with defensive controls like AV enabled.

> ℹ **Note:** Oftentimes, package managers such as apt or software management tools such as Chocolatey or Winget (now built-in!) can be used to automate the installation and management of dependencies in a convenient and repeatable way. Be conscious however that versions in package managers may be a couple versions behind on the real thing! Below is an example command to install the mentioned tooling all at once.
>
> ```
>  choco install -y nim choosenim go rust vscode visualstudio2019community dotnetfx
> ```

## Compiling programs

The languages that we will discuss during this workshop are *compiled* languages, meaning that a compiler is used to translate your source code into binary executables of your chosen format. The process of compilation differs per language. 

### C#

C# code (`.cs` files) can either be compiled directly (with the `csc` utility) or via Visual Studio itself. Most source code in this repo (except the solution to [bonus exercise 3](./Exercises/BONUS%20Exercise%203%20-%20Basic%20EDR%20Evasion/solutions/csharp/)) can be compiled as follows.

> ℹ **Note:** Make sure you run the below command in a "Visual Studio Developer Command Prompt" so it knows where to find `csc`, it is recommended to use the "x64 Native Tools Command Prompt" for your version of Visual Studio. The `/unsafe` flag will be required for most scripts where we access low-level functionality directly.

```
csc filename.exe
```

You can enable compile-time optimizations with the `/optimize` flag. You can hide the console window by adding `/target:winexe` as well, or compile as DLL with `/target:library` (but make sure your code structure is suitable for this).

### Nim

Nim code (`.nim` files) is compiled with the `nim c` command. The source code in this repo can be compiled as follows.

```
nim c filename.nim
```

If you want to optimize your build for size and strip debug information (much better for opsec!), you can add the following flags.

```
nim c -d:release -d:strip --opt:size filename.nim
```

Optionally you can hide the console window by adding `--app:gui` as well.

### Golang

Golang code (`.go` files) is compiled with the `go build` command. The source code in this repo can be compiled as follows.

```
GOOS=windows go build
```

If you want to optimize your build for size and strip debug information (much better for opsec!), you can add the following flags.

```
GOOS=windows go build -ldflags "-s -w"
```

### Rust

Rust code (`.rs` files) is compiled via the the `cargo` command. [Cargo](https://doc.rust-lang.org/cargo/guide) can be used to manage your dependencies and build your project. The source code in this repo can be compiled by navigating to the project folder and running the following command.

```
cargo build
```

If you want to optimize your build for size and strip debug information, you can add the following flags. Refer also to the `[profile.release]` section in each `Cargo.toml` file for some compile-time opsec options.

```
cargo build --release
```

## Dependencies

### C#

Most solutions can be compiled without dependencies. In case dependencies are required, a Visual Studio project is provided that links to the appropriate NuGet packages.

### Nim

Most Nim programs depend on a library called "Winim" to interface with the Windows API. You can install the library with the `Nimble` package manager as follows (after installing Nim):

```
nimble install winim
```

### Golang

Some dependencies are used in the source code of this repo. You can install them as follows (after installing Go):

```
go mod tidy
```

### Rust

Some examples depend on the `windows-sys` crate to call the Windows API. Since we are using Cargo, packages will be automatically managed when you compile a test or release build.

## Resources

The workshop slides reference some resources that you can use to get started. Additional resources, such as relevant blogs or code snippets, are listed in the `README.md` files for each exercise!
