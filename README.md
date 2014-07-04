Welcome to StealthInject
=======================

This is the source code page for the **StealthInject**.  With the source code, you can modify the tool in any way imaginable and share your changes with others!

Source releases
---------------

We recommend you work with a versioned release. The master branch contains unstable and possibly untested code, but it should be a great reference for new developments, or for spot merging bug fixes. Use it at your own risk.  

Getting up and running
----------------------

Here is the fun part!  This is a quick start guide to getting up and running with the source.  The steps below will take you through cloning your own private fork, then compiling and 
running the editor yourself on Windows other platforms will be implemented at a later point in time.  Okay, here we go!

1. We recommend using Git in order to participate in the community, but you can **download the source** as a zip file if you prefer. See instructions for 
   [setting up Git](http://help.github.com/articles/set-up-git), then [fork our repository](https://help.github.com/articles/fork-a-repo), clone it to your local machine.
   
2. You should now have an **StealthInject** folder on your computer.  All of the source and dependencies will go into this folder.  The folder name might have a branch suffix, but that's fine.

3. Okay, platform stuff comes next.  Depending on whether you are on Windows or another platform, follow one of the sections below.

## Windows

5. Be sure to have [Visual Studio 2013](http://www.microsoft.com/en-us/download/details.aspx?id=40787) installed.  You can use any 
   desktop version of Visual Studio 2013, including the free version:  [Visual Studio 2013 Express for Windows Desktop](http://www.microsoft.com/en-us/download/details.aspx?id=40787)

6. Load the project into Visual Studio by double-clicking on the **StealthInject.sln** file.

7. It's time to **compile the editor**!  In Visual Studio, make sure your solution configuration is set to **Release**, and your solution 
   platform is set to **x64** or **Win32** depending on your needs. Locate and click **Build** in your toolbar. A new menu should open allowing you to click *Build solution**

8. After compiling finishes the program is ready to use!

### Additional target platforms

Currently not supported.

Usage
-----

The **StealthInject** program consists out of a DLL which should be invoked using [HookFunction](https://git.koenj.com/koenj/hookfunction). The executable will inject the DLL into the remote process and invoke the python functions. **StealthInject** is made to hook arbitrary functions using simple python scripts and it allows for easy proxy function injection. Currently the hooking of any **cdecl**, **thiscall** and **stdcall** function is supported.

Example
-------

The following command will hook a function in the program **InterceptMe.exe** at the relative virtual address **0x11177**. This relative virtual address indicates the address of the **RC4** cryptography function. The next parameter is the full path to the DLL containing the proxy function. The next parameter is the name of the function we want to invoke in **StealthInject.DLL**. Therefore this parameter will always be **PythonHook**. The next parameter contains the name of the python function to invoke. In this case the name is **ProxyRC4**. The last two parameters indicate the declaration specification (cdecl, stdcall, thiscall) and the amount of parameters. The python script is expected to be named **Hooks.py** and it should be located in the working directory of the executable you want to inject in. The full command is shown below:

```
HookFunction InterceptMe.exe 0x11177 "D:\Projects\Werk\StealthInject\bin\x86\StealthInject.DLL" PythonHook ProxyRC4 cdecl 5
```

An example proxy python script is shown below:

```python
import StealthInject

def ProxyRC4(input, inputLength, key, keyLength, output):
    print("RC4(%08X, %i, %08X, %i, %08X)" % (input, inputLength, key, keyLength, output))

    StealthInject.CallOriginalFunction(input, inputLength, key, keyLength, output)
```

Every time the **RC4** function in the program will be invoked our program will intercept the code flow. This allows us to do tampering before encryption and after decryption. When invoking the command this way python will assume all parameters to be integers. There is an additional parameter which will allow us to specify the types allowing for easier tampering. The full command is shown below:


```
HookFunction InterceptMe.exe 0x11177 "X:\...\StealthInject.DLL" PythonHook ProxyRC4 cdecl 5 sisii
```

An example proxy python script is shown below:

```python
import StealthInject

def ProxyRC4(input, inputLength, key, keyLength, output):
    print("RC4(%s, %i, %s, %i, %08X)" % (input, inputLength, key, keyLength, output))

    #Tampering the data to be encrypted to be "GAAPEN".
    StealthInject.CallOriginalFunction("GAAPEN", 6, key, keyLength, output)
```

The types for the format string `sisii` are as follows:
- b - char
- B - unsigned char
- h - short int
- H - unsigned short int
- i - int
- I - unsigned int
- l - long
- k - unsigned long
- f - float
- s - UTF-8 string
- u - unicode string
- y - bytes

Added python functions
----------------------

The following python functions have been added:


|     Function name    |           Parameters           |                Description              |                Return Value              |
| -------------------- | ------------------------------ | --------------------------------------- | ---------------------------------------- |
| WriteMemoryInteger   | integer address, integer value | Write an integer to a memory location.  | Returns 1 on success.                    |
| ReadMemoryInteger    | integer address                | Read an integer from a memory location. | Return value on success.                 |
| WriteMemoryByte      | integer address, byte value    | Write an byte to a memory location.     | Returns 1 on success.                    |
| ReadMemoryByte       | integer address                | Read an byte from a memory location.    | Return value on success.                 |
| WriteMemoryString    | integer address, string value  | Write a string to a memory location.    | Returns 1 on success.                    |
| ReadMemoryString     | integer address                | Read a string from a memory location.   | Return value on success.                 |
| CallOriginalFunction | original parameters (variable) | Call the original function.             | Return result of call on success else 0. |

Additional Notes
----------------

Visual Studio 2013 is strongly recommended for compiling.

The first time you start the editor from a fresh source build, you may experience long load times.  This only happens on the first run.