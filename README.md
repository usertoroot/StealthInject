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

The **StealthInject** program allows you to inject a DLL into a process without using library loading function calls. This also means that the DLL will remain unlisted in the module list.

Example
-------

The following command will stealthily inject TestDll.dll into the program **InterceptMe.exe**. The full command is shown below:

```
StealthInject "C:\TestDll.dll" InterceptMe.exe
```

Additional Notes
----------------

Visual Studio 2013 is strongly recommended for compiling.

The first time you start the editor from a fresh source build, you may experience long load times.  This only happens on the first run.