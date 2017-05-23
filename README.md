# ltmdm64_poc

# Windows 7 SP1 x64 Code Integrity Bypass POC using ltmdm64.sys

# Description

Bug was found in ltmdm64.sys!DriverEntry driver incorrectly uses RtlQueryRegistryValues API it also lacks security cookies across entire binary except GsDriverEntry function.

This PoC was created back in 2014 and submitted later in 2015 to MSRC they were not able to located the driver authors but also didn't take any action on fixing the problem.

ltmdm64.sys is shipped since Windows Vista and present in digitally signed catalog files.

This PoC is detected by Windows Defender as Exploit:Win64/Ropero.A

# Usage

1) Compile PoC
2) Run compiled binary ( see example.jpg )
3) Load vulnerable driver ( drv_install_and_start.cmd )
4) Enjoy patched g_CiEnabled now you can load unsigned drivers

