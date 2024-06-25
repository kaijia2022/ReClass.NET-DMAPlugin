# ReClass.NET-DMAPlugin
A plugin for ReClass.Net that enables memory input from DMA physical memory acquisition device. Only memory read feature is enabled, but can be extended to allow memory write and live debugging. 

## Installation
- Compile or download from [release]()
- Copy `DMAPlugin.dll` and `vmmsharp.exe` into the Plugin folder (ReClass.NET/x64/Plugins)
- Download the latest [MemProcFS release](https://github.com/ufrisk/MemProcFS/releases)
- Download `FTD3XX.dll` in the [Requirement](https://github.com/ufrisk/LeechCore/wiki/Device_FPGA) section
- Place `leechcore.dll`, `vmm.dll` and `FTD3XX.dll` alongside `DMAPlugin.dll` and `vmmsharp.exe` in the Plugin folder.
- Download the latest [ReClass.NET release](https://github.com/ReClassNET/ReClass.NET/releases/)
- Start ReClass.NET and check the plugins form if the DMA plugin is listed. Open the "Native Helper" tab and switch Function Provider to "DMA".
## Compiling
1. Clone this Repository
2. Clone [MemProcFS](https://github.com/ufrisk/MemProcFS) by [ufrisk](https://github.com/ufrisk)
3. Clone [ReClass.Net](https://github.com/ReClassNET/ReClass.NET) by [KN4CK3R](https://github.com/KN4CK3R)
4. Create the following folder structure

```
..\ReClass.NET\
..\ReClass.NET\ReClass.NET\ReClass.NET.csproj
..\ReClass.NET-DMAPlugin
..\ReClass.NET-DMAPlugin\DMAPlugin.csproj
..\MemProcFS\
..\MemProcFS\vmmsharp\
..\MemProcFS\memprocfs\memprocfs.vcxproj
```
## Known Issues
- Icon and Path are not supported in the Process Browser form
- Due to dependencies to `vmm.dll` and `leechcore.dll`, the plugin is x64 only.
