using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Windows.Forms;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using ReClassNET.Core;
using ReClassNET.Debugger;
using ReClassNET.Extensions;
using ReClassNET.Memory;
using ReClassNET.Plugins;
using vmmsharp;
using System.Data;
using System.Runtime.InteropServices;
using ReClassNET.MemoryScanner;
using static vmmsharp.Vmm;
using static System.Collections.Specialized.BitVector32;
using ReClassNET.Forms;
using ReClassNET;

namespace DMAPlugin
{
    [Flags]
    public enum SectionCharacteristics : uint
    {
        IMAGE_SCN_MEM_EXECUTE = 0x20000000,
        IMAGE_SCN_MEM_READ = 0x40000000,
        IMAGE_SCN_MEM_WRITE = 0x80000000,
        IMAGE_SCN_MEM_DISCARDABLE = 0x02000000,
        IMAGE_SCN_MEM_NOT_CACHED = 0x04000000,
        IMAGE_SCN_MEM_NOT_PAGED = 0x08000000,
        IMAGE_SCN_CNT_CODE = 0x00000020,
        IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040,
        IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080,
    }

    public struct ProcessData
    {
        public uint Id { get; set; }
        public string Name { get; set; }
        public string Path { get; set; }

        public override string ToString()
        {
            return $"PID: {Id}, Name: {Name}, Path: {Path}";
        }

        public bool isValid()
        {
            return Id != 0 && Name != null;
        }
    }
    public class DMAPluginExt : Plugin, ICoreProcessFunctions
    {
        private readonly object sync = new object();

        private IPluginHost host;

        private ProcessBrowserForm procBrowser;

        private Vmm vmm;

        private ProcessData[] processList;

        private Vmm.MAP_MODULEENTRY[] mModule;

        public override bool Initialize(IPluginHost host)
        {
            Contract.Requires(host != null);

            this.host = host ?? throw new ArgumentNullException(nameof(host));

            host.Process.CoreFunctions.RegisterFunctions("DMA", this);

            vmm = new Vmm("", "-device","fpga");

            procBrowser = new ProcessBrowserForm(Program.Settings.LastProcess);

            return true;
        }

        public override void Terminate()
        {
            processList = null;

            host = null;

            vmm.Close();
        }

        private void FetchProcessListFromDMA()
        {
            uint[] dwPidList = vmm.PidList();
            processList = new ProcessData[dwPidList.Length];
            int i = 0;
            foreach (uint dwPid in dwPidList)
            {
                Vmm.PROCESS_INFORMATION procInfo = vmm.ProcessGetInformation(dwPid);
                ProcessData pd = new ProcessData();
                pd.Id = procInfo.dwPID;
                pd.Name = procInfo.szName;
                pd.Path = procInfo.szNameLong;
                processList[i++] = pd;
                
            }
        }
        public void EnumerateProcesses(EnumerateProcessCallback callbackProcess)
        {
            if (callbackProcess == null)
            {
                return;
            }

            FetchProcessListFromDMA();

            foreach (ProcessData process in processList)
            {
                if (process.isValid())
                {
                    var data = new EnumerateProcessData
                    {
                        Id = (IntPtr)process.Id,
                        Name = process.Name,
                        Path = process.Path
                    };

                    callbackProcess(ref data);
                }
                
            }

        }


        private bool EnumerateRemoteModules(IntPtr process, EnumerateRemoteModuleCallback callbackModule)
        {
            if(callbackModule == null)
            {
                return false;
            }
            mModule = vmm.Map_GetModule( (uint)process, false);

            if(mModule.Length == 0)
            {
                return false;
            }

            foreach (Vmm.MAP_MODULEENTRY module in mModule)
            {
                var data = new EnumerateRemoteModuleData
                {
                    BaseAddress = (IntPtr)module.vaBase,
                    Size = (IntPtr)module.cbImageSize,
                    Path = module.wszFullName
                };

                callbackModule(ref data);

            }
            return true;

        }

        private String VadMap_Protection(Vmm.MAP_VADENTRY pVad)
        {
            char[] protection = new char[6];
            byte vh = (byte)(pVad.Protection >> 3);
            byte vl = (byte)(pVad.Protection & 7);

            protection[0] = pVad.fPrivateMemory ? 'p' : '-';                           // PRIVATE MEMORY
            protection[1] = (vh & 2) != 0 ? ((vh & 1) != 0 ? 'm' : 'g') : ((vh & 1) != 0 ? 'n' : '-');  // -/NO_CACHE/GUARD/WRITECOMBINE
            protection[2] = (vl == 1 || vl == 3 || vl == 4 || vl == 6) ? 'r' : '-';    // READ
            protection[3] = (vl & 4) != 0 ? 'w' : '-';                                 // WRITE
            protection[4] = (vl & 2) != 0 ? 'x' : '-';                                 // EXECUTE
            protection[5] = (vl == 5 || vl == 7) ? 'c' : '-';                          // COPY ON WRITE

            if (protection[1] != '-' && protection[2] == '-' && protection[3] == '-' && protection[4] == '-' && protection[5] == '-')
            {
                protection[1] = '-';
            }

            return new string(protection);
        }

        /// <summary>Reports a single module and section for the loaded file.</summary>
		/// <param name="process">The process handle (in our case the process PID).</param>
		/// <param name="callbackSection">The callback which gets called for every section.</param>
		/// <param name="callbackModule">The callback which gets called for every module.</param>
        public void EnumerateRemoteSectionsAndModules(IntPtr process, EnumerateRemoteSectionCallback callbackSection, EnumerateRemoteModuleCallback callbackModule)
        {

            EnumerateRemoteModules(process, callbackModule);

            foreach (Vmm.MAP_MODULEENTRY module in mModule)
            {     
                Vmm.IMAGE_SECTION_HEADER[] SECTIONs = vmm.ProcessGetSections((uint)process, module.wszText);

                foreach (IMAGE_SECTION_HEADER SECTION in SECTIONs)
                {
                    var section = new EnumerateRemoteSectionData
                    {
                        BaseAddress = (IntPtr)(module.vaBase + SECTION.VirtualAddress),
                        Size = (IntPtr)SECTION.MiscPhysicalAddressOrVirtualSize,
                        Protection = SectionProtection.NoAccess,
                        Type = SectionType.Image,
                        ModulePath = module.wszText,
                        Name = SECTION.Name
                    };
                    SectionCharacteristics characteristics = (SectionCharacteristics)SECTION.Characteristics;

                    if (characteristics.HasFlag(SectionCharacteristics.IMAGE_SCN_MEM_READ))
                        section.Protection |= SectionProtection.Read;

                    if (characteristics.HasFlag(SectionCharacteristics.IMAGE_SCN_MEM_WRITE))
                        section.Protection |= SectionProtection.Write;

                    if (characteristics.HasFlag(SectionCharacteristics.IMAGE_SCN_MEM_EXECUTE))
                        section.Protection |= SectionProtection.Execute;

                    if (characteristics.HasFlag(SectionCharacteristics.IMAGE_SCN_CNT_CODE))
                        section.Category = SectionCategory.CODE;

                    if (characteristics.HasFlag(SectionCharacteristics.IMAGE_SCN_CNT_INITIALIZED_DATA))
                        section.Category = SectionCategory.DATA;

                    if (characteristics.HasFlag(SectionCharacteristics.IMAGE_SCN_CNT_UNINITIALIZED_DATA))
                        section.Category = SectionCategory.DATA;

                    callbackSection(ref section);

                }
            }

            Vmm.MAP_VADENTRY[] mVad = vmm.Map_GetVad((uint)process);

            foreach (MAP_VADENTRY vad in mVad)
            {
                if (vad.fImage)
                    continue;
                
                var section = new EnumerateRemoteSectionData
                {
                    BaseAddress = (IntPtr)vad.vaStart,
                    Size = (IntPtr)vad.cbSize,
                    Protection = SectionProtection.NoAccess,
                };
                if (vad.fFile)
                {
                    section.Type = SectionType.Mapped;
                    section.Category = SectionCategory.Unknown;
                }
                else if (vad.fHeap)
                {
                    section.Type = SectionType.Private;
                    section.Category = SectionCategory.HEAP;
                }
                else if (vad.fStack || vad.fPrivateMemory || vad.fTeb || vad.fPageFile)
                {
                    section.Type = SectionType.Private;
                    section.Category = SectionCategory.DATA;
                }
                else
                {
                    section.Type = SectionType.Private;
                    section.Category = SectionCategory.Unknown;
                }

                String protectionStr = VadMap_Protection(vad);
                if (protectionStr.Contains("p"))
                    section.Protection |= SectionProtection.NoAccess;
                
                if (protectionStr.Contains("g"))
                    section.Protection |= SectionProtection.Guard;
                
                if (protectionStr.Contains("r"))
                    section.Protection |= SectionProtection.Read;
                
                if (protectionStr.Contains("w"))
                    section.Protection |= SectionProtection.Write;
                
                if (protectionStr.Contains("x"))
                    section.Protection = SectionProtection.Execute;

                if(protectionStr.Contains("c"))
                    section.Protection = SectionProtection.CopyOnWrite;

                callbackSection(ref section);
            }

            /*Vmm.MAP_HEAP mHeap = vmm.Map_GetHeap( (uint)process);

            foreach (MAP_HEAPSEGMENTENTRY segment in mHeap.segments)
            {
                var section = new EnumerateRemoteSectionData
                {
                    BaseAddress = (IntPtr)segment.va,
                    Size = (IntPtr)segment.cb,
                    Protection = SectionProtection.NoAccess,
                    Type = SectionType.Private,
                    Category = SectionCategory.HEAP
                };
                uint tpHeapSegment = segment.tpHeapSegment;

                if (tpHeapSegment == 1 || tpHeapSegment == 2 || tpHeapSegment == 3 || tpHeapSegment == 5 || tpHeapSegment == 6 || tpHeapSegment == 7)
                    section.Protection |= SectionProtection.Read;

                callbackSection(ref section);
            }*/
            
        }
        /// <summary>Request a handle to the remote process (in our case, the handle is just the PID).</summary>
		/// <param name="pid">The process ID.</param>
		/// <param name="desiredAccess">access type (not needed).</param>
		/// <returns>the pid unchanged as the process handle.</returns>
        public IntPtr OpenRemoteProcess(IntPtr pid, ProcessAccess desiredAccess)
        {
            return pid;
        }

        public bool IsProcessValid(IntPtr process)
        {
            lock (sync)
            {
                return vmm.ProcessGetInformation((uint)process).dwState != 0xFFFFFFFF;
            }
        }

        /// <summary>Close the remote process.</summary>
		/// <param name="process">The process handle (in our case the process PID).</param>
        public void CloseRemoteProcess(IntPtr process)
        {
            if (process == null)
            {
                return;
            }

            process = IntPtr.Zero;
        }

        public bool ReadRemoteMemory(IntPtr process, IntPtr address, ref byte[] buffer, int offset, int size)
        {
            byte[] memRead = vmm.MemRead((uint)process, (ulong)address, (uint)size, Vmm.FLAG_NOCACHE);

            if (memRead == null)
            {
                return false;
            }
            if (memRead.Length != size)
            {
                return false;
            }

            Buffer.BlockCopy(memRead, 0, buffer, offset, size);

            return true;
        }

        public bool WriteRemoteMemory(IntPtr process, IntPtr address, ref byte[] buffer, int offset, int size)
        {
            //Not supported

            return false;
        }

        public void ControlRemoteProcess(IntPtr process, ControlRemoteProcessAction action)
        {
            //Not supported

            return;
        }

        public bool AttachDebuggerToProcess(IntPtr id)
        {
            //Not supported

            return false;
        }

        public void DetachDebuggerFromProcess(IntPtr id)
        {
            //Not supported

            return;
        }

        public bool AwaitDebugEvent(ref DebugEvent evt, int timeoutInMilliseconds)
        {
            //Not supported

            return false;
        }

        public void HandleDebugEvent(ref DebugEvent evt)
        {
            //Not supported

            return;
        }

        public bool SetHardwareBreakpoint(IntPtr id, IntPtr address, HardwareBreakpointRegister register, HardwareBreakpointTrigger trigger, HardwareBreakpointSize size, bool set)
        {
            //Not supported

            return false;
        }
    }
}
