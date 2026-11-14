# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
param(
    [Parameter(Mandatory = $true)][int]$ControllerPid,
    [Parameter(Mandatory = $true)][string]$ExpectedExecutable
)
$ErrorActionPreference = 'Stop'
$controller = Get-CimInstance Win32_Process -Filter "ProcessId = $ControllerPid"
if (!$controller -or $controller.ExecutablePath -ne [IO.Path]::GetFullPath($ExpectedExecutable) -or
    $controller.CommandLine -notlike '*--etw-watch-broker*') { throw 'Expected the owned broker watchdog' }
Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class BrokerThreadQuery {
 [StructLayout(LayoutKind.Sequential)] struct Trustee {public IntPtr multiple;public int operation,form,type;public IntPtr name;}
 [StructLayout(LayoutKind.Sequential)] struct Access {public uint rights;public int mode;public uint inheritance;public Trustee trustee;}
 [DllImport("kernel32",SetLastError=true)] static extern IntPtr OpenThread(uint rights,bool inherit,int tid);
 [DllImport("kernel32",SetLastError=true)] static extern uint GetProcessIdOfThread(IntPtr thread);
 [DllImport("kernel32")] static extern bool CloseHandle(IntPtr handle);
 [DllImport("kernel32")] static extern IntPtr LocalFree(IntPtr handle);
 [DllImport("advapi32",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSidToSid(string text,out IntPtr sid);
 [DllImport("advapi32")] static extern uint GetSecurityInfo(IntPtr handle,int type,uint info,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
 [DllImport("advapi32",CharSet=CharSet.Unicode)] static extern uint SetEntriesInAcl(uint count,ref Access entry,IntPtr oldAcl,out IntPtr newAcl);
 [DllImport("advapi32")] static extern uint SetSecurityInfo(IntPtr handle,int type,uint info,IntPtr owner,IntPtr group,IntPtr dacl,IntPtr sacl);
 public static void Inject(int pid,int tid) {
  IntPtr thread=OpenThread(0x60800,false,tid);if(thread==IntPtr.Zero)throw new Exception("OpenThread "+Marshal.GetLastWin32Error());
  IntPtr sid=IntPtr.Zero,descriptor=IntPtr.Zero,acl=IntPtr.Zero;
  try {
   if(GetProcessIdOfThread(thread)!=(uint)pid)throw new Exception("Thread ownership changed");
   if(!ConvertStringSidToSid(WindowsIdentity.GetCurrent().User.Value,out sid))throw new Exception("SID");
   IntPtr owner,group,oldAcl,sacl;
   uint error=GetSecurityInfo(thread,6,4,out owner,out group,out oldAcl,out sacl,out descriptor);
   if(error!=0)throw new Exception("GetSecurityInfo "+error);
   Access entry=new Access();entry.rights=0x800;entry.mode=1;entry.trustee.form=0;entry.trustee.type=1;entry.trustee.name=sid;
   error=SetEntriesInAcl(1,ref entry,oldAcl,out acl);if(error!=0)throw new Exception("SetEntriesInAcl "+error);
   error=SetSecurityInfo(thread,6,4,IntPtr.Zero,IntPtr.Zero,acl,IntPtr.Zero);if(error!=0)throw new Exception("SetSecurityInfo "+error);
   Console.WriteLine("INJECTED_THREAD_QUERY pid="+pid+" tid="+tid+" mask=0x800");
  } finally {if(acl!=IntPtr.Zero)LocalFree(acl);if(descriptor!=IntPtr.Zero)LocalFree(descriptor);if(sid!=IntPtr.Zero)LocalFree(sid);CloseHandle(thread);}
 }
}
'@
$threadId = [Diagnostics.Process]::GetProcessById($ControllerPid).Threads[0].Id
[BrokerThreadQuery]::Inject($ControllerPid, $threadId)
