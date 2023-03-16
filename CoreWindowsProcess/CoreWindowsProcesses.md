Core Windows Processes
==========================

* This summary is designed to give you an understanding of what normal Windows operating system behavior looks like and how to identify suspicious processes running on an endpoint.

---------------------------------------------------------------------------
introduction :
================

In order to protect endpoints from viruses, company's used various antivirus programs that helped prevent attacks on the endpoints.

Nowadays with the advancement of technology this is no longer enough because the attacks have been upgraded and nowadays being only with an antivirus on the endpoint is no longer enough.

Today antivirus is just one tool within the layerd defensive approach.
New Security toolssuch as EDR (Endpoint Detection and Response),have been created because antivirus cannot catch every malicious binary and process running on the endpoint and cant defend the endpoint from any sort type of attack.

But even with those tools,it is still not 100% effective because attackers can still bypass the defences running on the endpoint.
and this is when the Security Analyst,SOC Analyst,Detection Engineer or Threat Hunter comes to place.
if one of the tools alerts us of a suspicious binary or process,we must investigate and decide on a real-time action.
Knowing the expected behavior of the system we need to defend we can decide if the binary or process is normal behavior or evil.

---------------------------------------------------------------------------

Task Manager :
================

Task Manager is a tool that built-in GUI-Based in the Windows Operating System that allow the users to see what is running on the windows system in real-time.

This tool provides information such as usage of CPU and memory. 
When a program is not responding Task manager is used to end(kill) the process of this program.

(To get To your Task Manager on Windows Press Ctrl+Shift+Esc)

The columns are very minimal. The columns Name,Status,CPU and Memory are the only ones visible.
To view more columns, right-click on any column header to open more options

Let's go over each column and Explain it:
------------------------------------------
* Type - Each process falls into 1 of 3 categories (Apps,Background process or Windows process.)

* Publisher - Think of this as the name of the author of this program.

* PID - This is the process identfier number.Windows assigns a unique process identfier each time a program starts.if the same program has multiple running processes,each will have its unique process identifier(PID.)

* Process Name - This is the file name of the procces.for example the file name for Task Manager is Taskmeg.exe.

* Command line - The full command used to lunch the process. For example to lunch Task Manager you need to lunch the command:
"C:\Windows\system32\taskmgr.exe"

* CPU - The amount of processing power the process uses.

* Memory - The amount of physical working memory utilized by the process.

---------------------------------------------------------------------------

As a cyber analyst the columns "Image path file" and "Command line" can add some importnat information about the proceeses because they can quickly alert to the analyst about any outliers with given process.

For example if we look at the 1.PNG picture in PNG files we can see that in PID 384 the process svchost.exe, a Windows process the Command line is not what its supose to be and now we can perform a deeper analysis.

Now,of course you can add as much cloumns as you like but the performance of the Task manger will be affected by it and your analysis because of the non-importanat information that will show up.

---------------------------------------------------------------------------

Task Manager is a powerfull built-in tool but It subtracts important information when analyzing proceeses, such as parent process information.

What is parent process information?
------------------------------------
The parent process information is used to inherit many propeties to the child process such as the current directory and environment variables (if not explicity specified).
Windows stores the parent process ID in the child process managment object for future generations.

Now Back to our process svchost.exe,if the parent process PID 384 is not services.exe, this will warrant further analysis because it means that this process is not a child process of services.exe.

In the image 2.png in PNG Files the PID for services.exe is 632. Now how did svchost.exe start before services.exe? Well, it didnt.. Task manager doesnt show a psrent-child process view and thats why other tools such as Process Hacker and Process Explorer come to rescue.

---------------------------------------------------------------------------

System:
========

The first Windows process on the Task Manager is System. a PID for any given process is assigned at random, but for the System process the PID will be always 4. Why and what does this process do?

The system process PID is a spacial kind of thread that runs only in kernel mode and runs code only in the system space and doesnt have a user process address space.

To read more about this subject and for the difference between user mode and kernel mode Visit the following link :  https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/user-mode-and-kernel-mode

---------------------------------------------------------------------------

Now Let's check what a normal behavior of this process looks like by view the propeties of this sytem (3.png in PNG files):
----------------------------------------------------

* Image Path : N/A
* Parent Process : None
* Number of instance : One
* User Account : Local System
* Start Time : a boot time

Now,in the Process Hacker this information is slightly different (4.png in PNG files.)
----------------------------------------------------

* Image Path : C:\Windows\system32\ntoskrnl.exe (NT OS Kernel)
* Parent Process : System idle Process (0)

As we can Tell Process Hacker confirms that this is a legit Microsoft Windows process.

--------------------------------------------------------------------------

What is unusual behavior for this process?
-------------------------------------------

* A parent process (aside from system idle process (0))
* Multiple instance of system.(Should be only one instance)
* A different PID.(Other than 4 cause it will be always 4)
* Not running in Session 0

--------------------------------------------------------------------------

SMSS.exe:
===========

smss.exe(Session Manager Subsystem) also known as Windows Session Manager, is responsible for creating new sessions. it is the first user-mode process started by the kernel.

This process starts the kernel and user modes of the Windows subsystem.
This subsystem includes win32k.sys (kernel mode),winsrv.dll(user-mode) and csrss.exe(user-mode).

Smss.exe starts csrss.exe and wininit.exe in Session 0 that is isolated Windows session for the opreating system, and csrss.exe and winlogon.exe for session 1, which is the user session. The first child instance create child instances in new sessions and its done by smss.exe copying itself into the new session and terminating itself.
You can find in PNG Files (5.png) an image of Session 0 and Session 1.

--------------------------------------------------------------------------

Also any other subsystem that listed in the "Required" value of the file Subsystems is also lunched.
This file exsist in the Registry Editor in the Path :

"HKLM\System\CurrentControlSet\Control\Session Manager\Subsystems"

Note: The process smss.exe has the PID of 384 and PID of 488
--------------------------------------------------------------------------

SMSS is also responsible for creating environment variables,virtual memory paging files and starts winlogon.exe.

Normal Behavior:
-----------------

* Image Path : %SystemRoot%\System32\smss.exe
* Parent Process : System
* Number of instances : One master instance and child instance per session. The child instance exits after creating the session.
* User Account : Local System
* Start Time : Within seconds of boot time for the master instance.

Unusual Behavior:
------------------

* A Different parent process other than System (PID 4)
* The image path is different from C:\Windows\System32
* More than one running process.(children self-terminate and exit after each new session)
* The running User is not SYSTEM user
* Unexpected registry entries for subsystem

--------------------------------------------------------------------------

csrss.exe:
============

csrss.exe(Client Server Runtime Process) is the user-mode side of the Windows subsystem.
This process should always running and is critical to system operation.
if this process is termineted by chance, it will result in system faliure. this process is responsible for the Win32 console window and process thread creation and deletion.
For each instance "csrsrv.dll","basesrv.dll" and "winsrv.dll" are loaded.

--------------------------------------------------------------------------

This process is also responsible for making the windows API available to other processes,mapping drive letters and handling the windows shutdown process.

Note: csrss.exe and winlogon.exe are called from smss.exe at startup for session 1.
--------------------------------------------------------------------------

Now What is a Noraml Behavior of this process on each Session?
---------------------------------------------------------------

Session 0 (PID 392)
Session 1 (PID 512)

* Image Path : %SystemRoot%\System32\csrss.exe
* Parent Process : Created by an instance of smss.exe
* Number of instances : Two or more
* User Account : Local System
* Start Time : within seconds of boot time for the first two instances 
(Session 0 and 1).start times for additional instances occur as new sessions are created, although only Sessions 0 and 1 are often created.

Unusual Behavior:
-----------------

* An actual parent process. (smss.exe calls this process and self-terminates.)
* Image path file other than C:\Windows\System32
* Subtle misspellings to hide rogue proceeses that masquerading as csrss.exe in plain sight.
* The user is not the SYSTEM user.

--------------------------------------------------------------------------

wininit.exe:
==============

wininit.exe(Windows intialization Process) is responsible for lunch the services.exe,lsass.exe(Local Security Athority) and lsaiso.exe within Session 0.
it is another critical Windows process that runs in the background along with its child processes.

Note: lsaiso.exe is a process associated with Credential Guard and KeyGuard and you will only see this process if Credential Guard is enabled.

------------------------------------------------------------------------

Noraml Behavior :
-------------------

* Image Path : %SystemRoot%\System32\wininit.exe
* Parent Process : Created by an instance of smss.exe
* Number of Instances : One
* User Account : Local System
* Start Time : Within seconds of boot time

unusual Behavior:
--------------------

* An actual parent process. (smss.exe calls this process and self-terminates).
* Image file path other than C:\Windows\System32
* Subtle misspellings to hide rogue processes in plain sight
* Multiple running instances
* Not running as SYSTEM.

--------------------------------------------------------------------

wininit.exe > services.exe:
============================

Service Control Manager or (SCM) is responsible to handle system services and has few roles:
* loading services
* interacting with services
* starting or ending services

this process maintains a database that can be queried a Windows buit-in tool such as "sc.exe".

DESCRIPTION BY CMD : "SC is a command line program used for communicating with the service Control Manager and services."

all the information regarding services is stored in the registry path : "HKLM\System\CurrentControlSet\Services".

(Image in PNG_Files)

---------------------------------------------------------------------

This process also loads device drivers marked as auto-start into memory.

When a user logs into a machine successfully, this process is responsible for setting the value of the last known Good control set to that of the CurrentControlSet.

registry key path : "HKLM\System\LastKnownGood"

(Image of the file path in PNG_FILES)

This process is the parent to several other key processes such as: svchost.exe,spoolsv.exe,msmpeng.exe and dllhost.exe.

to read more about this process visit this link : "https://en.wikipedia.org/wiki/Service_Control_Manager" 

(image of the child processes in PNG_Files)

--------------------------------------------------------------------

Normal Behavior:
------------------

* Image Path : %SystemRoot%\System32\services.exe
* Parent Process : wininit.exe
* Number of instances : One
* User Account : Local System
* Start Time : Within seconds of boot time


Unusual Behavior:
-------------------

* A parent process other than wininit.exe
* Image file path other than C:\Windows\System32
* Subtle misspellings to hide rogue proceeses in plain sight.
* Multiple running instances
* Not running as SYSTEM

----------------------------------------------------------------------

wininit.exe > services.exe > svchost.exe :
============================================

The Service Host or svchost.exe is responsible for hosting and managing windows services.
The services running in this process are implemented as DLLs. The DLL to implement is stored in  the registry for the service under the "Parametes" subkey in "ServiceDLL".

The full path is : "HKLM\SYSTEM\CurrentControlSet\Services\SERVICE NAME\Parameters".

(in the PNG_Files the example image is the ServiceDLL value for the Dcomlaunch service).

--------------------------------------------------------------------

To view this information follow those steps:
---------------------------------------------

1) right-click the svchost.exe process.

2) in the menu go to services>"SERVICENAME">Go to service

3) Right-click the service and select properties.(You can see there in the buttom the Service DLL).

after those steps you can found the Binary Path of the service.

Also notice how it is structured. There is a key identifier in the binary path, and the identifier is "-k".
This is how a legitimate svchost.exe process is called.

--------------------------------------------------------------------

The "-k" parameter is for grouping similar services to share the same process.
This concept was based on the OS design and implemented to reduce resource consumption.
all of that started from Windows 10 Version 1703 when services grouped into host processes changed. On machines running more than 3.5GB of memory each service will run its own process.

To read more about this process visit this link :
"https://en.wikipedia.org/wiki/Svchost.exe"

Now back to the key identifier (-k) from the binary path, in the image in PNG_Files (Dcomlaunch -k) the -k value is Dcomlaunch.
Other services are running with the same binary path in the image.

-------------------------------------------------------------------

Let's take LSM as an example and inspect the value for ServiceDLL.

(image in PNG_Files under the name LSM_ServiceDLL)

Since svchoost.exe will always have multiple running processes on any Windows system, this process has been a target for malicious use. Adversaries create malware to masquerade as this process and try to hide amongst the legitimate svchost.exe processes. They can name the malware svchost.exe or misspell it slightly, such as scvhost.exe. By doing so the intention it to go under the radar.
Another tactic is to install/call a malicious service(DLL).

-----------------------------------------------------------------

Normal Behavior:
------------------

* Image Path : %SystemRoot%\System32\svchost.exe
* Parent Process : services.exe
* Number of instances : Many (More than one or 2..)
* User Account : A few (SYSTEM,Network Service,Local Service) depending on the svchost.exe instance. in windows 10 some instances run as the logged-in user.
* Start-Time : Typically within seconds of boot time. other instances of svchost.exe can be started after boot.


Unusual Behavior:
-------------------

* A parent process other than services.exe
* Image file path other than C:\Windows\system32
* Subtle misspelling to hide rogue processes in plain sight
* The absence of the -k parameter

--------------------------------------------------------------------

lsass.exe :
=============

LSASS(Local Security Authority Subsystem Service) is a process in Windows operating system that is responsible for enforcing the security policy on the system.
It verifies users logging on to the Windows server or computer,handles password changes,creates access tokens and it also writs to the Windows Security Log.

----------------------------------------------------------------------

This process create security tokens for the AD (Active Directory),SAM(Security Account Manager) and NETLOGON.

This process uses authentication packages that is specified in the reg path : "HKLM\System\CurrentControlSet\Control\Lsa"

(Picture from the path in PNG_Files under the name Lsa.)

-------------------------------------------------------------------

Lsass.exe is another process adversaries(Hackers) target.
Common tools such as "mimikatz" are used do dump credentials,or adversaries mimic this process to hide in plain sight.
Again, they do this by either naming their malware by this process name or simply misspelling the malware slightly.

------------------------------------------------------------------

Normal Behavior:
------------------

* Image Path : %SystemRoot%\System32\lsass.exe
* Parent Process : wininit.exe
* Number of instances : One
* User Account : Local System
* Start Time : Within seconds of boot time

Unusual Behavior:
-------------------

* A parent process other than wininit.exe
* Image file path other than C:\Windows\System32
* Subtle misspellings to hide rogue processes in plain sight.
* Multiple running instances
* Not running as SYSTEM

----------------------------------------------------------------------

winlogon.exe:
==============

The Windows Logon winogon.exe is a process that responsible for handling the Secure Attention Sequence(SAS)
It is the CTRL+ALT+DELETE key combination users press to enter their username and password.

This process is also responsible for loading the user profile it loads the user NTUSER.DAT into HKCU and userinit.exe loads the user shell.(Image in PNG_files under the name winlogon)

you can read more about this process here: "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-2000-server/cc939862(v=technet.10)?redirectedfrom=MSDN "

---------------------------------------------------------------------

This process is also responsible for locking the screen and running the user screensaver,among other functions.

Remember : smss.exe launches this process along with a copy of csrss.exe within session 1.

-----------------------------------------------------------------------

Noraml Behavior:
-----------------

* Image Path : %SystemRoot%\System32\winlogon.exe
* Parent Process : created by an instance of smss.exe that exits,so analysis tools usually do not provide the parent process name.
* Number of instaces : One or more
* User Account : Local System
* Start Time : Within seconds of boot time for the first time instance (For Session 1).Additional instances occur as new sessions are created,typically throgh Remote Desktop or Fast User Switching logons.

Unusual Behavior:
------------------

* An actual parent process. (smss.exe calls this process and self-terminates)
* Image file path other than C:\Windows\System32
* Subtle misspellings to hide rogue processes in plain sight.
* Not running as SYSTEM
* shell value in the registry other than explorer.exe
-------------------------------------------------------------------

explorer.exe :
===============

the Windows Explorer, explorer.exe. This process gives the user acess to folders and files.
This process also provides functionality to the Start Menu and Taskbar.

As mentioned previously the winlogon process runs userinit.exe which launches the value in the reg path "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell". Userinit.exe exits after spawning explorer.exe and because of this the parent process in non-existent.

------------------------------------------------------------------

Normal Behavior:
-----------------

* Image Path : %SystemRoot%\explorer.exe
* Parent Process : Created by userinit.exe and exits
* Number of instances : One or more pre interactively logged-in user.
* User Account : Logged-in user(s)
* Start Time : First instance when the first ineractive user logon session begins

Unusual Behavior:
-------------------

* An actual parent process (userinit.exe calls this process and exits)
* Image file path other than C:\Windows
* Running as an unknown user
* Subtle misspellings to hide rogue processes in plain sight
* Outbound TCP/IP connections.

----------------------------------------------------------------------

Conclusion:
=============

Understanding how the Windows operating system functions as a defender is vital. The Windows processes discussed in this room are core processes, and understanding how they usually operate can aid a defender in identifying unusual activity on the endpoint. 

With the introduction of Windows 10, new processes have been added to the list of core processes to know and understand normal behaviour.

Earlier it was mentioned that if Credential Guard is enabled on the endpoint, an additional process will be running, which will be a child process to wininit.exe, and that process is lsaiso.exe. This process works with lsass.exe to enhance password protection on the endpoint. 

Other processes with Windows 10 are RuntimeBroker.exe and taskhostw.exe (formerly taskhost.exe and taskhostex.exe). Please research these processes and any other processes you might be curious about to understand their purpose and their normal functionality.

-----------------------------------------------------------------------



























