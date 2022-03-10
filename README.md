# ¡WARNING! DO NOT TRY TO USE THIS AS IS  

## Forest-Wide-Windows-Update-Sequence
I wrote this script for my domain environment (meaning it will not work in your environment as is) because my AD forest lacks an RODC,  a DHCP failover, and DNS failover in addition to the fact that my domain controller is on Hyper-V (Server 2016 Desktop Experience. Not the bare metal variety). This means that when patch Tuesday rolls around, I need to update and reboot my servers in a very specific sequence so that I'm not in the middle of installing an update while my PDC (which triples as PDC, DNS, and DHCP) is rebooting or rebooting my Hyper-V host while the guest VM is mid-update, etc.  
```ps1
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
iex (irm "https://raw.githubusercontent.com/nstevens1040/Forest-Wide-Windows-Update-Sequence/main/DomainWide-CheckForUpdates.ps1")
```

