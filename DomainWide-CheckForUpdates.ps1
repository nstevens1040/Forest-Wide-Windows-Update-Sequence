if(![Security.Principal.WindowsPrincipal]::New([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    throw [System.Security.AccessControl.PrivilegeNotHeldException]::new()
    return
}
function ClearLine
{
    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline=$true)]
        [string]$String
    )
    @(
        [string]::Join("",@((0..($string.Length + 8)).ForEach({ $([char]8) }))),
        [string]::Join("",@((0..($string.Length + 8)).ForEach({ $([char]32) }))),
        [string]::Join("",@((0..($string.Length + 8)).ForEach({ $([char]8) })))
    ).ForEach({ Write-Host $_ -NoNewLine })
}
function ShutdownAndWait
{
    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline=$true)]
        [string]$Computer
    )
    cmd /c "shutdown.exe /s /t 1 /m \\$($Computer) /d P:2:17"
    [console]::CursorVisible = $false
    while(Test-Connection -ComputerName $Computer -Count 1 -Quiet -ea 0){
        $string = "`r$($Computer) is up. Awaiting shutdown"
        Write-Host "$($string)       " -ForeGroundColor Yellow -NoNewLine
        (0..6) | % {
            $string = $string + "."
            Write-Host $string -ForegroundColor Yellow -NoNewline
            sleep -m 499
        }
    }
    $now = [datetime]::Now
    while (!(Test-Connection -ComputerName $Computer -Count 1 -Quiet -ea 0) -and ([datetime]::Now - $now).TotalSeconds -lt 5){}
    $string | ClearLine
    Write-Host "`r$($computer)"  -ForegroundColor Green -NoNewLine
    write-host " has shut down." -ForegroundColor Yellow
    [console]::CursorVisible = $true
}
function WaitFor-Reboot
{
    [cmdletbinding()]
    Param(
        [Parameter(ValueFromPipeline=$true)]
        [string]$Computer
    )
    [console]::CursorVisible = $false
    while(Test-Connection -ComputerName $Computer -Count 1 -Quiet -ea 0)
    {
        $string = "`r$($Computer) is up. Awaiting shutdown"
        Write-Host "$($string)       " -ForeGroundColor Yellow -NoNewLine
        (0..6) | % {
            $string = $string + "."
            Write-Host $string -ForegroundColor Yellow -NoNewline
            sleep -m 499
        }
    }
    while(!(Test-Connection -ComputerName $Computer -Count 1 -Quiet -ea 0))
    {
        $string = "`r$($Computer) is rebooting. Please wait"
        Write-Host "$($string)       " -ForeGroundColor Yellow -NoNewLine
        (0..6) | % {
            $string = $string + "."
            Write-Host $string -ForegroundColor Yellow -NoNewline
            sleep -m 499
        }
    }
    [console]::CursorVisible = $true
}

function Get-WUStates
{
    [cmdletbinding()]
    Param()
    $states = [System.Collections.Generic.Dictionary[[string],[string]]]::New()
    foreach($computer in $computers)
    {
        $state = Get-WUJob -ComputerName $computer | % stateName
        $states.Add($computer,$state)
    }
    return $states
}
function Write-ThenClear
{
    [cmdletbinding()]
    Param(
        [string]$NewMessage,
        [string]$OldMessage,
        [Int32]$Top,
        [Int32]$Left
    )
    if(![string]::IsNullOrEmpty($OldMessage))
    {
        [console]::SetCursorPosition($left,$top)
        write-host "$([string]::Join([string]::Empty,$OldMessage.Split("$([char]10)").ForEach({"$([string]::Join([string]::Empty,@(1.."$($_ -replace "$([char]10)",[string]::Empty)".Length).ForEach({"$([char]32)"})))$([char]10)"})))" -NoNewLine
    }
    [console]::SetCursorPosition($left,$top)
    Write-Host $NewMessage -NoNewline -ForegroundColor Yellow
}

$DOMAIN_CONTROLLER = Get-ADDomainController |% HostName
$DOMAIN_CONTROLLER_ip = Resolve-DnsName -Name $DOMAIN_CONTROLLER |% IPAddress
$MAIL_SERVER = Resolve-DnsName -Name (Resolve-DnsName -Name mail |% IPAddress) |% namehost
$MAIL_SERVER_ip = Resolve-DnsName -Name $MAIL_SERVER |% IPAddress
$HYPERV_SERVER = Get-ADObject -LDAPFilter '(&(ObjectClass=serviceConnectionPoint)(Name=Microsoft Hyper-V))' -Properties serviceBindingInformation |% serviceBindingInformation | ? {$_ -match $env:USERDOMAIN}
$HYPERV_SERVER_ip = Resolve-DnsName -Name $HYPERV_SERVER |% IPAddress
$computers = @(
    $MAIL_SERVER,
    $DOMAIN_CONTROLLER,
    $HYPERV_SERVER
)
$DEVPROD = Get-ADComputer -LDAPFilter '(!(userAccountControl:1.2.840.113556.1.4.803:=2)(operatingSystem=*server*))' |% DNSHostName | ? {$_ -notin $computers} | sort | select -First 1
$HPPROD = Get-ADComputer -LDAPFilter '(!(userAccountControl:1.2.840.113556.1.4.803:=2)(operatingSystem=*server*))' |% DNSHostName | ? {$_ -notin $computers} | sort | select -Last 1
$computers += $DEVPROD
$computers += $HPPROD
$all_results = @()
$all = $computers.Count
(0..8).ForEach({ Write-Host ""})
for($i = 0; $i -lt $all; $i++)
{
    $computer = $computers[$i]
    write-progress -PercentComplete (($i+1)/$all*100) -Status "$((($i+1)/$all*100).ToString("##.##"))%" -Activity "Starting Windows Updates on $($computer)"
    $result = @()
    # $result += Get-WindowsUpdate -AutoSelectOnly -ComputerName $computer -ForceDownload -Verbose -Debuger
    $result += Install-WindowsUpdate -AutoSelectOnly -ComputerName $computer -Install -Verbose -Debuger
    $all_results += $result
}
Write-Progress -Complete -Activity "Windows Update initiation completed."
write-host "Windows Update initiation completed." -ForegroundColor Green
write-host "BREAKPOINT:" -ForeGroundColor Blue -NoNewLine
write-host " strike " -ForegroundColor Yellow -NoNewLine
write-host "Enter" -ForeGroundColor Green -NoNewLine
write-host " to continue " -ForegroundColor Yellow -NoNewLine
Read-Host
$status = Get-WUStates
$top = [console]::CursorTop
$left = [console]::CursorLeft
$then = [datetime]::Now
[console]::CursorVisible = $false
if($status.Keys.Where({$status[$_] -eq 'Running'}).Count -eq 0)
{
    write-host "None of the servers in your environment are running a PSWindowsUpdate task."
    return
}
while($status.Keys.Where({$status[$_] -eq 'Running'}).Count -gt 0)
{
    if(![string]::IsNullOrEmpty($msg))
    {
        $old_msg = $msg
        $msg = "`rCurrently Downloading:`n    $([string]::Join("`n    ",@($status.Keys.Where({$status[$_] -eq 'Running'}))))`nReady to Install:`n    $([string]::Join("`n    ",@($status.Keys.Where({$status[$_] -eq 'Ready'}))))"
        Write-ThenClear -OldMessage $old_msg -NewMessage $msg -Top $top -Left $left
    } else {
        $msg = "`rCurrently Downloading:`n    $([string]::Join("`n    ",@($status.Keys.Where({$status[$_] -eq 'Running'}))))`nReady to Install:`n    $([string]::Join("`n    ",@($status.Keys.Where({$status[$_] -eq 'Ready'}))))"
        Write-ThenClear -NewMessage $msg -Top $top -Left $left
    }
    $status = Get-WUStates
}
[console]::CursorVisible = $true
$status = Get-WUStates
if($status.Keys.Where({$status[$_] -eq 'Running'}).Count -eq 0)
{
    Restart-Computer -ComputerName $DOMAIN_CONTROLLER -Force
    $DOMAIN_CONTROLLER | WaitFor-Reboot

    Restart-Computer -ComputerName $MAIL_SERVER -Force
    $MAIL_SERVER | WaitFor-Reboot

    $MAIL_SERVER | ShutdownAndWait
    $DOMAIN_CONTROLLER | ShutdownAndWait

    while((test-connection -ComputerName $MAIL_SERVER_ip -Count 1 -Quiet) -or (test-connection -ComputerName $DOMAIN_CONTROLLER_ip -Count 1 -Quiet)){}

    Invoke-Command -Computer $HYPERV_SERVER_ip -ScriptBlock {Stop-Service vmms -Force} -Credential (Get-Credential "$($ENV:USERDOMAIN)\$($ENV:USERNAME)")

    Restart-Computer -ComputerName $HYPERV_SERVER_ip -Force
    $HYPERV_SERVER_ip| WaitFor-Reboot

    Restart-Computer -ComputerName $HPPROD -Force
    $HPPROD| WaitFor-Reboot

    Restart-Computer -ComputerName $DEVPROD -Force
    $DEVPROD | WaitFor-Reboot

}
