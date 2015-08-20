# Pure PowerShell/WMI replacements for various shell commands
#   Most of these came from development of the Empire agent

function Get-Route {
    $adapters = @{}
    Get-WmiObject Win32_NetworkAdapterConfiguration | %{ $adapters[[int]($_.InterfaceIndex)] = $_.IPAddress }
    Get-WmiObject win32_IP4RouteTable | %{
        $out = New-Object psobject
        $out | Add-Member Noteproperty 'Destination' $_.Destination
        $out | Add-Member Noteproperty 'Netmask' $_.Mask
        if ($_.NextHop -eq "0.0.0.0"){
            $out | Add-Member Noteproperty 'NextHop' "On-link"
        }
        else{
            $out | Add-Member Noteproperty 'NextHop' $_.NextHop
        }
        if($adapters[$_.InterfaceIndex] -and ($adapters[$_.InterfaceIndex] -ne "")){
            $out | Add-Member Noteproperty 'Interface' $($adapters[$_.InterfaceIndex] -join ",")
        }
        else {
            $out | Add-Member Noteproperty 'Interface' '127.0.0.1'
        }
        $out | Add-Member Noteproperty 'Metric' $_.Metric1
        $out
    } | ft -autosize
}

function Get-Tasklist {
    $owners = @{}
    Get-WmiObject win32_process | % {$o = $_.getowner(); if(-not $($o.User)){$o="N/A"} else {$o="$($o.Domain)\$($o.User)"}; $owners[$_.handle] = $o}
    Get-Process | % {
        $arch = "x64"
        if ([System.IntPtr]::Size -eq 4){
            $arch = "x86"
        }
        else{
            foreach($module in $_.modules) {
                if([System.IO.Path]::GetFileName($module.FileName).ToLower() -eq "wow64.dll") {
                    $arch = "x86"
                    break
                }
            }
        }
        $out = New-Object psobject
        $out | Add-Member Noteproperty 'ProcessName' $_.ProcessName
        $out | Add-Member Noteproperty 'PID' $_.ID
        $out | Add-Member Noteproperty 'Arch' $arch
        $out | Add-Member Noteproperty 'UserName' $owners[$_.id.tostring()]
        $mem = "{0:N2} MB" -f $($_.WS/1MB)
        $out | Add-Member Noteproperty 'MemUsage' $mem
        $out
    } | Sort-Object -Property PID | ft -wrap
}

function Get-NetStat {
    Get-WmiObject -class "Win32_NetworkAdapterConfiguration" | ? {$_.IPEnabled -Match "True"} | % {
        $out = New-Object psobject
        $out | Add-Member Noteproperty 'Description' $_.Description
        $out | Add-Member Noteproperty 'MACAddress' $_.MACAddress
        $out | Add-Member Noteproperty 'DHCPEnabled' $_.DHCPEnabled
        $out | Add-Member Noteproperty 'IPAddress' $($_.IPAddress -join ",")
        $out | Add-Member Noteproperty 'IPSubnet' $($_.IPSubnet -join ",")
        $out | Add-Member Noteproperty 'DefaultIPGateway' $($_.DefaultIPGateway -join ",")
        $out | Add-Member Noteproperty 'DNSServer' $($_.DNSServerSearchOrder -join ",")
        $out | Add-Member Noteproperty 'DNSHostName' $_.DNSHostName
        $out | Add-Member Noteproperty 'DNSSuffix' $($_.DNSDomainSuffixSearchOrder -join ",")
        $out
    } | fl
}
