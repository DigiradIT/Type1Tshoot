<#
.SYNOPSIS
   Returns a list of connected interfaces
.NOTES
    If SSL VPN is connected it will be included in the list of connected interfaces.
.OUTPUTS
    Collection of network interface objects.
#>
function Get-ConnectedInterfaces {

 Get-NetIPConfiguration | Where-Object {$_.NetAdapter.status -ne "Disconnected"}
}

<#
.SYNOPSIS
    Determines whether the SSL VPN is connected based on the descriptions of connected interfaces.
.NOTES
    If fortinet changes the description of the interface this will break!
.OUTPUTS
    A hash objcet with a connected key.
#>
function Test-SSLVPNInterface{

    $result_hash = @{result_type = "SSL_VPN"}
    $ssl_connection = Get-ConnectedInterfaces | Where-Object {$_.InterfaceDescription -eq "Fortinet SSL VPN Virtual Ethernet Adapter"}
        if ($null -ne $ssl_connection){
            $result_hash.connected = $true
        } else{
            $result_hash.connected = $false
        }
        return $result_hash
    
}

<#
.SYNOPSIS
    Runs tests on the output of Test-SSLVPNInterface and returns the test result.
.OUTPUTS
    A PSCustom Object taht contains "Test Name", "Result", and "Detail" keys.
    Result will be either Pass or Error.
#>
function Get-SSLVPNInterfaceStatus{
    $result = Test-SSLVPNInterface
    if ($result.connected){
        [PSCustomObject]@{
            "Test Name" = "SSL VPN Interface Online";
            "Result" = "Pass";
            "Detail" = "SSL VPN is up."
        }
    } else {
        [PSCustomObject]@{
            "Test Name" = "SSL VPN is down";
            "Result" = "Warn";
            "Detail" = "SSL VPN interface note found."
        }
    }
}

<#
.SYNOPSIS
    Determines whether there is a connected physical ethernet connection.
.NOTES
    The Fortinet SSL interface shows up as a an ethernet interface and can only be 
    distinguished from physical ethernet adapters by it's description.
.OUTPUTS
    A result hash with a connected key.
#>
function Test-ConnectedEthernet{
        $result_hash = @{result_type = "connected_ethernet"}
        $physical_ethernet = Get-ConnectedInterfaces | 
        Where-Object {$_.InterfaceAlias -like "Ethernet*"} |
        Where-Object {$_.InterfaceDescription -ne  "Fortinet SSL VPN Virtual Ethernet Adapter"}

       if ($physical_ethernet -ne $null) {
        $result_hash.connected = $true
       } else{
        $result_hash.connected = $false
       } 

       $result_hash
}

<#
.SYNOPSIS
    Runs tests on the output of Test-ConnectedEthernet and returns the test result.
.OUTPUTS
    A PSCustom Object taht contains "Test Name", "Result", and "Detail" keys.
    Result will be either Pass or Error.
#>
function Get-ConnectedEthernetStatus{
    $result = Test-ConnectedEthernet
    if ($result.connected){
        [PSCustomObject]@{
            "Test Name" = "Physical Ethernet Connected";
            "Result" = "Pass";
            "Detail" = "Physical Ethernet Port is connected."
        }
    } else {
        [PSCustomObject]@{
            "Test Name" = "No Physical Ethernet Conneted";
            "Result" = "Error";
            "Detail" = "No Physcial Ethernet Port is conneted."
        }
    }
}

<#
.SYNOPSIS
    Determines whether there is a connected physical ethernet port that is assigned
    an IP in the 172.17.0.0/16 subnet.
.NOTES
    Since individual Fortigates assign different network addresses we cannot currently 
    narrow down this check.  If in the future we change our addressing scheme this 
    function will need to be updated.
.OUTPUTS
    A result hash with a type1_network_address key.
#>
function Test-Type1NetworkAddress{
        $result_hash = @{result_type="Type1_Network_address"}
        $network_address = Get-ConnectedInterfaces | 
        Where-Object {$_.InterfaceAlias -like "Ethernet*"} |
        Where-Object {$_.InterfaceDescription -ne  "Fortinet SSL VPN Virtual Ethernet Adapter"} |
        Where-Object {$_.IPv4Address.IPAddress -like "172.17.*"}
        
        if ($null -ne $network_address) {
            $result_hash.type1_network_address = $network_address.IPv4Address.IPAddress
        } else {
            $result_hash.type1_network_address = "not_found"
        }

        $result_hash
}

<#
.SYNOPSIS
    Runs tests on the output of Test-Type1NetworkAddress and returns the test result.
.OUTPUTS
    A PSCustom Object taht contains "Test Name", "Result", and "Detail" keys.
    Result will be either Pass or Error.
#>
function Get-Type1NetworkAddressStatus{
    $result = Test-Type1NetworkAddress
    if ($result.type1_network_address -ne "not_found"){
        [PSCustomObject]@{
            "Test Name" = "Type 1 Address Assigned to Ethernet";
            "Result" = "Pass";
            "Detail" = "Type 1 network address is assigned: $($result.type1_network_adress)"
        }
    } else {
        [PSCustomObject]@{
            "Test Name" = "Type 1 Address Assigned to Ethernet";
            "Result" = "Error";
            "Detail" = "Type 1 network address is not assigned."
        }
    }
}
<#
.SYNOPSIS
    Determines whether there isa service listening on either TCP 3104 or 3105.
.NOTES
    3104 and 3105 are the default listening ports for the PICOM service.
.OUTPUTS
    A result hash with a key set to the listening port.
#>
function Test-PicomListening{
    $result_hash = @{result_type="Picom_Listening"}
    $listening = Get-NetTCPConnection -State Listen |
    Where-Object {$_.LocalPort -in "3104", "3105"}

    foreach ($port in $listening) {
        $result_hash[$port.LocalPort.ToString()] = "listening"
    } 

    $result_hash
}

<#
.SYNOPSIS
    Runs tests on the output of Test-PicomListening and returns the test result.
.OUTPUTS
    A PSCustom Object taht contains "Test Name", "Result", and "Detail" keys.
    Result will be either Pass or Error.
#>
function Get-PicomListeningStatus{
    $result = Test-PicomListening
    if (($result["3104"] -eq "listening") -and ($result["3105"] -eq "listening")){
        [PSCustomObject]@{
            "Test Name" = "Picom listening";
            "Result" = "Pass";
            "Detail" = "Picom is listening on ports 3104 and 3104"
        }
    } else {
        [PSCustomObject]@{
            "Test Name" = "Picom listening";
            "Result" = "Error";
            "Detail" = "Picom is not $($result["3104"]) on port 3104, and $($result["3105"]) on port 3105"
        }
    }
}

<#
.SYNOPSIS
    Determines whether the configuration files needed for PICOM exist.
.NOTES
    If configuration files are added or removed as requirements we will need
    to update this function.
.OUTPUTS
    A result hash with a cfg file count and ini file count key.
#>

function Test-ConfigFilesExist{

    $result_hash = @{result_type="Config_Files_Exist"}
     
    $cfg_file_cnt =  Get-ChildItem -Path "C:/Program Files (x86)/ScImage/Picom"|
        Where-Object {$_.name -like "*.cfg"} |
        Where-Object {$_.name -in "NdSCP3104.cfg", "NDStoreSCPXA.cfg"} |
        Measure-Object
    $ini_file_cnt =  Get-ChildItem -Path "C:/Program Files (x86)/ScImage/Picom"|
        Where-Object  {$_.name -like "*.ini"}|
        Where-Object {$_.name -in "picom.ini"} |
        Measure-Object

    $result_hash.cfg_file_count = $cfg_file_cnt.count
    $result_hash.ini_file_count = $ini_file_cnt.count

    $result_hash
}

<#
.SYNOPSIS
    Runs tests on the output of Test-ConfigFileExist and returns the test result.
.OUTPUTS
    A PSCustom Object that contains "Test Name", "Result", and "Detail" keys.
    Result will be either Pass or Error.
#>
function Get-ConfigFilesExistStatus{
    $result = Test-ConfigFilesExist
    if (($result.cfg_file_count -eq 2) -and ($result.ini_file_cnt -eq 1)){
        [PSCustomObject]@{
            "Test Name" = "Config Files Exist";
            "Result" = "Pass";
            "Detail" = "All needed configuraiton files exist."
        }
    } elseif ($result.cfg_file_count -ne 2){
        [PSCustomObject]@{
            "Test Name" = "Config Files Exist";
            "Result" = "Error";
            "Detail" = "Configuration file missing."
        } 
    } elseif ($result.ini_file_count -lt 1){
        [PSCustomObject]@{
            "Test Name" = "Config Files Exist";
            "Result" = "Warn";
            "Detail" = "picom.ini file missing."
        }
    }
}
<#
.SYNOPSIS
    Determines whether there is a PICOM license file present.
.NOTES
    It is important to note that this is an existence check.  We are not
        able to parse the license file
.OUTPUTS
    A result hash with a license file count key.
#>
function Test-LicenseFileExist{
    $result_hash = @{result_type="License_File_Exist"}
    $lic_count = Get-ChildItem -Path "C:/Program Files (x86)/ScImage/Picom" |
    Where-Object {($_.name -like "*.plic*")}  |
    Measure-Object

    $result_hash.license_file_count = $lic_count.count
    $result_hash
}
<#
.SYNOPSIS
    Runs tests on the output of Test-LicenseFileExist and returns the test result.
.OUTPUTS
    A PSCustom Object taht contains "Test Name", "Result", and "Detail" keys.
    Result will be either Pass or Error.
#>
function Get-LicenseFileExistStatus{
    $result = Test-LicenseFileExist
    if ($result.license_file_count -ge 1){
        [PSCustomObject]@{
            "Test Name" = "License File Exist";
            "Result" = "Pass";
            "Detail" = "License file found."
        }
    } else {
        [PSCustomObject]@{
            "Test Name" = "License File Exist";
            "Result" = "Error";
            "Detail" = "No license file found."
        }
    } 
}
<#
.SYNOPSIS
    Determines whether needed fields are present in the NdSCP3104.cfg file.
.NOTES
    In this check we are determining whether fields that are configured as part of the
    install process are correct.  This test does not verify the entirety of the file.

    There are redundant fields withing the config file, and we must validate them all.  There are also 
    redundant fields across other config files that need to be configured.
.OUTPUTS
    A result hash with a Picom_Region_Code, modality, picom_server_dns, picom_server_port, and mrn_region_code 
    keys.
#>

function Test-SCP3104Config {
    $content = Get-Content -Path "C:/Program Files (x86)/ScImage/Picom/NdSCP3104.cfg"
    $result_hash = @{result_type = "SCP_3104_Config"}

    $result_hash.Picom_Region_Code = $content |
        select-string -pattern "^poldeviceid=([0-9]+)_.*_" |
        %{$_.matches[0].groups[1].value}

    $result_hash.modality = $content |
        select-string -pattern "^poldeviceid=[0-9]+_(.*)_" |
        %{$_.matches[0].groups[1].value}
    
    $result_hash.picom_server_dns = $content |
        select-string -pattern "^picomserverip=([0-9a-z.]+)" |
        %{$_.matches[0].groups[1].value}
    
    $result_hash.picom_server_port = $content |
        select-string -pattern "^picomserverport=([0-9]+)"|
        %{$_.matches[0].groups[1].value}

    $result_hash.mrn_region_code = $content |
        select-string -pattern "^\*,\*=([0-9]+)_" |
        %{$_.matches[0].groups[1].value}
   
    $result_hash

}
<#
.SYNOPSIS
    Runs tests on the output of Test-SCP3104Config and returns the test result.
.OUTPUTS
    A PSCustom Object taht contains "Test Name", "Result", and "Detail" keys.
    Result will be either Pass or Error.
#>
function Get-SCP3104ConfigStatus{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $hub_code
    )
    $result = Test-SCP3104Config
    $picom_server_names = "west.picom365.com","east.picom365.com", "posting.picom365.com"
    $picom_server_ports = "9057", "796"
    switch($result){
        {$null -eq $_.mrn_region_code} {
            [PSCustomObject]@{
                "Test Name" = "SCP 3104 MRN Region code";
                "Result" = "Warn";
                "Detail" = "MRN Region code not found";
            }
        } 
        {$_.mrn_region_code -ne $hub_code}{
            [PSCustomObject]@{
                "Test Name" = "SCP 3104 MRN Region code";
                "Result" = "Warn";
                "Detail" = "Hub code does not match, config file hub code: $($_.mrn_region_code)";
            }
        }
        {$_.mrn_region_code -eq $hub_code}{
            [PSCustomObject]@{
                "Test Name" = "SCP 3104 MRN region code";
                "Result" = "Pass";
                "Detail" = "SCP 3104 MRN region code set correctly.";
            }
        }
        {$null -eq $_.Picom_Region_Code} {
            [PSCustomObject]@{
                "Test Name" = "SCP 3104 PICOM region code";
                "Result" = "Warn";
                "Detail" = "PICOM region code not found";
            }
        } 
        {$_.Picom_Region_Code -ne $hub_code}{
            [PSCustomObject]@{
                "Test Name" = "SCP 3104 PICOM region code";
                "Result" = "Warn";
                "Detail" = "Hub code does not match, config file hub code: $($_.mrn_region_code)";
            }
        }
        {$_.Picom_Region_Code -eq $hub_code}{
            [PSCustomObject]@{
                "Test Name" = "SCP 3104 PICOM region code";
                "Result" = "Pass";
                "Detail" = "SCP 3104 PICOM region code set correctly.";
        }
        }
        {$null -eq $_.modality} {
            [PSCustomObject]@{
                "Test Name" = "SCP 3104 modality";
                "Result" = "Warn";
                "Detail" = "modality not found";
            }
        } 
        {$_.modality -ne "NM"}{
            [PSCustomObject]@{
                "Test Name" = "SCP 3104 modality";
                "Result" = "Error";
                "Detail" = "Modality is not set to NM";
            }
        }
        {$_.modality -eq "NM"}{
            [PSCustomObject]@{
                "Test Name" = "SCP 3104 modality";
                "Result" = "Pass";
                "Detail" = "SCP 3104 modality set correctly.";
            }
        }
        {$null -eq $_.picom_server_dns} {
            [PSCustomObject]@{
                "Test Name" = "SCP 3104 PICOM server dns";
                "Result" = "Error";
                "Detail" = "PICOM server dns not found";
            }
        } 
        {$_.picom_server_dns -notin $picom_server_names}{
            [PSCustomObject]@{
                "Test Name" = "SCP 3104 PICOM server dns";
                "Result" = "Error";
                "Detail" = "PICOM server DNS is set to an incorrect value: $($_.picom_server_dns)";
            }
        }
        {$_.picom_server_dns -in $picom_server_names}{
            [PSCustomObject]@{
                "Test Name" = "SCP 3104 PICOM server dns";
                "Result" = "Pass";
                "Detail" = "SCP 3104 PICOM server dns set correctly.";
            }
        }
        {$null -eq $_.picom_server_port} {
            [PSCustomObject]@{
                "Test Name" = "SCP 3104 PICOM server port";
                "Result" = "Error";
                "Detail" = "PICOM server port not found";
            }
        } 
        {$_.picom_server_port -notin $picom_server_ports}{
            [PSCustomObject]@{
                "Test Name" = "SCP 3104 PICOM server port";
                "Result" = "Error";
                "Detail" = "PICOM server port is set to an incorrect value: $($_.picom_server_port)";
            }
        }
        {$_.picom_server_port -in $picom_server_ports}{
            [PSCustomObject]@{
                "Test Name" = "SCP 3104 PICOM server port";
                "Result" = "Pass";
                "Detail" = "SCP 3104 PICOM server port set correctly.";
            }
        }

    }
}

<#
.SYNOPSIS
    Checks whether needed fields are configured properly in the NDStoreSCPXA file. 
.NOTES
    Only fields that are configured at installation are checked.
.OUTPUTS
    A result hash.
#>
function Test-NdStoreSCPXA {
    $content = Get-Content -Path "C:/Program Files (x86)/ScImage/Picom/NdStoreSCPXA.cfg"
    $result_hash = @{result_type = "NdStoreSCPXA_Config"} 

    $result_hash.Picom_Region_Code = $content |
        Select-String -pattern "^PolDeviceID=([0-9]+)_.*_" |
        %{$_.Matches[0].Groups[1].Value}

    $result_hash.Modality = $content |
        Select-String -pattern "^PolDeviceID=[0-9]+_(.*)_" |
        %{$_.Matches[0].Groups[1].Value}
    
    $result_hash.Remote_DICOM_Server = $content |
        Select-String -pattern "^PicomServerIP=([0-9a-z.]*)" |
        %{$_.Matches[0].Groups[1].Value}
    
    $result_hash.Remote_DICOM_Server = $result_hash.Remote_DICOM_Server.Trim()
    
    $result_hash.Picom_Server_Port = $content |
        Select-String -pattern "^PicomServerPort=([0-9]+)" |
        %{$_.Matches[0].Groups[1].Value}
    
    $result_hash.MRN_Region_Code = $content |
        Select-String -pattern "^\*,\*=([0-9]+)_" |
        %{$_.Matches[0].Groups[1].Value}
    
    $result_hash.remote_dicom_sr_name = $content |
        Select-String -pattern "RemoteDicomSR=(.*)\|.*" |
        %{$_.Matches[0].Groups[1].Value}

    $result_hash.remote_dicom_sr_port = $content |
    Select-String -pattern "RemoteDicomSR=.*\|([0-9]+)" |
        %{$_.Matches[0].Groups[1].Value}
    
    $result_hash.remote_dicom_sr_port = $result_hash.remote_dicom_sr_port.Trim()
    
    $result_hash
}

<#
.SYNOPSIS
    Runs tests on the output of Test-NdStoreSCPXA and returns the test result.
.OUTPUTS
    A PSCustom Object taht contains "Test Name", "Result", and "Detail" keys.
    Result will be either Pass or Error.
#>
function Get-NdStoreSCPXAStatus{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $hub_code
    )
    $result = Test-NdStoreSCPXA
    $picom_server_names = "west.picom365.com","east.picom365.com", "posting.picom365.com"
    $picom_server_ports = "9057", "796"
    switch($result){
        {$null -eq $_.Picom_Region_Code} {
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA PICOM region code";
                "Result" = "Error";
                "Detail" = "MRN Region code not found";
            }
        } 
        {$_.Picom_Region_Code -ne $hub_code}{
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA PICOM Region code";
                "Result" = "Error";
                "Detail" = "Hub code does not match, config file hub code: $($_.mrn_region_code)";
            }
        }
        {$_.Picom_Region_Code -eq $hub_code}{
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA PICOM region code";
                "Result" = "Pass";
                "Detail" = "NdStoreSCPXA PICOM region code set correctly.";
            }
        }
        {$null -eq $_.Modality} {
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA modality";
                "Result" = "Error";
                "Detail" = "NdStoreSCPXA modality not found.";
            }
        } 
        {$_.Modality -ne "NM"}{
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA modality";
                "Result" = "Error";
                "Detail" = "NdStoreSCPXA modality is not NM, current value: $($_.mrn_region_code)";
            }
        }
        {$_.Modality -eq "NM"}{
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA modality";
                "Result" = "Pass";
                "Detail" = "NdStoreSCPXA set correctly.";
            }
        }
        {$null -eq $_.Remote_DICOM_Server} {
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA remote DICOM server";
                "Result" = "Error";
                "Detail" = "remote DICOM server not found";
            }
        } 
        {$_.Remote_DICOM_Server -notin $picom_server_names}{
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA remote DICOM server";
                "Result" = "Error";
                "Detail" = "NdStoreSCPXA remote DICOM server is incorrect.";
            }
        }
        {$_.Remote_DICOM_Server -in $picom_server_names}{
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA remote DICOM server";
                "Result" = "Pass";
                "Detail" = "NdStoreSCPXA remote DICOM server set correctly.";
            }
        }
        {$null -eq $_.Picom_Server_Port} {
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA PICOM server port";
                "Result" = "Error";
                "Detail" = "PICOM server port not found";
            }
        } 
        {$_.Picom_Server_Port -notin $picom_server_ports}{
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA PICOM server port";
                "Result" = "Error";
                "Detail" = "NdStoreSCPXA PICOM server port is incorrect";
            }
        }
        {$_.Picom_Server_Port -in $picom_server_ports}{
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA PICOM server port";
                "Result" = "Pass";
                "Detail" = "NdStoreSCPXA PICOM server port set correctly.";
            }
        }
        {$null -eq $_.MRN_Region_Code} {
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA MRN region code";
                "Result" = "Error";
                "Detail" = "NdStoreSCPXA MRN region code not found";
            }
        } 
        {$_.MRN_Region_Code -ne $hub_code}{
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA MRN region code";
                "Result" = "Error";
                "Detail" = "NdStoreSCPXA MRN region code is incorrect";
            }
        }
        {$_.MRN_Region_Code -eq $hub_code}{
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA MRN region code";
                "Result" = "Pass";
                "Detail" = "NdStoreSCPXA MRN region code is correct.";
            }
        }
        {$null -eq $_.remote_dicom_sr_name} {
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA DICOM SR name";
                "Result" = "Error";
                "Detail" = "NdStoreSCPXA DICOM SR name not found.";
            }
        } 
        {$_.remote_dicom_sr_name -notin $picom_server_names}{
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA DICOM SR name";
                "Result" = "Error";
                "Detail" = "NdStoreSCPXA DICOM SR name is incorrect.";
            }
        }
        {$_.remote_dicom_sr_name -in $picom_server_names}{
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA DICOM SR name";
                "Result" = "Pass";
                "Detail" = "NdStoreSCPXA DICOM SR name is correct";
            }
        }
        {$null -eq $_.remote_dicom_sr_port} {
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA DICOM SR port";
                "Result" = "Error";
                "Detail" = "NdStoreSCPXA DICOM SR port not found.";
            }
        } 
        {$_.remote_dicom_sr_port -notin $picom_server_ports}{
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA DICOM SR port";
                "Result" = "Error";
                "Detail" = "NdStoreSCPXA DICOM SR port is incorrect.";
            }
        }
        {$_.remote_dicom_sr_port -in $picom_server_ports}{
            [PSCustomObject]@{
                "Test Name" = "NdStoreSCPXA DICOM SR port";
                "Result" = "Pass";
                "Detail" = "NdStoreSCPXA DICOM SR port is correct";
            }
        }
    }
}

<#
.SYNOPSIS
    Checks configuration settings in Picom.ini file. 
.NOTES
    Only checks field configured at installation.
.OUTPUTS
    A result hash.
#>
function Test-PicomIni {
    $content = Get-Content -Path "C:/Program Files (x86)/ScImage/Picom/Picom.ini"
    $result_hash = @{result_type = "Picom_Ini"} 

    $result_hash.License_Region_Code = $content |
        Select-String -pattern "^LicenseSources=([0-9]+)_.*" |
        %{$_.Matches[0].Groups[1].Value}
    
    $result_hash.License_Modality = $content |
        Select-String -pattern "^LicenseSources=[0-9]+_([A-Z]{2}).*" |
        %{$_.Matches[0].Groups[1].Value}
    
    $result_hash.License_Device_Name = $content |
        Select-String -pattern "^LicenseDeviceName=DIG-(.*)-2078.*" |
        %{$_.Matches[0].Groups[1].Value}

    

    $result_hash
}

<#
.SYNOPSIS
    Runs tests on the output of Test-PicomIni and returns the test result.
.OUTPUTS
    A PSCustom Object taht contains "Test Name", "Result", and "Detail" keys.
    Result will be either Pass or Error.
#>
function Get-PicomIniStatus{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $hub_code,
        [Parameter()]
        [string]
        $computer_name
    )
    $result = Test-PicomIni
    switch($result){
        {$null -eq $_.License_Region_Code} {
            [PSCustomObject]@{
                "Test Name" = "PICOM ini license region code";
                "Result" = "Error";
                "Detail" = "PICOM ini license region code not found";
            }
        } 
        {$_.License_Region_Code -ne $hub_code}{
            [PSCustomObject]@{
                "Test Name" = "PICOM ini license region code";
                "Result" = "Error";
                "Detail" = "PICOM ini license region code is incorrect.";
            }
        }
        {$_.License_Region_Code -eq $hub_code}{
            [PSCustomObject]@{
                "Test Name" = "PICOM ini license region code";
                "Result" = "Pass";
                "Detail" = "PICOM ini license region code is correct";
            }
        }
        {$null -eq $_.License_Modality} {
            [PSCustomObject]@{
                "Test Name" = "PICOM ini license modality";
                "Result" = "Error";
                "Detail" = "PICOM ini license modality not found";
            }
        } 
        {$_.License_Modality -ne "NM"}{
            [PSCustomObject]@{
                "Test Name" = "PICOM ini license modality";
                "Result" = "Error";
                "Detail" = "PICOM ini license modality is incorrect.";
            }
        }
        {$_.License_Modality -eq "NM"}{
            [PSCustomObject]@{
                "Test Name" = "PICOM ini license modality";
                "Result" = "Pass";
                "Detail" = "PICOM ini license modality is correct";
            }
        }
        {$null -eq $_.License_Device_Name} {
            [PSCustomObject]@{
                "Test Name" = "PICOM ini license device name";
                "Result" = "Error";
                "Detail" = "PICOM ini license device name not found";
            }
        } 
        {$_.License_Device_Name -ne $computer_name}{
            [PSCustomObject]@{
                "Test Name" = "PICOM ini license device name";
                "Result" = "Error";
                "Detail" = "PICOM ini license device name is incorrect.";
            }
        }
        {$_.License_Device_Name -eq $computer_name}{
            [PSCustomObject]@{
                "Test Name" = "PICOM ini license device name";
                "Result" = "Pass";
                "Detail" = "PICOM ini license device name is correct";
            }
        }
    }
}

<#
.SYNOPSIS
    Checks the status of the PICOM TSM service.
.OUTPUTS
    A result hash.
#>
function Test-PicomTSMService {
    $result_hash = @{result_type = "PICOM_TSM"}
    $service_status = Get-Service | where name -eq "PICOM TSM"
    if ($null -eq $service_status){
        $result_hash.TSM_Service_Status = "Service not registered"
    } elseif ($service_status.Status -ne "Running"){
        $result_hash.TSM_Service_Status = "Service not started"
    } else {
        $result_hash.TSM_Service_Status = "Service running"
    }

    $result_hash
}

<#
.SYNOPSIS
    Runs tests on the output of Test-PicomTSMService and returns the test result.
.OUTPUTS
    A PSCustom Object that contains "Test Name", "Result", and "Detail" keys.
    Result will be either Pass or Error.
#>
function Get-PicomTSMServiceStaus{
    $result = Test-PicomTSMService
    switch ($result) {
        {$_.TSM_Service_Status -eq "Service not registered"}{
            [PSCustomObject]@{
                "Test Name" = "Picom TSM Service";
                "Result" = "Error";
                "Detail" = "Picom TSM Service is not registered.";
            }
        }
        {$_.TSM_Service_Status -eq "Service not started"}{
            [PSCustomObject]@{
                "Test Name" = "Picom TSM Service";
                "Result" = "Error";
                "Detail" = "Picom TSM Service is not started.";
            }
        }
        {$_.TSM_Service_Status -eq "Service running"}{
            [PSCustomObject]@{
                "Test Name" = "Picom TSM Service";
                "Result" = "Pass";
                "Detail" = "Picom TSM Service is running.";
            }
        }
    }
}

<#
.SYNOPSIS
    Checks if there is a connection to the internet.
.NOTES
    Performs ping test against google DNS.
.OUTPUTS
    A result hash.
#>
function Test-InternetConnection{
    $result_hash = @{result_type = "Internet_Connection"}
    $result_hash.google_ping_test = (Test-NetConnection 8.8.8.8).PingSucceeded
    $result_hash
}

<#
.SYNOPSIS
    Runs tests on the output of Test-InternetConnection and returns the test result.
.OUTPUTS
    A PSCustom Object taht contains "Test Name", "Result", and "Detail" keys.
    Result will be either Pass or Error.
#>
function Get-InternetConnectionStatus{
    $result = Test-InternetConnection

    if ($result.google_ping_test) {
            [PSCustomObject]@{
                "Test Name" = "Internet connection test";
                "Result" = "Pass";
                "Detail" = "Can ping 8.8.8.8";
            }
    } else{
            [PSCustomObject]@{
                "Test Name" = "Internet connection test";
                "Result" = "Error";
                "Detail" = "Cannot ping 8.8.8.8";
            }
    }
}

<#
.SYNOPSIS
    Checks connection to camera system using ICMP and a connection to TCP 3389.
.NOTES
    This test runs both the ping test and the TCP connection test for RDP.
.OUTPUTS
    A result hash.
#>
function Test-XPConnection {
    $result_hash = @{result_type = "XP_Connection"}
    $wired_network_interface = Get-ConnectedInterfaces | Test-Type1NetworkAddress
    if ($wired_network_interfaces.type1_network_address -eq "not_found"){
        $result_hash.rdp_test = "not_performed"
        $result_hash.ping_test = "not_performed"
    } else {
        $XP_IP_Octets = $wired_network_interface.type1_network_address.split(".")
        $XP_IP = "$($XP_IP_Octets[0]).$($XP_IP_Octets[1]).$($XP_IP_Octets[2]).130"

        $result_hash.rdp_test = (Test-NetConnection $XP_IP -RemotePort 3389).TcpTestSucceeded
        $result_hash.ping_test = (Test-NetConnection $XP_IP).PingSucceeded
    }
    $result_hash
}

<#
.SYNOPSIS
    Runs tests on the output of Test-XPConnection and returns the test result for ICMP.
.OUTPUTS
    A PSCustom Object taht contains "Test Name", "Result", and "Detail" keys.
    Result will be either Pass or Error.
#>
function Get-XPConnectionPingStatus {
    $result = Test-XPConnection
    switch($result){
        {"not_performed" -eq $_.ping_test }{
            [PSCustomObject]@{
                "Test Name" = "XP Ping";
                "Result" = "Error";
                "Detail" = "XP Ping RDP not performed - no suitabl IP found. Check IP configuration tests.";
            }
            Break
        }
        {$_.ping_test -eq $false}{
            [PSCustomObject]@{
                "Test Name" = "XP Ping";
                "Result" = "Error";
                "Detail" = "XP Ping failed to ping.";
            }
            Break
        }
        {$_.ping_test -eq $true}{
            [PSCustomObject]@{
                "Test Name" = "XP Ping";
                "Result" = "Pass";
                "Detail" = "XP Ping passed.";
            }
            Break
        }
    }
}

<#
.SYNOPSIS
    Runs tests on the output of Test-XPConnection and returns the test result for RDP.
.OUTPUTS
    A PSCustom Object taht contains "Test Name", "Result", and "Detail" keys.
    Result will be either Pass or Error.
#>
function Get-XPConnectionRDPStatus {
    $result = Test-XPConnection
    switch($result){
        {  "not_performed" -eq $_.rdp_test}{
            [PSCustomObject]@{
                "Test Name" = "XP Connection RDP";
                "Result" = "Error";
                "Detail" = "XP Connection RDP test not performed - no suitable IP found.  Check IP configuration tests.";
            }
            Break
        }
        {$_.rdp_test -eq $false}{
            [PSCustomObject]@{
                "Test Name" = "XP Connection RDP";
                "Result" = "Error";
                "Detail" = "XP Connection RDP test failed to connect.";
            }
            Break
        }
        {$_.rdp_test -eq $true}{
            [PSCustomObject]@{
                "Test Name" = "XP Connection RDP";
                "Result" = "Pass";
                "Detail" = "XP Connection RDP passed.";
            }
            Break
        }
    }
}

<#
.SYNOPSIS
    Checks connectvity to the Fortigate interface. 
.NOTES
    If we change how addressing is handled by the Fortigate we will need to update this check.
.OUTPUTS
    A result hash.
#>
function Test-FGConnection {
    $result_hash = @{result_type = "FG_Connection"}
    $wired_network_interface = Get-ConnectedInterfaces | Test-Type1NetworkAddress
    if ($wired_network_interfaces.type1_network_address -eq "not_found"){
        $result_hash.ping_tech_side = "not_performed"
    } else {
        $FG_IP_Octets = $wired_network_interface.type1_network_address.split(".")
        $FG_Tech_IP = "$($FG_IP_Octets[0]).$($FG_IP_Octets[1]).$($FG_IP_Octets[2]).1"

        $result_hash.ping_tech_side = (Test-NetConnection $FG_Tech_IP).PingSucceeded
    }
    $result_hash
}

<#
.SYNOPSIS
    Runs tests on the output of Test-FGConnection and returns the test result for ICMP.
.OUTPUTS
    A PSCustom Object taht contains "Test Name", "Result", and "Detail" keys.
    Result will be either Pass or Error.
#>
function Get-FGConnectionStatus{
    $result = Test-FGConnection
    switch($result){
        {  "not_performed" -eq $result.ping_tech_side}{
            [PSCustomObject]@{
                "Test Name" = "FG Ping technician side";
                "Result" = "Error";
                "Detail" = "FG Ping technician side not performed - no suitable IP found.";
            }
        }
        {$result.ping_tech_side -eq $false}{
            [PSCustomObject]@{
                "Test Name" = "FG Ping technician side";
                "Result" = "Error";
                "Detail" = "FG Ping technician side ping failed.";
            }
        }
        {$result.ping_tech_side -eq $true}{
            [PSCustomObject]@{
                "Test Name" = "FG Ping technician side";
                "Result" = "Pass";
                "Detail" = "FG Ping technician side ping succeeded.";
            }
        }
    }
}
<#
.SYNOPSIS
    Checks configuration of firewall rules. 
.NOTES
    This must be run in an administrative shell.
.OUTPUTS
    A result hash.
#>
function Test-FirewallRules{
    $result_hash = @{result_type = "Firewall_Rules"}
    $PICOMFirewallRules = Get-NetFirewallRule -PolicyStore ActiveStore |
        where DisplayName -like "*ScImage*"

    if ($PICOMFirewallRules -eq $null){
         $result_hash.Picom_Rule_Present = "false"
    } else {
         $result_hash.Picom_Rule_Present = "true"
    }
    $result_hash
}

<#
.SYNOPSIS
    Runs tests on the output of Test-FirewalRules and returns the test result for ICMP.
.OUTPUTS
    A PSCustom Object taht contains "Test Name", "Result", and "Detail" keys.
    Result will be either Pass or Error.
#>
function Get-FirewallRulesStatus{
    $result = Test-FirewallRules
    switch($result){
        {$_.Picom_Rule_Present -eq "false"}{
            [PSCustomObject]@{
                "Test Name" = "PICOM Firewall rule present";
                "Result" = "Error";
                "Detail" = "PICOM Firewall rule is not present.";
            }
        }
        {$_.Picom_Rule_Present -eq "true"}{
            [PSCustomObject]@{
                "Test Name" = "PICOM Firewall rule present";
                "Result" = "Pass";
                "Detail" = "PICOM Firewall rule is present.";
            }
        }
    }
}

<#
.SYNOPSIS
    Checks the number of days the computer has been online.
.NOTES
    CIM providers are used rather than the dedicated PowerShell command for accessing uptime for
    compatibility reasons.  Only the most recent versions of PowerShell have a command available for
    checking uptime directly.
.OUTPUTS
    A result hash.
#>
function Get-UptimeStaus{
    $daysUP = (New-TimeSpan -start (Get-CimInstance -ClassName win32_operatingsystem | Select-Object -exp LastBootUpTime) -end (Get-Date)).Days
    if ($daysUp -gt 5){
            [PSCustomObject]@{
                "Test Name" = "System Uptime";
                "Result" = "Error";
                "Detail" = "System has not been restarted in one week.";
            }
    } else {
            [PSCustomObject]@{
                "Test Name" = "System Uptime";
                "Result" = "Pass";
                "Detail" = "System has been restarted this week.";
            }
    }
}
<#
.SYNOPSIS
    Sends diagnostic info to Azure blob storage.
.DESCRIPTION
    If results are passed as an argument they are sent to Azure blob storage. 
    If no results are given then all tests are run using Run-PICOMTroubleShooting.
.NOTES
    Base uri and SAS token will eventually expire and will need to be renewed in the Azure portal.
    Should consider factoring this in to a configuration file or env variable, but we need to know
    how we will distribute the script before we can do that.
.OUTPUTS
    Returns the Azure blob URL wher diag logs can be viewed.
#>


function Send-DiagnosticInfo{
    param (
        [Parameter()]
        [object]
        $results
    )

    $baseUri = "https://digiradtypeonediag.blob.core.windows.net/diaglogs"
    $SASToken = "sv=2021-06-08&ss=b&srt=co&sp=rwactfx&se=2024-02-07T07:23:15Z&st=2023-02-06T23:23:15Z&spr=https&sig=umTtYC8fKGSez4Oe5CfsG00%2BdRTYk1%2FBAB8lvH8TltA%3D"

    $comptuer_name = $env:COMPUTERNAME
    $timeStamp = Get-Date -Format o | % {$_ -replace ":", ""} | %{$_ -replace "\.", ""}
    $fileName = "$($comptuer_name)-$($timeStamp)"
    $uploadUrl = "$($baseUri)/$($fileName)?$($SASToken)"
    $headers = @{
            'x-ms-blob-type' = 'BlockBlob'
        }
    if($null -eq $results){
        Run-PICOMTroubleShooting | Out-String | Invoke-RestMethod -Uri $uploadUrl -Headers $headers -Method Put
    } else {
        $results |  Out-String | Invoke-RestMethod -Uri $uploadUrl -Headers $headers -Method Put
    }

    $uploadUrl
}
<#
.SYNOPSIS
    Creates a user test tracker custom object that is used to keep track of the final results of all
    tests run by the Run-UserTests cmdlet.
.DESCRIPTION
    The tracking object returned must have keys that represent each test to be performed by Run-UserTest.
.OUTPUTS
    A custom PS object that includes tracking keys.
#>


function Create-UserTestTracker{
    #These are the keys for the tracked tests.  If a new test is added you need to 
    #include it here.
    $test_status = [PSCustomObject]@{
        EthernetStatus= $false
        InternetStatus = $false
        Type1NetworkAddress = $false
        XPPingStatus = $false
        XPRDPStatus = $false
        FGConnectionStatus = $false
        ContinueTesting = $true
    }
    #Checks if all tests configured on the object have passed.
    $all_passed_method = {
        $passed = $true
        foreach($test in $this.psobject.properties.name){
            if ($test -eq "UserAbort"){
                continue
            }
            if (-not $this.$test){
                $passed = $false
            }
        }
        return $passed
    }

    $mem_param = @{
        MemberType = "ScriptMethod"
        InputObject = $test_status
        Name = "AllPassed"
        Value = $all_passed_method
    }

    Add-Member @mem_param

    return $test_status
}

<#
.SYNOPSIS
    Function for retrieving user input to continue, quit, or retry tests.
.DESCRIPTION
    The function translates the characters provided by the user into more explicit 
    strings that are used by other functions to know how to execute next steps.
.OUTPUTS
    A string representing the action chosen by the user.
#>

function Get-UserInput{
    param(
        $UserMessage = "Press c to Continue to next test; Press r to Retry this test; Press q to Quit all Testing"
    )
    while($true){
        $user_input = Read-Host($UserMessage)
        switch($user_input){
            "c" {
                return "continue"
            }
            "r"{
                return "retry"
            }
            "q" {
                return "quit"
            }
            Default {
                "Invalid input"
            }
        }
    }
}

<#
.SYNOPSIS
    Function for handling the generic actions involved with running a user test including user input
    and output.
.DESCRIPTION
    Receives a test function, a test tracking object, and test metadata and performs the given test and records
    the results on the testing object.  Also handles displaying results to the user and gathering input from
    the user using the Get-UserInput function.
.NOTES
    The key provided as Tracker key must match one of the keys that is configured on the tracker object
    constructor function.
#>
function Run-UserTest{
    param(
        $TestTracker,
        $TrackerKey,
        $TestCmdLet,
        $SuccessMessage,
        $FailureMessage
    )
    Write-Host "Running user test $TrackerKey"
    if (-not $TestTracker.ContinueTesting){
        return
    } 
    $status = Invoke-Command $TestCmdLet 
    if($status.Result -eq "Pass"){
        Write-Host($SuccessMessage) -ForegroundColor Yellow -BackgroundColor DarkGreen
        $TestTracker.$TrackerKey = $true
        return
    }else{
        Write-Host($FailureMessage) -ForegroundColor Yellow -BackgroundColor DarkRed 
        $user_choice = Get-UserInput
        switch($user_choice){
            "continue"{
                $es = Invoke-Command $TestCmdLet
                if($es.Result -eq "Pass"){
                    $TestTracker.$TrackerKey = $true
                }
                return
            }
            "retry"{
                break
            }
            "quit"{
                $TestTracker.ContinueTesting = $false
                return
            }
        }
    }
}
<#
.SYNOPSIS
    Takes a test tracker and outputs the testing result to the user and prompts for input.
.OUTPUTS
    A testtracker object.
#>


function Summarize-Results{
    param(
        $TestTracker
    )

    if($TestTracker.AllPassed()){
        Write-Host "Testing is complete and all tests are passing!  If you are still having problems please create a helpdesk ticket"
    }else{
        $user_choice = Get-UserInput -UserMessage "Testing has completed with errors, press r or c to re-run tests or q to quit.  If you need help please create a helpdesk ticket"
        switch($user_choice){
            "continue"{
                $TestTracker.ContinueTesting = $false
                return
            }
            "quit"{
                $TestTracker.ContinueTesting = $false
                return
            }
            "retry"{
               return 
            }
            Default{
                $TestTracker.ContinueTesting = $false
                return
            }
        }
    }
}
<#
.SYNOPSIS
    A runner function that creates a test tracker and runs configured tests.
.DESCRIPTION
    There is not much to this function. It will continue to run tests as long as the 
    tracker ContinueTesting attribute is set to true.  If new tests need to be added they
    must be added as a Run-UserTest call in the body of the while loop.
#>
function Run-UserTests{
    $tracker = Create-UserTestTracker
    while((-not $tracker.AllPassed()) -and $tracker.ContinueTesting){
        Run-UserTest -TestTracker $tracker -TrackerKey "EthernetStatus" `
            -TestCmdLet {Get-ConnectedEthernetStatus} `
            -SuccessMessage "Ethernet connection test passed!" `
            -FailureMessage "Network cable is not connected. Please connect an ethernet cable to the laptop and port 1 on the FortiGate and the Fortigate is online."

        Run-UserTest -TestTracker $tracker -TrackerKey "InternetStatus" `
            -TestCmdLet {Get-InternetConnectionStatus} `
            -SuccessMessage "You can reach the internet!" `
            -FailureMessage "Unable to reach the internet!  You may not be able to upload studies to ScImage and IT will not be able to help you remotely.  Contact IT at your site for help connecting to the internet."

        Run-UserTest -TestTracker $tracker `
            -TrackerKey "Type1NetworkAddress" `
            -TestCmdLet {Get-Type1NetworkAddressStatus} `
            -SuccessMessage "Ethernet interface is assigned a valid IP!" `
            -FailureMessage "Wired network has an incorrect IP address!  Please make sure that the laptop is connected to Port 2 on the FortiGate and the FortiGater is online."
        
        Run-UserTest -TestTracker $tracker `
            -TrackerKey "XPPingStatus" `
            -TestCmdLet {Get-XPConnectionPingStatus} `
            -SuccessMessage "Camera computer is reachable!" `
            -FailureMessage "Camera Computer is not reachable!  Please make sure that the camera computer is online and connected to port 1 of the FortiGate"

        Run-UserTest -TestTracker $tracker `
            -TrackerKey "XPRDPStatus" `
            -TestCmdLet {Get-XPConnectionRDPStatus} `
            -SuccessMessage "Can remote into camera computer!" `
            -FailureMessage "Cannot remote into camera computer!  Please make sure that the camera computer is online and connected to port 1 of the FortiGate"
        
        Run-UserTest -TestTracker $tracker `
            -TrackerKey "FGConnectionStatus" `
            -TestCmdLet {Get-FGConnectionStatus} `
            -SuccessMessage "FortiGate is reachable!" `
            -FailureMessage "FortiGate is not reachable!  Please make sure the FortiGate is plugged in and online, and that your laptop is connected to it on port 2"
        
        Summarize-Results -TestTracker $tracker
    }
    $tracker
}
<#
.SYNOPSIS
    Runs all tests.
#>


function Run-AllTests{
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true)]
        [string]
        $hub_code
    )

    $computer_name = $env:COMPUTERNAME

    Get-SSLVPNInterfaceStatus
    Get-ConnectedEthernetStatus
    Get-Type1NetworkAddressStatus
    Get-PicomListeningStatus
    Get-ConfigFilesExistStatus
    Get-LicenseFileExistStatus
    Get-SCP3104ConfigStatus -hub_code $hub_code
    Get-NdStoreSCPXAStatus -hub_code $hub_code
    Get-PicomIniStatus -hub_code $hub_code -computer_name $computer_name
    Get-PicomTSMServiceStaus
    Get-XPConnectionRDPStatus
    Get-XPConnectionPingStatus
    Get-FirewallRulesStatus
    Get-FGConnectionStatus
    Get-UptimeStaus

}

<#
.SYNOPSIS
    Runs all test and outputs the result.
.INPUTS
    Requires the hub code for validating configuration files.  Can optionally provide
    an orderby argument that will determine in what order the test results will be 
    displayed.
#>
function Run-PICOMTroubleShooting{
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true)]
        [string]
        $hub_code,
        [Parameter()]
        [string]
        $order_by = "test"
    )
   $output = Run-AllTests -hub_code $hub_code  

   $ordering = "Passed", "Warning", "Error"

   if($order_by -eq "test"){
           $output
           Send-DiagnosticInfo -results $output
   } else{
           $output | Sort-Object {$ordering.IndexOf($_.Result)}     
           Send-DiagnosticInfo -results $output
   }
}
