function Get-ConnectedInterfaces {

 Get-NetIPConfiguration | Where-Object {$_.NetAdapter.status -ne "Disconnected"}
}

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
function Test-PicomListening{
    $result_hash = @{result_type="Picom_Listening"}
    $listening = Get-NetTCPConnection -State Listen |
    Where-Object {$_.LocalPort -in "3104", "3105"}

    foreach ($port in $listening) {
        $result_hash[$port.LocalPort.ToString()] = "listening"
    } 

    $result_hash
}

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
    } elseif ($result.ini_file_count -ne 2){
        [PSCustomObject]@{
            "Test Name" = "Config Files Exist";
            "Result" = "Warn";
            "Detail" = "picom.ini file missing."
        }
    }
}
function Test-LicenseFileExist{
    $result_hash = @{result_type="License_File_Exist"}
    $lic_count = Get-ChildItem -Path "C:/Program Files (x86)/ScImage/Picom" |
    Where-Object {($_.name -like "*.plic*")}  |
    Measure-Object

    $result_hash.license_file_count = $lic_count.count
    $result_hash
}
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

function Test-PicomIni {
    $content = Get-Content -Path "C:/Program Files (x86)/ScImage/Picom/Picom.ini"
    $result_hash = @{result_type = "Picom_Ini"} 

    $result_hash.License_Region_Code = $content |
        Select-String -pattern "^LicenseSources=([0-9]+)_.*" |
        %{$_.Matches[0].Groups[1].Value}
    
    $result_hash.License_Modality = $content |
        Select-String -pattern "^LicenseSources=[0-9]+_(.*)" |
        %{$_.Matches[0].Groups[1].Value}
    
    $result_hash.License_Device_Name = $content |
        Select-String -pattern "^LicenseDeviceName=(.*)" |
        %{$_.Matches[0].Groups[1].Value}

    $result_hash
}

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
    $computer_code = "DIG-$($computer_name)-2078"
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
        {$_.License_Device_Name -ne $computer_code}{
            [PSCustomObject]@{
                "Test Name" = "PICOM ini license device name";
                "Result" = "Error";
                "Detail" = "PICOM ini license device name is incorrect.";
            }
        }
        {$_.License_Device_Name -eq $computer_code}{
            [PSCustomObject]@{
                "Test Name" = "PICOM ini license device name";
                "Result" = "Pass";
                "Detail" = "PICOM ini license device name is correct";
            }
        }
    }
}

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

function Get-XPConnectionStatus {
    $result = Test-XPConnection
    switch($result){
        {  "not_performed" -eq $_.rdp_test}{
            [PSCustomObject]@{
                "Test Name" = "XP Connection RDP";
                "Result" = "Error";
                "Detail" = "XP Connection RDP test not performed - no suitable IP found.  Check IP configuration tests.";
            }
        }
        {$_.rdp_test -eq $false}{
            [PSCustomObject]@{
                "Test Name" = "XP Connection RDP";
                "Result" = "Error";
                "Detail" = "XP Connection RDP test failed to connect.";
            }
        }
        {$_.rdp_test -eq $true}{
            [PSCustomObject]@{
                "Test Name" = "XP Connection RDP";
                "Result" = "Pass";
                "Detail" = "XP Connection RDP passed.";
            }
        }
        {"not_performed" -eq $_.ping_test }{
            [PSCustomObject]@{
                "Test Name" = "XP Ping RDP";
                "Result" = "Error";
                "Detail" = "XP Ping RDP not performed - no suitabl IP found. Check IP configuration tests.";
            }
        }
        {$_.ping_test -eq $false}{
            [PSCustomObject]@{
                "Test Name" = "XP Ping RDP";
                "Result" = "Error";
                "Detail" = "XP Ping RDP failed to ping.";
            }
        }
        {$_.ping_test -eq $true}{
            [PSCustomObject]@{
                "Test Name" = "XP Ping RDP";
                "Result" = "Pass";
                "Detail" = "XP Ping passed.";
            }
        }
    }
}

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

function Run-PICOMTroubleShooting{
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
    Get-XPConnectionStatus
    Get-FGConnectionStatus
}