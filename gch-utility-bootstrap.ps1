Start-Transcript -Path $PSScriptRoot\bootstrap.log -Append -ErrorAction SilentlyContinue
$session = (query session $env:USERNAME)
if ($session -match '^>rdp'){
    write-output "running in RDP!"    
}elseif ($session -match '^>console'){
    write-output "running in Console!"    
} else {
    write-output $session
}

Stop-Transcript -ErrorAction SilentlyContinue