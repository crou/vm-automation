# this is an initial setup for a vm
Start-Transcript -Path $psscriptroot\transcript.log -Force -ErrorAction SilentlyContinue
write-output "Sample output"
write-output "Sample output from $psscriptroot"
Get-ChildItem env:\ | Out-File -FilePath "$psscriptroot\output.txt" -Force
Stop-Transcript -ErrorAction SilentlyContinue