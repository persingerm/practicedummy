[CmdletBinding]
Get-Process -OutVariable Stuff
$Stuffed = ($Stuff | Select-Object Name | Out-String)
"MP=$Stuffed" >> $env:GITHUB_ENV
