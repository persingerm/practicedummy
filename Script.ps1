[CmdletBinding]
Get-Process -OutVariable Stuff
$Stuffed = ($Stuff | Out-String) -join ','
"MP=$Stuffed" >> $env:GITHUB_ENV
