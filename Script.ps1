[CmdletBinding]
Get-Process -OutVariable Stuff
$Stuffed = ($Stuff.Name | Out-String)
"MP=$Stuffed" >> $env:GITHUB_ENV
