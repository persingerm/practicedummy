[CmdletBinding]
Get-Process -OutVariable Stuff
$Stuff | Out-String
"MP=$Stuffed" >> $env:GITHUB_ENV
