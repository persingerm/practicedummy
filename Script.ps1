[CmdletBinding]
Get-Process -OutVariable Stuff
$Stuffed = $Stuff | Out-String
"MP=$Stuffed" >> $env:GITHUB_ENV
