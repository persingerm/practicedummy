[CmdletBinding]
Get-Process -OutVariable Stuff
[string[]]$Stuffed = $Stuff
"MP=$Stuffed" >> $env:GITHUB_ENV
