[CmdletBinding]
Get-Process -OutVariable Stuff
$Stuff
"MP=$Stuff" >> $env:GITHUB_ENV
