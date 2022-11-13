[CmdletBinding]
Get-Service -OutVariable Stuff
$Stuff
"MP=$Stuff" >> $env:GITHUB_ENV
