[CmdletBinding]
Get-Process -OutVariable Stuff
$Stuffed = $Stuff | Out-String
"MP=$Stuff" >> $env:GITHUB_ENV
