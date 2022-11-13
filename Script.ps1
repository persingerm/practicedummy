[CmdletBinding]
Get-Process -OutVariable Stuff
$Stuffed = $Stuff.ToString()
"MP=$Stuffed" >> $env:GITHUB_ENV
