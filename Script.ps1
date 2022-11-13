[CmdletBinding]
Get-Process -OutVariable Stuff
$Stuffed = $Stuff | ForEach-Object {($_).ToString()}
"MP=$Stuffed" >> $env:GITHUB_ENV
