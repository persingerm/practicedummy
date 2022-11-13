[CmdletBinding]
Get-Process -OutVariable Stuff
"MP=$Stuff" >> $env:GITHUB_ENV
