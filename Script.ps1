[CmdletBinding]
Get-ChildItem ./ -Recurse -OutVariable Stuff
$Stuff
"MP=$Stuff" >> $env:GITHUB_ENV
