[CmdletBinding]
Get-ChildItem ./ -Recurse -OutVariable Stuff
$Stuff
$Stuff >> $GITHUB_STEP_SUMMARY
