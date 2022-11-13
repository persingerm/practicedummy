[CmdletBinding]
Get-ChildItem ./ -Recurse -OutVariable Stuff
$Stuff
bash "echo $Stuff >> $GITHUB_STEP_SUMMARY"
