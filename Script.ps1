[CmdletBinding]
Get-ChildItem ./ -Recurse -OutVariable Stuff
$Stuff
bash -c 'echo "$Stuff >> $GITHUB_STEP_SUMMARY"'
