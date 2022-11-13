[CmdletBinding]
Get-ChildItem ./ -Recurse -OutVariable Stuff
$Stuff
bash echo "$($Stuff.Name) >> $GITHUB_STEP_SUMMARY"
