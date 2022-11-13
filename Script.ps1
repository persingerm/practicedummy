[CmdletBinding]
Get-ChildItem ./ -Recurse -OutVariable Stuff
$Stuff
bash -c "echo $($Stuff).Name >> $GITHUB_STEP_SUMMARY"
