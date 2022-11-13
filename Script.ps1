[CmdletBinding]
Get-ChildItem ./ -Recurse -OutVariable Stuff

Write-Output $Stuff >> $GITHUB_STEP_SUMMARY
