Get-ChildItem ./ -Recurse

Write-Output 'script said some things' >> $GITHUB_STEP_SUMMARY
