# Run wix with its arguments; echo everything; re-emit each WiX error/warning line as a GitHub
# annotation (::error:: / ::warning::) so a failed build is diagnosable from the public API.
$out = & wix @args 2>&1 | ForEach-Object { "$_" }
$rc = $LASTEXITCODE
foreach ($l in $out) {
    Write-Host $l
    if ($l -match '\berror\b') { Write-Host "::error title=wix::$l" }
    elseif ($l -match '\bwarning\b') { Write-Host "::warning title=wix::$l" }
}
exit $rc
