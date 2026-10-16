$bytes = [System.IO.File]::ReadAllBytes('C:\Шестаков\Code\vscode\projects\HOSTS\hosts_advanced.txt')
Write-Host "First 10 bytes:"
$bytes[0..9] | ForEach-Object { Write-Host $_.ToString('X2') }

Write-Host ""
Write-Host "Check for BOM (EF BB BF):"
if ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
    Write-Host "BOM detected"
} else {
    Write-Host "No BOM"
}

Write-Host ""
Write-Host "Check line endings:"
$content = [System.IO.File]::ReadAllText('C:\Шестаков\Code\vscode\projects\HOSTS\hosts_advanced.txt')
$crlfCount = ([regex]::Matches($content, "`r`n")).Count
$lfCount = ([regex]::Matches($content, "(?<!`r)`n")).Count
Write-Host "CRLF count: $crlfCount"
Write-Host "LF only count: $lfCount"

Write-Host ""
Write-Host "First 3 lines hex dump:"
$lines = [System.IO.File]::ReadAllLines('C:\Шестаков\Code\vscode\projects\HOSTS\hosts_advanced.txt')
for ($i = 0; $i -lt [Math]::Min(3, $lines.Count); $i++) {
    $lineBytes = [System.Text.Encoding]::UTF8.GetBytes($lines[$i])
    $hex = ($lineBytes | ForEach-Object { $_.ToString('X2') }) -join ' '
    Write-Host "Line $($i+1): $hex"
    Write-Host "  Text: $($lines[$i])"
}
