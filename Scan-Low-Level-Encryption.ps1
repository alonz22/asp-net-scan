function Check-LowLevelEncryption {
    param($file)

    $content = Get-Content -Path $file

    $lineNumber = 0
    $matchesFound = $false
    $matchCounter = 0  # Initialize match counter

    foreach ($line in $content) {
        $lineNumber++

        if ($line -match '(?i)\b(?:md5|GetMD5Hash|sha1|base64|des|rc4|rot13)\(') {
            Write-Host "Warning: Low-level encryption method detected in: $file (Line: $lineNumber)`n" -ForegroundColor Red
            Write-Host "Line: $line`n"
            $matchesFound = $true
            $matchCounter++  # Increment the match counter
        }

        if ($line -match '(?i)\bSHA256\b') {
            Write-Host "Warning: sha256 encryption method was detected in: $file (Line: $lineNumber)`n"
            Write-Host "Line: $line`n"
            Write-Host "Consider using sha512, or best, use bcrypt for stronger security.`n" -ForegroundColor Red
            $matchesFound = $true
            $matchCounter++  # Increment the match counter
        }
    }

    return $matchesFound, $matchCounter
}

# Prompt user for path to scan
$path = Read-Host "Enter the path to scan"

# Check if the path is valid
if (-not (Test-Path $path -PathType Container)) {
    Write-Output "Invalid path. Please provide a valid directory path."
    exit
}

# Get all .aspx files in the given path recursively
$aspxFiles = Get-ChildItem -Path $path -Filter "*.aspx" -Recurse

$matchesFound = $false
$matchCounter = 0  # Initialize total match counter
foreach ($file in $aspxFiles) {
    $matches, $count = Check-LowLevelEncryption $file.FullName
    if ($matches) {
        $matchesFound = $true
        $matchCounter += $count  # Add the current file's match count to the total counter
    }
}

if ($matchesFound) {
    Write-Host "Using low-level encryption methods such as MD5, SHA1, and base64 is highly discouraged in ASP.NET as they are susceptible to modern cryptographic attacks. 
    `nReplace these weak algorithms with stronger ones like SHA512 or bcrypt to ensure robust data protection.`n" -ForegroundColor DarkYellow

    # Calculate the score based on the total match count
    $score = if ($matchCounter -ge 1) {
        "3/10"
        $Severity = "Medium"
    } if ($matchCounter -ge 2) {
        "5/10"
        $Severity = "Medium"
    } if ($matchCounter -ge 3) {
        "7/10"
        $Severity = "Hgih"
    } 
    if ($matchCounter -ge 5) {
        "9.8/10"
        $Severity = "Critical"
    }
    
     Write-Host "`nTotal Vulnerability Matches Found: $matchCounter" -ForegroundColor Green
     Write-Host "`nSeverity: $Severity" -ForegroundColor Red
     Write-Host "`nTotal Vulnerabilities Score: $score" -ForegroundColor DarkYellow
} else {
   Write-Host "`nNo Matches Found For Scanned Vulnerabilities."
    
}
