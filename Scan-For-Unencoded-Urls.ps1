function Check-NotURLEncodedLinks {
    param($file)

    $content = Get-Content -Path $file
    $matchesFound = $false
    $lineNumber = 0
    $matchCounter = 0  # Initialize match counter

    foreach ($line in $content) {
        $lineNumber++

        $urlMatches = [regex]::Matches($line, '(?i)(?<=\?|&)[^&?=\s]+=[^&?=\s]+')

        foreach ($match in $urlMatches) {
            $queryParam = $match.Value
            $value = ($queryParam -split '=', 2)[1]
            $decodedValue = [System.Uri]::UnescapeDataString($value)
            $encodedValue = [System.Uri]::EscapeDataString($decodedValue)

            # Check if the decoded value is different from the encoded value and HttpUtility.UrlEncode is not used
            if ($value -ne $encodedValue -and $line -notmatch 'HttpUtility\.UrlEncode' -and $line -notmatch 'rel="stylesheet"')  {
                Write-Host "Warning: URL not encoded link detected in: $file (Line: $lineNumber)`n" -ForegroundColor DarkYellow
                Write-Host "Line: $line`n" -ForegroundColor Red
                Write-Host "Query Parameter: $queryParam`n" -ForegroundColor Red
                $matchesFound = $true
                $matchCounter++  # Increment the match counter
            }
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
    $matches, $count = Check-NotURLEncodedLinks $file.FullName
    if ($matches) {
        $matchesFound = $true
        $matchCounter += $count  # Add the current file's match count to the total counter
    }
}

if ($matchesFound) {
    Write-Host "`nImproper or insufficient URL encoding can lead to various security vulnerabilities, 
            such as Cross-Site Scripting (XSS) attacks and Server-Side Request Forgery (SSRF) vulnerabilities. 
            These issues can occur when user input or other untrusted data is not correctly encoded before being included in URLs or used in HTTP requests. 
            Exploiting these vulnerabilities can enable attackers to execute malicious code, steal sensitive information, or perform unauthorized actions on the server." -ForegroundColor DarkYellow

    # Calculate the score based on the total match count
    if ($matchCounter -ge 5) {
        $score = "5/10"
        $Severity = "Medium"
    } if ($matchCounter -ge 20) {
        $score = "7/10"
        $Severity = "High"
    } if ($matchCounter -ge 40) {
        $score = "9.5/10"
        $Severity = "Critical"
    }

    Write-Host "`nTotal Vulnerability Matches Found: $matchCounter" -ForegroundColor Green
    Write-Host "`nSeverity: $Severity" -ForegroundColor Red
    Write-Host "`nTotal Vulnerabilities Score: $score" -ForegroundColor DarkYellow
} else {
    Write-Host "`nNo Matches Found For Scanned Vulnerabilities."

}
