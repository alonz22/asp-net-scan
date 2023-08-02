function Check-FileUploadVulnerabilities {
    param($file)

    $content = Get-Content -Path $file

    $lineNumber = 0
    $matchesFound = $false
    $matchCounter = 0

    foreach ($line in $content) {
        $lineNumber++

        if ($line -match '(?i)(new HttpPostedFile\(|File\.SaveAs\()') {
            Write-Host "`nWarning: Direct file upload detected in: $file (Line: $lineNumber)`n" -ForegroundColor DarkYellow
            Write-Host "Line: $line`b" -ForegroundColor Red
            Write-Host "Direct file uploads can lead to security risks. Always validate and sanitize user inputs before saving files.`n" -ForegroundColor DarkYellow
            $matchesFound = $true
            $matchCounter++
        }

        if ($line -match '(?i)Path\.Combine\(') {
            Write-Output "`nWarning: Path manipulation detected in: $file (Line: $lineNumber)`n" -ForegroundColor DarkYellow
            Write-Output "Line: $line`n" -ForegroundColor Red
            Write-Output "Path manipulation can lead to directory traversal attacks. Ensure proper validation of file paths before saving or accessing files.`n" -ForegroundColor DarkYellow
            $matchesFound = $true
            $matchCounter++
        }

        if ($line -match '(?i)HttpPostedFile\.FileName') {
            Write-Host "`nWarning: Missing file type validation detected in: $file (Line: $lineNumber)`n" -ForegroundColor DarkYellow
            Write-Host "Line: $line`n"
            Write-Host "`nAlways validate the file type before saving it to prevent malicious file uploads.`n" -ForegroundColor DarkYellow
            $matchesFound = $true
            $matchCounter++
        }

        if ($line -match '(?i)HttpPostedFile\.ContentLength') {
            Write-Host "`nWarning: Missing file size validation detected in: $file (Line: $lineNumber)`n" -ForegroundColor DarkYellow
            Write-Host "Line: $line`n" -ForegroundColor Red
            Write-Host "Always check the file size before saving it to prevent excessive resource usage.`n" -ForegroundColor DarkYellow
            $matchesFound = $true
            $matchCounter++
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

# Get all .aspx, .aspx.cs, and .cs files in the given path recursively
$aspxFiles = Get-ChildItem -Path $path -Filter "*.aspx" -Recurse
$aspxCSFiles = Get-ChildItem -Path $path -Filter "*.aspx.cs" -Recurse
$csFiles = Get-ChildItem -Path $path -Filter "*.cs" -Recurse

$allFiles = $aspxFiles + $aspxCSFiles + $csFiles  # Combine all the file arrays

$matchesFound = $false
$matchCounter = 0  # Initialize total match counter

foreach ($file in $allFiles) {
    $matches, $count = Check-FileUploadVulnerabilities $file.FullName
    if ($matches) {
        $matchesFound = $true
        $matchCounter += $count  # Add the current file's match count to the total counter
    }
}

if ($matchesFound) {
    Write-Host "Direct file uploads and insecure file handling in your web application can lead to serious security vulnerabilities. 
    `nEnsure proper validation and secure file handling practices to protect against potential attacks and unauthorized access." -ForegroundColor DarkYellow

    # Calculate the score based on the total match count
   # Calculate the score and severity based on the total match count
    if ($matchCounter -ge 20) {
        $score = "10/10"
        $Severity = "CRITICAL"
    } elseif ($matchCounter -ge 7) {
        $score = "9.8/10"
        $Severity = "CRITICAL"
    } elseif ($matchCounter -ge 5) {
        $score = "8/10"
        $Severity = "HIGH"
    } elseif ($matchCounter -ge 4) {
        $score = "6/10"
        $Severity = "MEDIUM"
    } elseif ($matchCounter -ge 2) {
        $score = "4/10"
        $Severity = "MEDIUM"
    } elseif ($matchCounter -ge 1) {
        $score = "3/10"
        $Severity = "LOW"
    }

     Write-Host "`nTotal Matches Found: $matchCounter" -ForegroundColor Green
    Write-Host "Severity: $Severity" -ForegroundColor DarkYellow
    Write-Host "Score: $score" -ForegroundColor DarkYellow
}
else {

    Write-Host "`nNo Matches Found For Scanned Vulnerabilities."
}
