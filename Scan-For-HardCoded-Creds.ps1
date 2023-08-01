function Check-HardcodedCredentials {
    param($file)

    $content = Get-Content -Path $file

    $lineNumber = 0
     $matchesFound = $false
    $matchCounter = 0  # Initialize match counter
    foreach ($line in $content) {
        $lineNumber++

        if ($line -match '(?i)new\s+NetworkCredential\s*\(\s*".*"\s*,\s*".*"\s*\)') {
            Write-Host "Warning: Hardcoded NetworkCredential detected in: $file (Line: $lineNumber)" -ForegroundColor Red
            Write-Host "Line: $line" -ForegroundColor Red
            Write-Host "Consider storing your credentials inside the Web.Config and use it in your code by using System.Configuration NameSpace." -ForegroundColor DarkYellow
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
    $matches, $count = Check-HardcodedCredentials $file.FullName
    if ($matches) {
        $matchesFound = $true
        $matchCounter += $count  # Add the current file's match count to the total counter
    }
}

if ($matchesFound) {
    Write-Host "`n`n`nUsing hardcoded credentials in ASP.NET or any application is considered a severe security vulnerability and is highly discouraged." -ForegroundColor DarkYellow

    # Calculate the score based on the total match count
    $score = if ($matchCounter -ge 1) {
        "3/10"
         $Severity = "LOW"
    }
    
    $score = if ($matchCounter -ge 5) {
        "9.8/10"
         $Severity = "Critical"
    }
    $score = if ($matchCounter -ge 4) {
        "8/10"
         $Severity = "MEDIUM"
    }
     $score = if ($matchCounter -ge 3) {
        "6/10"
         $Severity = "MEDIUM"
    }
    

    Write-Host "`nTotal Vulnerability Matches Found: $matchCounter" -ForegroundColor Green
     Write-Host "`nSeverity: $Severity" -ForegroundColor Red
     Write-Host "`nTotal Vulnerabilities Score: $score" -ForegroundColor DarkYellow
}
else{
 Write-Host "`nNo Matches Found For Scanned Vulnerabilities."

}