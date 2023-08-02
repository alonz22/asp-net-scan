function Check-CookieProperties {
    param (
        [string]$file
    )

    $content = Get-Content -Path $file -Raw
    $matchesFound = $false
    $matchCounter = 0  # Initialize match counter

    # Check if the word "HttpCookie" appears in the content
    if ($content -match "HttpCookie") {
        # Check for the presence of all required properties in the script block
        $requiredProperties = @(".Expires", ".HttpOnly", ".Secure", ".SameSite")
        $missingProperties = $requiredProperties | Where-Object { $content -notlike "*$_*" }

        # Display messages based on the result
        if ($missingProperties.Count -gt 0) {
            Write-Host "`nWarning: The file $($file) contains 'HttpCookie', but is missing the following properties: $($missingProperties -join ', ')`n" -ForegroundColor Red
            $matchesFound = $true

            # Increment the match counter relatively based on the number of missing properties
            switch ($missingProperties.Count) {
                1 { $matchCounter += 1 }  # Increment by 1
                2 { $matchCounter += 2 }  # Increment by 2
                3 { $matchCounter += 3 }  # Increment by 3
                default { $matchCounter += 4 }  # Increment by 4 (if 4 or more properties are missing)
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


# Get all .aspx, .aspx.cs, and .cs files in the given path recursively
$aspxFiles = Get-ChildItem -Path $path -Filter "*.aspx" -Recurse
$aspxCSFiles = Get-ChildItem -Path $path -Filter "*.aspx.cs" -Recurse
$csFiles = Get-ChildItem -Path $path -Filter "*.cs" -Recurse

$allFiles = $aspxFiles + $aspxCSFiles + $csFiles  # Combine all the file arrays

$matchesFound = $false
$matchCounter = 0  # Initialize total match counter

foreach ($file in $allFiles) {
    $matches, $count = Check-CookieProperties $file.FullName
    if ($matches) {
        $matchesFound = $true
        $matchCounter += $count  # Add the current file's match count to the total counter
    }
}

if ($matchesFound) {
    Write-Host "failing to use the HttpOnly, Secure, SameSite, and Expires attributes when setting cookies can expose your web application to various security risks, 
    `nincluding session hijacking, XSS attacks, CSRF attacks, and unauthorized access to user data. By implementing these attributes properly, 
    `nyou can significantly improve the security and privacy of your web application, protecting your users from potential threats." -ForegroundColor DarkYellow

    # Calculate the score based on the total match count
    $score = if ($matchCounter -ge 5) {
        "8/10"
         $Severity = "Critical"
    } $score = if ($matchCounter -ge 3) {
        "6.5/10"
         $Severity = "High"
    }
     $score = if ($matchCounter -ge 1) {
        "4/10"
         $Severity = "Low"
    }
    $score = if ($matchCounter -ge 2) {
        "5.5/10"
         $Severity = "Medium"
    }

   
    
    Write-Host "`nTotal Vulnerability Matches Found: $matchCounter" -ForegroundColor Green
     Write-Host "`nSeverity: $Severity" -ForegroundColor Red
     Write-Host "`nTotal Vulnerabilities Score: $score" -ForegroundColor DarkYellow
}
else{
   Write-Host "`nNo Matches Found For Scanned Vulnerabilities."
}

