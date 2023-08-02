function Check-CSRFToken {
    param($file)

    $content = Get-Content -Path $file

    $lineNumber = 0
    $insideForm = $false
    $csrfTokenFound = $false
    $formMethod = ""
    $csrfTokenSessionExists = $false
    $matchesFound = $false
    $matchCounter = 0
    $loginFormWithPOSTAndNoCSRF = $false  # Track the specific case of login form with POST and no CSRF token

    foreach ($line in $content) {
        $lineNumber++
        if ($line -match '<form.*>') {
            $insideForm = $true
            $csrfTokenFound = $false
            $loginFormWithPOSTAndNoCSRF = $false  # Reset the flag when entering a new form
            $formMethod = $line -replace '.*method\s*=\s*"([^"]+)".*', '$1'
            $formRunatServer = $line -match '(?i)runat\s*=\s*"server"'
            continue
        }

        if ($insideForm -and $line -match '</form>') {
            $insideForm = $false
            if ($csrfTokenFound -and $formMethod -eq "GET") {
                Write-Host "Warning: GET method may expose the CSRF token value in the URL in: $file (Line: $lineNumber)" -ForegroundColor Red
                Write-Host "Line: $line"
                $matchesFound = $true
                $matchCounter++
            }
            if ($loginFormWithPOSTAndNoCSRF) {
                Write-Host "`nWarning:: form with POST method and no CSRF token found in: $file (Line: $lineNumber).
                `nIt is safer to implement anti-CSRF mechanism for forms with POST method." -ForegroundColor Yellow
                Write-Host "Line: $line"
                $matchesFound = $true
                $matchCounter++
            }
            $csrfTokenFound = $false
            continue
        }
      
        if ($line -match '(?i)<input[^>]*type\s*=\s*"hidden"[^>]*((id|name)\s*=\s*"CSRFTokenField"|name\s*=\s*"csrf|csrfToken|csrfTOKEN|CSRF")[^>]*>') {
            $csrfTokenFound = $true
            continue
        }

        if ($csrfTokenFound -and $line -match '(?i)<input[^>]*((id|name)\s*=\s*"CSRFTokenField"|name\s*=\s*"csrf|csrfToken|csrfTOKEN|CSRF")[^>]*>') {
            Write-Host "Warning: Non-hidden CSRF Token field found in form: $file (Line: $lineNumber)" -ForegroundColor Red
            Write-Host "Line: $line"
            $matchesFound = $true
            $matchCounter++
            $csrfTokenFound = $false
            continue
        }

        if ($line -match '(?i)Session\["CSRFToken"\]') {
            $csrfTokenSessionExists = $true
        }

        # Detect login forms with POST method and no CSRF token
        if ($insideForm -and $formMethod -eq "POST" -and -not $csrfTokenFound -and $line -match '(?i)<input[^>]*type\s*=\s*"submit"[^>]*((id|name)\s*=\s*"(login|signin|submit)")') {
            $loginFormWithPOSTAndNoCSRF = $true
        }

        # Detect ASP forms with runat="server" and no CSRF token
        if ($insideForm -and $formRunatServer -and $formMethod -eq "POST" -and -not $csrfTokenFound) {
            $loginFormWithPOSTAndNoCSRF = $true
        }
    }

    if ($insideForm -and $csrfTokenFound -and -not $csrfTokenSessionExists) {
        Write-Host "Warning: CSRF Token field found in form, but Session['CSRFToken'] is not set in: $file (Line: $lineNumber)" -ForegroundColor DarkYellow
        Write-Host "Line: $line"
        $matchesFound = $true
        $matchCounter++
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
    $matches, $count = Check-CSRFToken $file.FullName
    if ($matches) {
        $matchesFound = $true
        $matchCounter += $count  # Add the current file's match count to the total counter
    }
}

if ($matchesFound) {
    Write-Host "`n`nFailing to implement CSRF protection in your web application can expose users to Cross-Site Request Forgery attacks. 
    `nBy ensuring the presence of secure, hidden CSRF tokens within forms and associating them with session variables, 
    `nyou can prevent attackers from forging malicious requests and protect user data and actions." 

    # Calculate the score based on the total match count
    $Severity = "LOW"
    if ($matchCounter -ge 2) {
        $score = "6/10"
        $Severity = "MEDIUM"
    } if ($matchCounter -ge 4) {
        $score = "8/10"
        $Severity = "HIGH"
    } 
    if ($matchCounter -ge 6) {
        $score = "9.3/10"
        $Severity = "CRITICAL"
    } 
    
   Write-Host "`nTotal Vulnerability Matches Found: $matchCounter" -ForegroundColor Green
    Write-Host "`nSeverity: $Severity" -ForegroundColor Red
    Write-Host "`nTotal Vulnerabilities Score: $score" -ForegroundColor DarkYellow
}
else {
    Write-Host "`nNo Matches Found For Scanned Vulnerabilities."
   
}
