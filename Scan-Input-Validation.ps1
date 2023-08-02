function Check-InputValidation {
    param($file)

    $content = Get-Content -Path $file

    $lineNumber = 0
    $matchesFound = $false
    $matchCounter = 0  # Initialize match counter
    $insideForm = $false
    $isHtmlEncoded = $false
    foreach ($line in $content) {
        $lineNumber++
        if ($line -match '<form.*>') {
            $insideForm = $true
            continue
        }

        if ($insideForm -and $line -match '</form>') {
            $insideForm = $false
            continue
        }

        if ($insideForm -and $line -match '(?i)<input[^>]*type\s*=\s*"(text|email|password)"[^>]*value\s*=\s*"([^"]*)"[^>]*>') {
            $inputType = $matches[1]
            $inputValue = $matches[2]
            $isHtmlEncoded = $line -match '(HttpUtility\.HtmlEncode|Server\.HtmlEncode)'
            if ($inputType -in @('text', 'email', 'password') -and -not $isHtmlEncoded) {
                Write-Host "Input field ($inputType) not HTML encoded in: $file (Line: $lineNumber)`n" -ForegroundColor Red
                Write-Host "Line Containing the potential vulnerability: $line`n" -ForegroundColor DarkYellow
                $matchesFound = $true
                $matchCounter++  # Increment the match counter
            }
        }

        if ($isHtmlEncoded -and $line -match '(HttpUtility\.HtmlEncode|Server\.HtmlEncode)') {
            $isHtmlEncoded = $false
        }

        if ($line -match '(?i)(invalid\s+credentials|invalid\s+username|invalid\s+password|invalid\s+mail|user\s+not\s+exist|password\s+not\s+exist)') {
            Write-Host "Potentially Client-side validation found in: $file (Line: $lineNumber). `nConsider Server-Side Validation instead, and return a matching error code following to your validation.`n" -ForegroundColor Red
            Write-Host "Line Containing the potential vulnerability: $line`n" -ForegroundColor DarkYellow
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

# Get all .aspx, .aspx.cs, and .cs files in the given path recursively
$aspxFiles = Get-ChildItem -Path $path -Filter "*.aspx" -Recurse
$aspxCSFiles = Get-ChildItem -Path $path -Filter "*.aspx.cs" -Recurse
$csFiles = Get-ChildItem -Path $path -Filter "*.cs" -Recurse

$allFiles = $aspxFiles + $aspxCSFiles + $csFiles  # Combine all the file arrays

$matchesFound = $false
$matchCounter = 0  # Initialize total match counter

foreach ($file in $allFiles) {
    $matches, $count = Check-InputValidation $file.FullName
    if ($matches) {
        $matchesFound = $true
        $matchCounter += $count  # Add the current file's match count to the total counter
    }
}

if ($matchesFound) {
    Write-Host "`n`n`nNot using input validation mechanism in your code may lead to the following vulnerabilities:"
    Write-Host "`n1. Injection Attacks:"
    Write-Host "   Without input validation, attackers can exploit vulnerabilities such as SQL injection,"
    Write-Host "   where they insert malicious SQL code into input fields."
    Write-Host "`n2. Cross-Site Scripting (XSS) Attacks:"
    Write-Host "   Lack of input validation allows attackers to inject malicious scripts into user inputs,"
    Write-Host "   which are then executed on other users' browsers when viewing the affected page."
    Write-Host "`n3. Cross-Site Request Forgery (CSRF) Attacks:"
    Write-Host "   CSRF attacks occur when an attacker tricks a user's browser into making unauthorized requests to a website where the user is authenticated."
    Write-Host "`n4. Data Corruption and Loss:"
    Write-Host "   Invalid input can lead to data corruption or loss, impacting the integrity and availability of data."
    Write-Host "`n5. Denial of Service (DoS) Attacks:"
    Write-Host "   Attackers can use input validation weaknesses to trigger DoS attacks by submitting specially crafted"
    Write-Host "   input that consumes excessive resources or causes infinite loops in the application."
    Write-Host "`n6. Bypassing Security Controls:"
    Write-Host "   Inadequate input validation can allow attackers to bypass security controls,"
    Write-Host "   such as authentication mechanisms or access controls, gaining unauthorized access to sensitive areas of the application."

    # Calculate the score based on the total match count
     if ($matchCounter -ge 1){
        $score = "4/10"
        $Severity = "LOW"
    }
    if ($matchCounter -ge 2){
        $score = "5.5/10"
        $Severity = "LOW"
    }
     
    if ($matchCounter -ge 5) {
        $score = "8.3/10"
        $Severity = "High"
    } if ($matchCounter -ge 3) {
        $score = "7/10"
        $Severity = "MEDIUM"
    }
    if ($matchCounter -ge 15) {
        $score = "9.8/10"
        $Severity = "Critical"
    }

     Write-Host "`nTotal Matches Found: $matchCounter" -ForegroundColor Green
    Write-Host "Severity: $Severity" -ForegroundColor DarkYellow
    Write-Host "Score: $score" -ForegroundColor DarkYellow
} else {
     Write-Host "`nNo Matches Found For Scanned Vulnerabilities."

}
