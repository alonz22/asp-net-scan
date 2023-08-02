function Scan-WebConfig {
    param (
        [Parameter(Mandatory = $true)]
        [string]$path
    )

    $matchesFound = $false
    $matchCounter = 0  # Initialize match counter

    $webConfigFiles = Get-ChildItem -Path $path -Recurse -Filter "web.config" -ErrorAction SilentlyContinue

    $dangerousExtensions = @(".exe", ".cmd", ".dll")
    $foundDangerousExtensions = @()

    foreach ($file in $webConfigFiles) {
        $content = Get-Content $file.FullName -Raw

        $xml = [xml]$content

        # Retrieve the ConnectionString node
        $connectionStringNode = $xml.configuration.connectionStrings.add

        # Check if <httpErrors> and <customErrors> elements exist
        $httpErrorsElement = $xml.configuration.'system.webServer'.httpErrors
        $customErrorsElement = $xml.configuration.'system.web'.customErrors

        if (!$httpErrorsElement) {
            Write-Host "Warning: $($file.FullName) does not contain <httpErrors> element.`nNot using custom errors may expose sensitive information." -ForegroundColor DarkYellow
            $matchesFound = $true
            $matchCounter++
        }

        if (!$customErrorsElement) {
            Write-Host "Warning: $($file.FullName) does not contain `<customErrors>` element.`nNot using custom errors may expose sensitive information." -ForegroundColor DarkYellow
            $matchesFound = $true
            $matchCounter++
        }

        # Check if <add> elements for dangerous file extensions exist
        $addElements = $xml.configuration.'system.webServer'.security.requestFiltering.fileExtensions.add

        foreach ($extension in $dangerousExtensions) {
            $found = $addElements | Where-Object { $_.fileExtension -eq $extension -and $_.allowed -eq "false" }
            if (!$found) {
                $foundDangerousExtensions += $extension
                $matchesFound = $true
                $matchCounter++
            }
        }

        if ($foundDangerousExtensions.Count -gt 0) {
            Write-Host "Warning: $($file.FullName) does not block the following potentially dangerous file extensions:" -ForegroundColor Red
            foreach ($ext in $foundDangerousExtensions) {
                Write-Host "  $ext"  -ForegroundColor Green
                $matchesFound = $true
                $matchCounter++
            }
        }

        if ($connectionStringNode) {
            $connectionString = $connectionStringNode.connectionString
            $databaseName = $connectionStringNode.name

            # Use regular expressions to extract username and password from ConnectionString
            $usernameMatch = [regex]::Match($connectionString, 'User\s+ID\s*=\s*"(.*?)"')
            $passwordMatch = [regex]::Match($connectionString, 'Password\s*=\s*"(.*?)"')

            if ($usernameMatch.Success) {
                $username = $usernameMatch.Groups[1].Value
            }

            if ($passwordMatch.Success) {
                $password = $passwordMatch.Groups[1].Value
            }

            if ($databaseName -like "*$username*" -or $password.Length -lt 10 -or $password -like "*$username*" -or $password -like "*$databaseName*") {
                Write-Host "Potential issue in $($file.FullName): Line $($passwordMatch.Groups[1].Index + 1)"
                if ($databaseName -like "*$username*") {
                    Write-Host "Database name contains the username." -ForegroundColor DarkYellow
                    $matchesFound = $true
                    $matchCounter++
                }
                if ($password.Length -lt 10) {
                    Write-Host "Password length is less than 10 characters." -ForegroundColor Red
                    $matchesFound = $true
                    $matchCounter++
                }
                if ($password -like "*$username*" -or $password -like "*$databaseName*") {
                    Write-Host "Password contains the username or the database name." -ForegroundColor Red
                    $matchesFound = $true
                    $matchCounter++
                }
            }
        }
    }

    return $matchesFound, $matchCounter
}

# Prompt the user for the path
$path = Read-Host "Enter the path to scan for web.config files"

# Call the function with the user-provided path
$matches, $count = Scan-WebConfig -path $path

if ($matches) {
    Write-Host "`n`n`nThese vulnerabilities could lead to security breaches, data leaks, unauthorized access, and other potential threats to the web application and its users. 
    `nIt is crucial to address and remediate these issues promptly to enhance the application's security posture." -ForegroundColor DarkYellow

    # Calculate the score based on the total match count
    $Severity = "LOW"

    if ($count -ge 5) {
        $score = "8/10"
        $Severity = "HIGH"
    } 
    if ($count -ge 2) {
        $score = "3/10"
        $Severity = "MEDIUM"
    }
    if ($count -ge 2) {
        $score = "6.5/10"
        $Severity = "MEDIUM"
    } 
    
    if ($count -ge 8) {
        $score = "9.5/10"
        $Severity = "Critical"
    } 
    Write-Host "`nTotal Vulnerability Matches Found: $count" -ForegroundColor Green
    Write-Host "`nSeverity: $Severity" -ForegroundColor DarkYellow
    Write-Host "`nTotal Vulnerabilities Score: $score" -ForegroundColor DarkYellow
} else {
    Write-Host "`nNo Matches Found For Scanned Vulnerabilities."
    
}
