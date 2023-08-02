function Get-SQLQueryPatterns {
    # Define common SQL query patterns (including only unparameterized queries with numbers)
    @(
        "(?<!cmd\.Parameters\.AddWithValue\('@)(?i)\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM|EXEC|ALTER)\b.*\b\d+\b"
    )
}

function Check-UnparameterizedSQLQueries {
    param($file)
    $matchesFound = $false
    $matchCounter = 0  # Initialize match counter
    $queryPatterns = Get-SQLQueryPatterns
    $content = Get-Content -Path $file
    $lineNumber = 0
 
    foreach ($line in $content) {
        $lineNumber++
        foreach ($pattern in $queryPatterns) {
            if ($line -match $pattern) {
                $queryString = $matches[0]
                $parameterSuggestions = Get-ParameterSuggestions $queryString
                Write-Host "Unparameterized SQL Query found in: $file (Line: $lineNumber)" -ForegroundColor Yellow
                Write-Host "`nLine: $line" -ForegroundColor Yellow
                Write-Host "`nSuggested parameter values:`n"
                foreach ($param in $parameterSuggestions) {
                    Write-Host "`t$param" -ForegroundColor Red
                }
                $matchesFound = $true
                $matchCounter++  # Increment the match counter
                break
            }
        }
    }
    return $matchesFound, $matchCounter
}

function Get-ParameterSuggestions {
    param([string]$queryString)

    # Use regular expressions to find numbers in the query string
    $numberMatches = $queryString | Select-String -Pattern "\b\d+\b" -AllMatches

    $suggestions = @()
    foreach ($match in $numberMatches.Matches) {
        # Suggest parameter names for each number found in the query
        $paramName = "paramNameReplacement , " + $match.Value
       # $suggestions += "@$paramName" 
       $suggestions += "It is safer to user parameters for the following in your code: " + "command.Parameters.AddWithValue(@$paramName)`n"
    }

    return $suggestions
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
    $matches, $count = Check-UnparameterizedSQLQueries $file.FullName
    if ($matches) {
        $matchesFound = $true
        $matchCounter += $count  # Add the current file's match count to the total counter
    }
}

if ($matchesFound) {
    Write-Host "`n`n`nSQL Injection Attacks: Without parameterization, malicious input can be directly injected into queries, 
    `nallowing attackers to manipulate and extract sensitive data or execute unauthorized commands.
    `nData Corruption and Loss: Lack of parameterization may lead to accidental data corruption or deletion, 
    `nas special characters or incorrect input can affect the integrity of the database.
    `nPerformance and Scalability Issues: Non-parameterized queries hinder query plan reuse, impacting performance and scalability, 
    `nespecially in high-traffic environments, increasing the risk of slow response times and resource consumption.`n" 

    # Calculate the score and severity based on the total match count
    if ($matchCounter -ge 20) {
        $score = "10/10"
        $Severity = "CRITICAL"
    } 
    elseif ($matchCounter -ge 15) {
        $score = "9/10"
        $Severity = "CRITICAL"
    }
    elseif ($matchCounter -ge 10) {
        $score = "8.5/10"
        $Severity = "HIGH"
    }
    elseif ($matchCounter -ge 7) {
        $score = "7.3/10"
        $Severity = "HIGH"
    } elseif ($matchCounter -ge 5) {
        $score = "6.5/10"
        $Severity = "HIGH"
    } elseif ($matchCounter -ge 4) {
        $score = "5"
        $Severity = "MEDIUM"
    } elseif ($matchCounter -ge 2) {
        $score = "4/10"
        $Severity = "MEDIUM"
    } elseif ($matchCounter -ge 1) {
        $score = "3/10"
        $Severity = "LOW"
    }
    
    Write-Host "`nTotal Matches Found: $matchCounter" -ForegroundColor Green
    Write-Host "`nSeverity: $Severity" -ForegroundColor Yellow
    Write-Host "`nScore: $score" -ForegroundColor Yellow
} else {
    Write-Host "`nNo Matches Found For Scanned Vulnerabilities."
}
