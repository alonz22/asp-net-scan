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
                Write-Host "Unparameterized SQL Query found in: $file (Line: $lineNumber)" -ForegroundColor Red
                Write-Host "`nLine: $line" -ForegroundColor Red
                $matchesFound = $true
                $matchCounter++  # Increment the match counter
                break
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
    $matches, $count = Check-UnparameterizedSQLQueries $file.FullName
    if ($matches) {
        $matchesFound = $true
        $matchCounter += $count  # Add the current file's match count to the total counter
    }
}

if ($matchesFound) {
    Write-Host "`n`n`nSQL Injection Attacks: Without parameterization, malicious input can be directly injected into queries, allowing attackers to manipulate and extract sensitive data or execute unauthorized commands.
    `nData Corruption and Loss: Lack of parameterization may lead to accidental data corruption or deletion, `nas special characters or incorrect input can affect the integrity of the database.
    `nPerformance and Scalability Issues: Non-parameterized queries hinder query plan reuse, impacting performance and scalability, 
    `nespecially in high-traffic environments, increasing the risk of slow response times and resource consumption." -ForegroundColor DarkYellow

    # Calculate the score and severity based on the total match count
    if ($matchCounter -ge 20) {
        $score = "10/10"
        $Severity = "CRITICAL"
    } elseif ($matchCounter -ge 7) {
        $score = "9.8/10"
        $Severity = "CRITICAL"
    } elseif ($matchCounter -ge 5) {
        $score = "9/10"
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
} else {
    Write-Host "`nNo Matches Found For Scanned Vulnerabilities."
}
