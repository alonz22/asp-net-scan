#  ASP.NET App Scanner with PowerShell


## Overview
Inspired by the challenges I faced manually checking my ASP.NET application for vulnerabilities, I developed these custom vulnerability scanners. With an aim to overcome the time-consuming process, these scanners automate the detection of potential security flaws.these checks cover a significant portion of the OWASP Top 10. While other paid and open-source tools exist, my personal journey drove me to create these tailored scanners to enhance the security posture of my application efficiently.

This repository contains a PowerShell script that serves as an ASP.NET app scanner. The script can help identify potential security vulnerabilities in your ASP.NET applications. The scanner targets various aspects of web application security, including cookies, missing CSRF tokens, file uploads, hard-coded credentials, unencoded URLs, input validation, low-level encryption, web.config files, and unparameterized queries.

## Features
Scan for missing CSRF tokens in HTML forms.
Detect hard-coded credentials in source code files.
Identify unencoded URLs that may lead to potential security risks.
Check for insecure input validation practices.
Inspect low-level encryption implementations.
Examine web.config files for security misconfigurations.
Detect unparameterized queries in database interactions.
Requirements
PowerShell 5.1 or later.
How to Use
Clone the repository or download the scripts to your local machine.

Open a PowerShell terminal.

Navigate to the directory where the aspnet_scanner.ps1 script is located.

Run the scanner script by executing the following command:

```PS> .\aspnet_scanner.ps1 ```
Once Prompted for a path, paste the "path/to/your/aspnet_app_directory" and hit enter.

The scanner will start analyzing the files in the specified directory and its subdirectories.

After the scan is complete, the script will display any detected vulnerabilities and provide recommendations for mitigating the issues.

## Vulnerabilities Detected
```
1. Missing CSRF Tokens:
The scanner will identify HTML forms that use the POST method but do not include a hidden
field with a CSRF token.
 CSRF protection is crucial to prevent Cross-Site Request Forgery attacks.

2. Hard-Coded Credentials:
The scanner will search for instances of hard-coded credentials in the source code.
Storing credentials directly in the code can lead to security breaches if the code is exposed.

3. Unencoded URLs:
Unencoded URLs can lead to security vulnerabilities, such as data exposure or injection attacks.
 The scanner will detect unencoded URLs and recommend proper encoding.

4. Insecure Input Validation:
The scanner will look for insecure input validation practices that could allow malicious
input to compromise the application's security.

5. Client Side Validation:
The `Scan-Input-Validation.ps1` also identifies client-side validation implementations,
which are less secure than server-side validation mechanisms.
It helps detect potential vulnerabilities that may expose applications
to security risks and data manipulation by malicious users.

6. Low-Level Encryption:
The scanner will analyze encryption implementations to identify potential weaknesses and recommend stronger encryption practices.

7. Web.config Misconfigurations
The scanner will inspect the web.config files to identify security misconfigurations that
may expose sensitive information or create security loopholes.

8. Unparameterized Queries:
The scanner will detect SQL queries that are not parameterized, which can lead to SQL injection vulnerabilities.

9. Cookies Misconfigurations
The scanner will identify cookies misconfigurations, such as using insecure attributes or
 not setting the secure flag for sensitive cookies, which may lead to
unauthorized access or session hijacking.

10. File Upload Vulnerabilities
The scanner will assess file upload functionality for
security vulnerabilities, such as unrestricted file types, missing file type validation,
or insecure handling of uploaded files.
```

## Output Sample for Web.Config Scanning:

```powershell
Warning: C:\SomePath\Web.config does not contain <httpErrors> element.
Not using custom errors may expose sensitive information.
Warning: C:\SomePath\Web.config does not block the following potentially dangerous file extensions:
  .exe
  .cmd
  .dll
Potential issue in C:\SomePath\Web.config: Line 1
Database name contains the username.
Password length is less than 10 characters.
Password contains the username or the database name.

These vulnerabilities could lead to security breaches, data leaks, unauthorized access, and other potential threats to the web application and its users. 
    
It is crucial to address and remediate these issues promptly to enhance the application's security posture.

Total Vulnerability Matches Found: 10

Severity: Critical

Total Vulnerabilities Score: 9.5/10
```

## Contributing
Contributions to the ASP.NET App Scanner with PowerShell are welcome! If you find any issues or have suggestions for improvements, please feel free to submit a pull request or open an issue in the repository.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## **Disclaimer**
Please note The ASP.NET App Scanner is a tool intended for security testing and research purposes only. You must obtain explicit permission from the application owner before scanning any website or application that you do not own or do not have explicit authorization to test. Unauthorized scanning of websites or applications may be illegal and is strictly prohibited.

The author of this script is not responsible for any misuse, unauthorized access, or damage caused by using this tool. Use the scanner at your own risk and with proper authorization.
## **NOTICE**
The powershell scripts may print results related to false-positives.
