ASP.NET App Scanner with PowerShell
License

Overview
This repository contains a PowerShell script that serves as an ASP.NET app scanner. The script can help identify potential security vulnerabilities in your ASP.NET applications. The scanner targets various aspects of web application security, including cookies, missing CSRF tokens, file uploads, hard-coded credentials, unencoded URLs, input validation, low-level encryption, web.config files, and unparameterized queries.

Features
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
Clone the repository or download the aspnet_scanner.ps1 script to your local machine.

Open a PowerShell terminal.

Navigate to the directory where the aspnet_scanner.ps1 script is located.

Run the scanner script by executing the following command:

PS> .\aspnet_scanner.ps1 
Once Prompted for a path, paste the "path/to/your/aspnet_app_directory" and hit enter.

The scanner will start analyzing the files in the specified directory and its subdirectories.

After the scan is complete, the script will display any detected vulnerabilities and provide recommendations for mitigating the issues.

Vulnerabilities Detected
1. Missing CSRF Tokens
The scanner will identify HTML forms that use the POST method but do not include a hidden field with a CSRF token. CSRF protection is crucial to prevent Cross-Site Request Forgery attacks.

2. Hard-Coded Credentials
The scanner will search for instances of hard-coded credentials in the source code. Storing credentials directly in the code can lead to security breaches if the code is exposed.

3. Unencoded URLs
Unencoded URLs can lead to security vulnerabilities, such as data exposure or injection attacks. The scanner will detect unencoded URLs and recommend proper encoding.

4. Insecure Input Validation
The scanner will look for insecure input validation practices that could allow malicious input to compromise the application's security.

5. Low-Level Encryption
The scanner will analyze encryption implementations to identify potential weaknesses and recommend stronger encryption practices.

6. Web.config Misconfigurations
The scanner will inspect the web.config files to identify security misconfigurations that may expose sensitive information or create security loopholes.

7. Unparameterized Queries
The scanner will detect SQL queries that are not parameterized, which can lead to SQL injection vulnerabilities.

Contributing
Contributions to the ASP.NET App Scanner with PowerShell are welcome! If you find any issues or have suggestions for improvements, please feel free to submit a pull request or open an issue in the repository.

License
This project is licensed under the MIT License - see the LICENSE file for details.

Disclaimer
Please note that the ASP.NET App Scanner is a tool intended for security testing and research purposes only. Always seek permission from the application owner before scanning any website or application that you do not own. The author of this script is not responsible for any misuse or damage caused by using this tool.
