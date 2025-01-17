# SQL Injection Vulnerability Test Script
## Overview
This Python script tests web applications for SQL injection vulnerabilities by injecting common SQL payloads into URL parameters. It analyzes the server's response to identify potential vulnerabilities.

## Features
- Accepts a URL with query parameters as input.
- Tests for common SQL injection payloads such as:
  - \' OR \'1\'=\'1
  - \'; DROP TABLE users --
  - and many others.
- Reports potential SQL injection vulnerabilities based on the server's response.

## Requirements
- Python 3.x
- Requests library
  \\\ash
  pip install requests
  \\\

## Usage
1. Clone the repository or download the code.
2. Install the required dependencies:
   \\\ash
   pip install requests
   \\\
3. Run the script:
   \\\ash
   python sql_injection_test.py
   \\\
4. Enter the URL you want to test, ensuring it contains query parameters.

### Example Input
To test for SQL injection vulnerabilities, you can enter a URL like:
\\\
https://example.com/page.php?id=1
\\\

The script will then test the specified URL for SQL injection vulnerabilities based on the predefined payloads.
