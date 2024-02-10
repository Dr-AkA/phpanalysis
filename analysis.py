import re
import sys

# Check for command-line arguments
if len(sys.argv) != 2:
    print("Usage: python analysis.py <path-to-code>")
    sys.exit()

# Get the path to the code
code_path = sys.argv[1]

# Check if the path exists and is a file
try:
    with open(code_path, 'r') as f:
        code = f.read()
except FileNotFoundError:
    print("The specified path does not exist or is not a file.")
    sys.exit()

# Define the patterns to search for
patterns = [
    # Look for SQL injection vulnerabilities
    r'(\$_GET|\$_POST|\$_REQUEST)\[.*?\]',  # Matches $_GET[], $_POST[], or $_REQUEST[] with any content inside brackets
    
    # Look for XSS vulnerabilities
    r'<script>.*?<\/script>',  # Matches any script tag with content inside, potentially indicating an XSS vulnerability
    
    # Look for CSRF vulnerabilities
    r'/csrf_token/',  # Matches occurrences of "/csrf_token/", could indicate a CSRF token being exposed
    
    # Look for file inclusion vulnerabilities
    r'/include\(.*\);/',  # Matches calls to include() function with any content inside parentheses, indicating possible file inclusion vulnerability
    
    # Look for directory traversal vulnerabilities
    r'/\.\.\//',  # Matches occurrences of "../" which could indicate an attempt at directory traversal
    r'/\.\./',    # Matches occurrences of ".." which could also indicate directory traversal attempts without the following "/"
    
    # Look for command injection vulnerabilities
    r';\s*(?:system|exec|shell_exec|passthru|pcntl_exec)\(.*?\);', # Matches common PHP functions used for command execution with any content inside parentheses
]

# Search for patterns in the code
for pattern in patterns:
    match = re.search(pattern, code)
    if match:
        print("Flaw detected: " + match.group(0))