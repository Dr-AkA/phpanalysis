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
    r'(\$_GET|\$_POST|\$_REQUEST)\[.*?\]',
    # Look for XSS vulnerabilities
    r'<script>.*?<\/script>',
    # Look for CSRF vulnerabilities
    r'/csrf_token/',
    # Look for file inclusion vulnerabilities
    r'/include\(.*\);/',
    # Look for directory traversal vulnerabilities
    r'/\.\.\//'
]

# Search for patterns in the code
for pattern in patterns:
    match = re.search(pattern, code)
    if match:
        print("Flaw detected: " + match.group(0))