import os
import re
import sys
import logging
from datetime import datetime

# Set up logging
log_filename = "flaw_detection_log.txt"
logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s - %(message)s')

# Check for command-line arguments
if len(sys.argv) != 2:
    print("Usage: python analysis.py <path-to-folder>")
    sys.exit()

# Get the path to the folder
folder_path = sys.argv[1]

# Check if the path exists and is a directory
if not os.path.isdir(folder_path):
    print("The specified path is not a directory or does not exist.")
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

# Search for patterns in each PHP file in the folder and its subdirectories
for root, dirs, files in os.walk(folder_path):
    for filename in files:
        if filename.endswith('.php'):
            file_path = os.path.join(root, filename)
            with open(file_path, 'r') as f:
                lines = f.readlines()
                for line_num, line in enumerate(lines, start=1):
                    for pattern in patterns:
                        match = re.search(pattern, line)
                        if match:
                            log_message = f"Flaw detected in directory '{os.path.basename(root)}', file '{filename}', line {line_num}: {match.group(0)} the matched pattern {pattern}"
                            print(log_message)  # Print to console
                            logging.info(log_message)  # Log to file
