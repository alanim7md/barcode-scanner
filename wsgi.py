"""
PythonAnywhere WSGI configuration file.

Instructions:
1. In PythonAnywhere dashboard, go to the Web tab.
2. Set Source code to: /home/<your-username>/barcode-scanner
3. Set Working directory to: /home/<your-username>/barcode-scanner
4. Set Virtualenv path to: /home/<your-username>/barcode-scanner/venv
5. Point WSGI configuration file to THIS file.
6. Set environment variables in the Web tab → Environment variables section:
   - SECRET_KEY = <generate a long random string, e.g. using: python -c "import secrets; print(secrets.token_hex(32))">

IMPORTANT: Do NOT use debug=True in production.
"""

import sys
import os

# Add the project directory to the Python path
project_home = '/home/<your-username>/barcode-scanner'  # <-- UPDATE THIS
if project_home not in sys.path:
    sys.path.insert(0, project_home)

# Set working directory
os.chdir(project_home)

# Import the Flask application
from app import app as application  # noqa: F401
