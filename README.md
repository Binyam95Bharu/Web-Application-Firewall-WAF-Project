# Simple Python Web Application Firewall (WAF)

A minimal, educational Web Application Firewall (WAF) built with Python (Flask) for the backend and a simple HTML/CSS/JS frontend.

---

## Features

- Filters and blocks malicious HTTP requests targeting vulnerabilities like:
  - SQL Injection (SQLi)
  - Cross-site Scripting (XSS)
  - Local/Remote File Inclusion (LFI/RFI)
  - Suspicious User-Agents
- Rate limiting per IP address
- Logs request details and matched rules
- Simple web interface to test requests and view recent WAF logs

---

## Getting Started

### Prerequisites

- Python 3.8+
- `pip` package manager

### Installation

1. Clone the repository or download the source files.

2. Open a terminal in the project directory.

3. Create and activate a virtual environment:

   On Windows (PowerShell):

   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
On macOS/Linux:

bash
Copy
Edit
python3 -m venv venv
source venv/bin/activate
Install dependencies:

bash
Copy
Edit
pip install flask
Running the Application
bash
Copy
Edit
python app.py
The app will start on http://localhost:5000

Usage
Open your browser and navigate to http://localhost:5000

Use the web interface to send test requests to the backend /app endpoint.

View recent WAF logs to monitor blocked and allowed requests.

Project Structure
graphql
Copy
Edit
simple-waf/
│
├── app.py            # Flask backend with WAF middleware and admin API
├── static/
│   └── index.html    # Frontend UI to test WAF and display logs
└── README.md         # This file
Limitations & Notes
This WAF is a basic prototype for educational purposes only.

Not production-ready — lacks authentication, persistence, advanced evasion handling.

Logs are stored in-memory and will reset on server restart.

Consider using established WAF solutions (e.g. ModSecurity) for real deployments.

Future Improvements
Add authentication for admin log access

Store logs in a database or external system

Expand detection rules and normalization

Implement reverse proxy forwarding for allowed traffic

License
MIT License

Author
BINYAM BHARU
