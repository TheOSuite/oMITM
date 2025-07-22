# oMITM

![GitHub License](https://img.shields.io/github/license/TheOSuite/oXSS)
![Python Version](https://img.shields.io/badge/python-3.13-blue)

oMITM is a basic Man-in-the-Middle (MITM) proxy built in Python using `http.server`, `socket`, `ssl`, `requests`, `cryptography`, and `tkinter`. It is designed to intercept, log, and perform basic analysis on HTTP and HTTPS traffic.

**Disclaimer:** This tool is intended for educational purposes, security testing of your own applications/network, and understanding web traffic. Using MITM techniques on networks or systems without explicit permission may be illegal and unethical. The author is not responsible for any misuse.

## Features

* Intercepts HTTP and HTTPS traffic.
* Generates a custom Certificate Authority (CA) and per-host certificates for HTTPS interception.
* Logs detailed information about requests and responses (headers, body).
* Provides a Tkinter GUI for controlling the proxy and viewing traffic.
* Performs real-time analysis to flag potential API calls and common vulnerability indicators (missing security headers, info disclosure, insecure cookies, sensitive data in URLs, HTTP usage on sensitive paths).
* Allows on-demand analysis of request and response bodies for keywords and error patterns.
* Export captured traffic to a JSON file.
* Clear captured traffic logs.

## Prerequisites

* Python 3.6 or higher
* The following Python libraries:
    * `requests`
    * `cryptography`
    * `pyOpenSSL` (Often needed by `requests`/`urllib3` for SSL, though `cryptography` handles our certs)
    * `tkinter` (Usually included with Python, but might require installation on some systems)

## Installation

1.  **Save the code:** Save the provided Python code as a `.py` file (e.g., `oMITM.py`).
2.  **Install dependencies:** Open your terminal or command prompt and install the required libraries using pip:

    ```bash
    pip install requests cryptography pyopenssl
    ```

## Generating and Trusting the CA Certificate

When you run oMITM for the first time, it will automatically generate a new Certificate Authority (CA) certificate (`ca.crt`) and a corresponding private key (`ca.key`) in the same directory as the script.

To intercept HTTPS traffic without your browser/applications showing certificate errors, you **MUST** install and trust this `ca.crt` file in your operating system's certificate store or your browser's trusted root certificates list.

* oMITM provides **"View CA Cert"** and **"Trust CA Info"** buttons in the GUI to help you locate the certificate file and provide general instructions.
* The exact steps to trust a CA vary depending on your operating system and browser. Please refer to their official documentation.
    * **Windows:** Search for "Manage computer certificates" or "Internet Options" -> Content tab -> Certificates.
    * **macOS:** Keychain Access -> System or Login keychain.
    * **Linux (Firefox/Chrome):** Browsers often have their own certificate stores (Preferences/Settings -> Privacy and Security -> Certificates -> Authorities). System-wide trust depends on the distribution (e.g., `/etc/ssl/certs/`).

**Security Note:** The `ca.key` file allows signing of arbitrary certificates. Keep this file secure and do not share it. The tool currently does not encrypt the private key file.

## Running the Proxy

1.  Open your terminal or command prompt.
2.  Navigate to the directory where you saved `oMITM.py`.
3.  Run the script:

    ```bash
    python oMITM.py
    ```
4.  The Tkinter GUI window should appear.

## Using the GUI

1.  **Host and Port:** Enter the IP address and port you want the proxy to listen on (default is `127.0.0.1:8888`). `127.0.0.1` is for proxying traffic from the same machine. To proxy from other devices, use your machine's local network IP and ensure your firewall allows connections.
2.  **Start Proxy:** Click "Start Proxy" to begin listening for connections.
3.  **Stop Proxy:** Click "Stop Proxy" to shut down the proxy server.
4.  **Configure Client:** Configure the application or browser you want to proxy to use the IP and port you specified (e.g., `127.0.0.1:8888`) as its HTTP and HTTPS proxy.
5.  **View Traffic:** As traffic passes through the proxy, entries will appear in the main listbox. The list shows the entry number, HTTP method, URL (truncated), status code, and indicators for API calls and analysis findings.
6.  **View Entry Details:** Double-click an entry in the listbox to open a separate viewer dialog. This dialog shows full request/response headers and body (decoded if possible), as well as real-time analysis findings.
7.  **Analyze Bodies:** In the viewer dialog, use the "Analyze Request Body" and "Analyze Response Body" buttons to run additional checks for keywords and error patterns specifically on the body content. Results appear in the "On-Demand Body Analysis" section.
8.  **Run Batch Analysis:** Click "Run Batch Analysis" (while the proxy is stopped) to get a summary count of potential API calls and total findings across all captured traffic.
9.  **Export Traffic:** Click "Export Traffic" to save the current traffic log to a JSON file.
10. **Clear Traffic:** Click "Clear Traffic" to remove all entries from the current log (requires confirmation).

## Analysis Features Explained

* **Real-time Findings:** As traffic is logged, `oMITM` automatically checks:
    * If the URL path matches common API patterns.
    * For missing common security response headers (HSTS, CSP, X-Frame-Options, etc.).
    * For headers that reveal server/technology information.
    * For missing `HttpOnly`, `Secure`, and `SameSite` flags in `Set-Cookie` headers.
    * If sensitive data keywords (`password`, `token`, etc.) appear in URL path segments or query parameters.
    * If potentially sensitive paths (`/login`, `/admin`, etc.) are accessed over unencrypted HTTP.
* **On-Demand Body Analysis:** When you click "Analyze Request Body" or "Analyze Response Body" in the viewer, `oMITM` checks the selected body for:
    * Sensitive data keywords.
    * Patterns indicating error messages or stack traces.
    * For JSON or XML structures and attempts to find keywords within them.

Findings from both real-time and on-demand analysis are displayed in the "Analysis" tab of the traffic viewer dialog.

## Limitations

* Analysis is passive and based on observable traffic patterns and content. It cannot find vulnerabilities requiring active probing or exploitation.
* Body capture size for logging is limited (default 1MB request, 2MB response) to manage memory usage.
* The GUI listbox performance may degrade with extremely large numbers of entries (over a few thousand).
* Sophisticated encoding or obfuscation techniques might evade simple keyword checks.
* Relies on the `requests` library's handling for forwarding, which covers most standard HTTP/1.1 cases.
