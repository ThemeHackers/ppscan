# ppscan 🚀

![Python](https://img.shields.io/badge/python-3.13+-blue.svg)
![Playwright](https://img.shields.io/badge/playwright-v1.40+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

**ppscan** is a powerful, next-generation **Prototype Pollution Scanner** written in Python. It is an advanced port of the popular `ppfuzz` tool, enhanced with modern features like structured JSON output, improved heuristics, and cross-platform compatibility.

It leverages **Playwright** to instrument a real browser context, ensuring accurate detection of client-side Prototype Pollution vulnerabilities by monitoring the DOM and JavaScript execution context for pollution indications.

## ✨ Features

- **🚀 High Performance**: Uses `asyncio` and Playwright for fast, concurrent scanning.
- **🎯 Accurate Detection**: Instruments the browser to detect actual pollution events, reducing false positives.
- **🛠️ Cross-Platform**: Works seamlessly on **Windows**, **macOS**, and **Linux**.
- **📊 Structured Output**: Supports JSON output for easy integration into CI/CD pipelines or other tools.
- **🛡️ Comprehensive Payloads**: Includes an expanded list of payloads covering various injection vectors (`__proto__`, `constructor`, etc.).
- **🔁 Auto-Retry**: Built-in network retry logic to handle flaky connections.
- **🕵️ SSRF Detection**: Supports callback URLs to detect Server-Side Request Forgery via prototype pollution.

## 📦 Installation

### Prerequisites
- Python 3.10+
- Chrome/Chromium installed (managed by Playwright)

### Setup
1.  **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/ppscan.git
    cd ppscan
    ```

2.  **Create a virtual environment**:
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate  # Linux/macOS
    # .venv\Scripts\activate   # Windows
    ```

3.  **Install dependencies**:
    ```bash
    pip3 install -r requirements.txt
    playwright install chromium
    ```

## 🚀 Usage

### Linux / macOS
```bash
./ppscan -u http://example.com
```

### Windows
```cmd
ppscan.bat -u http://example.com
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u`, `--url` | Target URL to scan | - |
| `-l`, `--list` | File containing a list of URLs | - |
| `-c`, `--concurrency` | Number of concurrent tabs/pages | `15` |
| `-t`, `--timeout` | Navigation timeout in seconds | `30` |
| `--json` | Save results to a JSON file | - |
| `--exploit` | Actively verify XSS by visiting potential payload URLs | `False` |
| `--proxy` | Proxy URL (e.g., `http://127.0.0.1:8080`) | - |
| `--headers` | Custom headers (JSON or `Key: Value`) | - |
| `--callback` | Callback URL for SSRF detection | `attacker.tld` |

## 💡 Examples

**Scan a single URL**
```bash
./ppscan -u "http://example.com/?q=test"
```

**Scan a list of URLs and save to JSON**
```bash
./ppscan -l urls.txt --json results.json
```

**Scan with proxy (e.g., Burp Suite)**
```bash
./ppscan -u http://example.com --proxy http://127.0.0.1:8080
```

## ⚠️ Disclaimer

This tool is for **educational purposes and authorized security testing only**. You must have explicit permission to scan any targets. The authors are not responsible for any misuse or damage caused by this tool.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
