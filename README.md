# XSSavior

XSSavior is a robust tool designed to identify cross-site scripting (XSS) vulnerabilities in web applications. It employs a combination of payload injection and DOM inspection to detect potential security flaws. By simulating user interactions and analyzing changes in the web page, XSSavior efficiently verifies whether the application is susceptible to XSS attacks.


## Features

- **Browser Control:** Integrates with Selenium to create automated test scenarios for effectively detecting XSS vulnerabilities in web applications.
- **Privacy-Focused Proxy Support:** Utilizes different proxies to conduct scanning operations securely, minimizing the risk of being monitored.
- **Accelerated Scanning:** Implements multithreading to send multiple payloads simultaneously, significantly speeding up the scanning process.
- **User-Friendly Interface:** Collects necessary information from the user.
- **Comprehensive Logging System:** Maintains detailed logs of all actions taken during the scanning process for easy analysis of identified vulnerabilities.


## Screenshots

![App Screenshot](https://raw.githubusercontent.com/EN5R/XSSavior/refs/heads/main/src/XSSavior.png)


## Videos
[https://github.com/EN5R/SQLspectre/blob/main/src/XSSavior.mp4
]()


## Usage

You can view the usage instructions with the following command:

```bash
  python3.12 xssavior.py
```


## Installation

XSSavior can be easily installed along with its required libraries as follows:

```bash
  pip3.12 install -r requirements.txt
```
    
## Running

You can run XSSavior with the following command:

```bash
  python3.12 xssavior.py
```

## Important Note

This script should not be run with `sudo`. Running it with `sudo` may lead to unexpected errors and some functions may not work correctly. Please run the script as a normal user.

## About the Project

**XSSavior** is a specialized tool created to uncover cross-site scripting (XSS) vulnerabilities in web applications. The core features of this tool include:

- **Custom Payload Delivery:** XSSavior injects user-defined payloads into target websites to evaluate how well input validation is handled and to spot potential vulnerabilities.

- **Response Assessment:** This tool reviews HTTP responses and checks for changes in the Document Object Model (DOM) that may suggest security risks.

- **Anonymity Through Proxy Usage:** To protect user identity and avoid detection, XSSavior supports rotating through multiple proxies while conducting scans.

- **Automated Browsing Capabilities:** Integrating with Selenium allows XSSavior to automate interactions with web browsers, facilitating more complex and thorough testing procedures.

- **In-Depth Activity Logging:** The software keeps comprehensive logs of each step in the scanning process, assisting users in analyzing results and addressing any issues effectively.

The goal of this project is to enhance the process of vulnerability assessment, providing both developers and security professionals with reliable tools to identify and mitigate XSS vulnerabilities in their applications.


## 🔗 Links
[![portfolio](https://img.shields.io/badge/my_portfolio-000?style=for-the-badge&logo=ko-fi&logoColor=white)](https://github.com/EN5R/)
[![Buy me a coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=000000)](https://www.buymeacoffee.com/EN5R)
[![Join Telegram](https://img.shields.io/badge/Join%20Telegram-0088cc?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/+K3G9CJmZfShmOGI0)

## License

This project is licensed under the [MIT License.](https://raw.githubusercontent.com/EN5R/XSSavior/refs/heads/main/LICENSE)

Feel free to modify or add any information as needed! If there's anything more you'd like to include, just let me know!
