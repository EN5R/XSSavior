import os
import re
import random
import requests
import time
import json
import argparse
import logging
import urllib.parse
from datetime import datetime
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from concurrent.futures import ThreadPoolExecutor


def print_banner():
    banner = r"""
		    __  _____ ___           _         
		    \ \/ / __/ __| __ ___ _(_)___ _ _ 
		     >  <\__ \__ \/ _` \ V / / _ \ '_|
		    /_/\_\___/___/\__,_|\_/|_\___/_|  
                                               
            			by @E5R with ❤
            							v1


	My Github Profile: 		https://github.com/EN5R
	My X Profile:			https://x.com/EN544R
	My Telegram Channel: 		https://t.me/+K3G9CJmZfShmOGI0
	My Buy Me a Coffee Page:	https://buymeacoffee.com/EN5R
	
    """
    print(banner)
    
    
# ANSI escape kodlarıyla renkler
class Colors:
    INFO = "\033[92m"   # Yeşil (Bilgi mesajları)
    WARNING = "\033[93m"  # Sarı (Uyarılar)
    ERROR = "\033[91m"  # Kırmızı (Hatalar)
    VULNERABILITY = "\033[91m"  # Kırmızı (Zafiyetler)
    RESET = "\033[0m"   # Renk sıfırlama    


# Özel bir logger formatı tanımlayarak seviyelere renk ekleyelim
class CustomFormatter(logging.Formatter):
    """Custom formatter to add colors to log messages based on level."""
    
    def format(self, record):
        # Log seviyesi kontrol edilerek renkler atanıyor
        if record.levelno == logging.INFO:
            record.msg = f"{Colors.INFO}{record.msg}{Colors.RESET}"
        elif record.levelno == logging.VULNERABILITY:
            record.msg = f"{Colors.VULNERABILITY}{record.msg}{Colors.RESET}"    
        elif record.levelno == logging.WARNING:
            record.msg = f"{Colors.WARNING}{record.msg}{Colors.RESET}"
        elif record.levelno == logging.ERROR:
            record.msg = f"{Colors.ERROR}{record.msg}{Colors.RESET}"
        
        return super().format(record)

# Logger ayarları
logger = logging.getLogger()
handler = logging.StreamHandler()
formatter = CustomFormatter('%(levelname)s: %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)  # INFO seviyesinde başlatma


class ExceptionHandler:
    def __init__(self, max_retries=3):
        self.max_retries = max_retries

    def handle_timeout_exception(self):
        for attempt in range(1, self.max_retries + 1):
            logging.info(f"Timeout occurred. Retrying... (Attempt {attempt}/{self.max_retries})")
            try:
                # Burada yeniden deneme yapmak için gerekli kod eklenebilir
                # Örneğin, bir API çağrısı ya da web sayfasını yenileme
                break  # Başarılı olursa döngüden çık
            except Exception as e:
                logging.error(f"Attempt {attempt} failed. Error: {str(e)}")
                if attempt == self.max_retries:
                    logging.vulnerability("Max retries exceeded for timeout exception.")

    def handle_invalid_proxy_exception(self):
        for attempt in range(1, self.max_retries + 1):
            logging.info(f"Invalid or blocked proxy detected. Switching to a new proxy... (Attempt {attempt}/{self.max_retries})")
            try:
                # Burada proxy değiştirme mantığı eklenebilir
                break  # Başarılı olursa döngüden çık
            except Exception as e:
                logging.error(f"Attempt {attempt} failed while changing proxy. Error: {str(e)}")
                if attempt == self.max_retries:
                    logging.vulnerability("Max retries exceeded for invalid proxy exception.")

    def handle_selenium_exception(self):
        logging.info("Selenium issue detected. Restarting browser...")
        self.restart_browser()

    def restart_browser(self):
        # Mevcut durumu kaydetmek için gerekli kodları burada ekleyin
        logging.info("Saving the current state...")
        # Durumu kaydetme kodları...

        # Tarayıcıyı yeniden başlatma mantığı
        logging.info("Restarting the browser...")
        # Tarayıcıyı yeniden başlatma kodları...
        

class ConfigurationManager:
    def __init__(self, config_file=None):
        self.config_file = config_file
        self.config = {}
        if config_file:
            self.load_config()

    def load_config(self):
        """Loads the script configuration from a file."""
        if not self.config_file:
            logging.error("No configuration file specified.")
            return

        try:
            with open(self.config_file, 'r') as file:
                self.config = json.load(file)
                logging.info(f"Configuration loaded from {self.config_file}")
        except FileNotFoundError as e:
            logging.error(f"Configuration file not found: {self.config_file}")
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON from {self.config_file}: {e}")

    def get_setting(self, key, default=None):
        """Retrieves a specific setting with an optional default value."""
        if key in self.config:
            return self.config[key]
        else:
            if default is not None:
                logging.warning(f"Setting '{key}' not found, returning default value: {default}")
            else:
                logging.warning(f"Setting '{key}' not found and no default value provided.")
            return default

    def save_config(self):
        """Saves the current configuration to a file for future use."""
        if not self.config_file:
            logging.error("No configuration file specified for saving.")
            return

        try:
            with open(self.config_file, 'w') as file:
                json.dump(self.config, file, indent=4)
                logging.info(f"Configuration saved to {self.config_file}")
        except Exception as e:
            logging.error(f"Error saving configuration to {self.config_file}: {e}")
            

class Logger:

    def __init__(self, log_file='scanner.log', log_response_length=100):
        """Initializes the logger with a specified log file."""
        logging.basicConfig(
            filename=log_file,
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.log_file = log_file
        self.log_response_length = log_response_length  # Yanıt uzunluğunu ayarlanabilir hale getir

    def log_request(self, url, payload, headers, response_code):
        """Logs details of each request made during scanning."""
        pass

    def log_error(self, message):
        """Records errors or exceptions that occur during the testing process."""
        logging.error(f"Error: {message}")

    def log_vulnerability_found(self, url, payload, response):
        """Logs details of detected vulnerabilities for later review."""
        logging.vulnerability(f"Vulnerability found at {url} with payload: {payload}")  # Daha yüksek seviyede loglama
        logging.vulnerability(f"Response: {response.text[:self.log_response_length]}...")  # İsteğe bağlı olarak loglama uzunluğu

    def log_request_error(self, url, error_message):
        """Logs details of errors that occur during requests."""
        logging.error(f"Request error at {url}: {error_message}")


class ReportGenerator:
    def __init__(self):
        self.vulnerabilities = []

    def add_vulnerability(self, url, payload, response, screenshot_path=None):
        """Adds a detected vulnerability to the report."""
        vulnerability = {
            'url': url,
            'payload': payload,
            'response': response[:100],  # Sadece ilk 100 karakteri alır
            'timestamp': datetime.now().isoformat(),
            'screenshot': screenshot_path
        }
        self.vulnerabilities.append(vulnerability)

    def generate_html_report(self, filename='report.html'):
        """Creates a detailed HTML report summarizing all detected vulnerabilities."""
        with open(filename, 'w') as file:
            file.write('<html><head><title>Vulnerability Report</title>')
            file.write('<style>body { font-family: Arial, sans-serif; } table { border-collapse: collapse; width: 100%; } th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }</style>')
            file.write('</head><body>')
            file.write('<h1>Vulnerability Report</h1>')
            file.write('<table><tr><th>URL</th><th>Payload</th><th>Response</th><th>Timestamp</th><th>Screenshot</th></tr>')
            for vuln in self.vulnerabilities:
                file.write('<tr>')
                file.write(f'<td>{vuln["url"]}</td>')
                file.write(f'<td>{vuln["payload"]}</td>')
                file.write(f'<td><pre>{vuln["response"]}</pre></td>')
                file.write(f'<td>{vuln["timestamp"]}</td>')
                if vuln['screenshot']:
                    file.write(f'<td><img src="{vuln["screenshot"]}" width="200"/></td>')
                else:
                    file.write('<td>N/A</td>')
                file.write('</tr>')
            file.write('</table></body></html>')
        print(f"HTML report generated: {filename}")

    def generate_json_report(self, filename='report.json'):
        """Creates a JSON-formatted report for integration with other systems or tools."""
        with open(filename, 'w') as file:
            json.dump(self.vulnerabilities, file, indent=4)
        print(f"JSON report generated: {filename}")

    def generate_plaintext_report(self, filename='report.txt'):
        """Generates a simple text report for easy reading."""
        with open(filename, 'w') as file:
            for vuln in self.vulnerabilities:
                file.write(f"URL: {vuln['url']}\n")
                file.write(f"Payload: {vuln['payload']}\n")
                file.write(f"Response: {vuln['response']}\n")
                file.write(f"Timestamp: {vuln['timestamp']}\n")
                if vuln['screenshot']:
                    file.write(f"Screenshot: {vuln['screenshot']}\n")
                else:
                    file.write("Screenshot: N/A\n")
                file.write("\n")
        print(f"TEXT report generated: {filename}")

    def include_screenshots(self, screenshot_path):
        """Embeds screenshots in the report to visualize detected vulnerabilities."""
        # Ekran görüntülerinin rapora eklenmesi için kullanım.
        pass  # Geliştirmek için kod eklenebilir.
        

class VulnerabilityChecker:
    def __init__(self, driver):
        self.driver = driver  # Selenium WebDriver instance

    def check_response_for_xss(self, response, payload):
        """Analyzes the HTML response for signs of payload execution."""
        # Daha kapsamlı bir kontrol: payload элементов içindeki tahrip edici içerikleri kontrol et
        if payload in response.text:
            print(f"XSS vulnerability detected in response with payload: {payload}")
            return True
        
        # Örnek daha güvenli HTML içerik kontrolü
        dangerous_elements = ['<script>', 'onerror', 'onclick', 'onload']
        if any(element in response.text for element in dangerous_elements):
            print("Potential XSS vulnerability detected due to dangerous elements in the response.")
            return True

        return False

    def check_dom_changes(self):
        """Uses Selenium to inspect the DOM for modifications caused by malicious payloads."""
        original_html = self.driver.page_source
        # Burada payload'ı çalıştırmanız gerekiyor. Bunun için uygun yöntem eklenmeli.
        # Örnek: self.execute_payload(payload)

        modified_html = self.driver.page_source
        if original_html != modified_html:
            print("DOM changes detected, possible XSS vulnerability.")
            return True
        
        return False

    def detect_javascript_alerts(self):
        """Looks for JavaScript alerts triggered by payload execution."""
        try:
            alert = self.driver.switch_to.alert
            print("JavaScript alert detected!")
            alert.accept()  # Accept the alert to close it
            return True
        except Exception as e:
            print("No JavaScript alert detected.")
            return False

    def log_vulnerability(self, payload, response):
        """Logs details of the detected vulnerability."""
        with open('vulnerabilities.log', 'a') as log_file:
            log_file.write(f"Timestamp: {datetime.now().isoformat()}\n")
            log_file.write(f"Vulnerability detected with payload: {payload}\n")
            log_file.write(f"Response: {response.text}\n\n")
        print("Vulnerability details logged.")
        

class SeleniumDriverManager:

    def __init__(self, proxy_rotator, user_agent_rotator):
        self.proxy_rotator = proxy_rotator
        self.user_agent_rotator = user_agent_rotator
        self.driver = None
        self.initialize_driver()

    def initialize_driver(self):
        """WebDriver'ı başlatır."""
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")  # Başsız modda çalıştırmak için
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")

        self.set_proxy(options)
        self.set_user_agent(options)

        try:
            self.driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
            logging.info("WebDriver successfully initialized.")
        except Exception as e:
            logging.error(f"Failed to initialize WebDriver: {str(e)}")
            raise  # Hatanın üst katmana iletilmesi

    def set_proxy(self, options):
        """WebDriver için bir proxy ayarlar."""
        if self.proxy_rotator:
            proxy = self.proxy_rotator.rotate_proxy()
            if proxy:
                options.add_argument(f'--proxy-server={proxy["http"]}')
                logging.info(f'Proxy set to: {proxy["http"]}')
            else:
                logging.warning("No proxy available. Proceeding without a proxy.")
        else:
            logging.info("Proxy rotator not provided. Proceeding without a proxy.")

    def set_user_agent(self, options):
        """WebDriver için bir kullanıcı ajanı ayarlar."""
        if self.user_agent_rotator:
            user_agent = self.user_agent_rotator.rotate_user_agent()
            if user_agent:
                options.add_argument(f'user-agent={user_agent}')
                logging.info(f'User agent set to: {user_agent}')
            else:
                logging.warning("No user agent available. Proceeding with default user agent.")
        else:
            logging.info("User agent rotator not provided. Proceeding with default user agent.")

    def navigate_to_page(self, url):
        """WebDriver ile belirtilen URL'ye yönlendirir."""
        try:
            self.driver.get(url)
            logging.info(f"Navigated to: {url}")
        except Exception as e:
            logging.error(f"Error navigating to {url}: {str(e)}")
            raise

    def execute_payload(self, payload, field_selector):
        """Belirtilen form alanına bir payload enjekte eder ve formu gönderir."""
        try:
            field = self.driver.find_element(By.CSS_SELECTOR, field_selector)
            field.send_keys(payload)
            field.submit()
            logging.info(f"Executed payload on selector '{field_selector}': {payload}")
        except Exception as e:
            logging.error(f"Error executing payload: {str(e)}")

    def capture_screenshot(self, filename):
        """Potansiyel bir zafiyet bulunduğunda ekran görüntüsü alır."""
        try:
            self.driver.save_screenshot(filename)
            logging.info(f"Screenshot captured: {filename}")
        except Exception as e:
            logging.error(f"Error capturing screenshot: {str(e)}")

    def close_driver(self):
        """WebDriver'ı kapatır ve kaynakları serbest bırakır."""
        if self.driver:
            self.driver.quit()
            logging.info("WebDriver closed.")
                                            

class UserAgentRotator:
    def __init__(self):
        self.user_agents = self.load_user_agents()
        self.used_agents = {}

    def load_user_agents(self):
        return [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.1 Safari/605.1.15",
            "Mozilla/5.0 (Linux; Android 8.0.0; Nexus 5X Build/OPR6.170623.021) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Mobile Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/91.0",
            "Mozilla/5.0 (Linux; Ubuntu; 18.04; rv:91.0) Gecko/20100101 Firefox/91.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        ]

    def rotate_user_agent(self):
        if not self.user_agents:
            print("No user agents available.")
            return None
        user_agent = random.choice(self.user_agents)
        self.track_used_agents(user_agent)
        return user_agent

    def track_used_agents(self, user_agent):
        if user_agent in self.used_agents:
            self.used_agents[user_agent] += 1
        else:
            self.used_agents[user_agent] = 1


class RequestHandler:
    def __init__(self, target_url, proxy=None):
        self.target_url = target_url
        self.http_methods = ['GET', 'POST', 'PUT', 'DELETE']  # HTTP methods to use
        self.proxy = proxy
        self.headers = {}  # Initialize headers attribute
        self.user_agent = None  # User agent initially None

    def set_user_agent(self, user_agent):
        if user_agent and user_agent != self.user_agent:  # Only set if it's different
            self.user_agent = user_agent
            self.headers['User-Agent'] = user_agent

    def send_request(self, payload, method='GET'):
        """Send request using the specified HTTP method with the given payload."""
        if self.user_agent:
            self.headers['User-Agent'] = self.user_agent

        try:
            method = method.upper()
            if method == 'GET':
                response = requests.get(
                    f"{self.target_url}?payload={requests.utils.quote(payload)}",
                    headers=self.headers,
                    proxies=self.proxy
                )
            elif method == 'POST':
                response = requests.post(
                    self.target_url,
                    data={'payload': payload},
                    headers=self.headers,
                    proxies=self.proxy
                )
            elif method == 'PUT':
                response = requests.put(
                    self.target_url,
                    data={'payload': payload},
                    headers=self.headers,
                    proxies=self.proxy
                )
            elif method == 'DELETE':
                response = requests.delete(
                    self.target_url,
                    data={'payload': payload},
                    headers=self.headers,
                    proxies=self.proxy
                )
            else:
                raise ValueError("Unsupported HTTP method.")

            return response
        except requests.RequestException as e:
            logging.error(f"Request error: {e}")
            return None

    def rotate_methods(self):
        """Randomly select a method for HTTP requests."""
        return random.choice(self.http_methods)

    def handle_response(self, response):
        """Process the HTTP response and check for known vulnerability indicators."""
        if response and response.status_code == 200:
            # This should be a constant or configurable:
            expected_error_message = "beklenen bir hata mesajı"  
            if expected_error_message in response.text:
                logging.info("Vulnerability detected!")
                return True
            else:
                logging.info("No vulnerability detected.")
                return False
        else:
            logging.error(f"Error with response: {response.status_code if response else 'No response'}")
            return False

    def retry_request(self, payload, method='GET', retries=3, delay=5):
        """Apply logic to retry the request."""
        for attempt in range(retries):
            logging.info(f"Attempt {attempt + 1} of {retries} for payload: {payload}...")
            response = self.send_request(payload, method)
            if response and self.handle_response(response):
                return True
            logging.warning(f"Request failed, retrying in {delay} seconds...")
            time.sleep(delay)  # Add delay
        logging.error("All retry attempts failed.")
        return False

    def perform_test(self, payload, method='GET'):
        """Perform a test by sending a payload using the specified method."""
        if not self.target_url.startswith(('http://', 'https://')):
            logging.error("Geçersiz URL: Şema eksik.")
            return False

        test_url = f"{self.target_url}?payload={requests.utils.quote(payload)}"
        try:
            response = self.send_request(payload, method)
            if response and response.status_code == 200:
                if "beklenen bir hata mesajı" in response.text:  # Replace with constant
                    logging.info(f"Payload başarılı: {payload}")
                    return True
                else:
                    logging.warning(f"Successful request but the expected condition was not met: {payload}")
                    return False
            else:
                logging.error(f"Hata kodu: {response.status_code}. Yanıt: {response.text[:100] if response else 'No response'}")
                return False
        except requests.RequestException as e:
            logging.error(f"Genel hata: {e}")
            return False
                                              

class PayloadManager:
    def __init__(self, filename):
        self.payloads = []
        self.load_payloads(filename)

    def load_payloads(self, filename):
        """Belirtilen dosyadan payload'ları yükler."""
        try:
            with open(filename, 'r') as file:
                self.payloads = [line.strip() for line in file if line.strip()]
            print(f"{len(self.payloads)} payload'lar başarıyla yüklendi.")
        except FileNotFoundError:
            print(f"Hata: '{filename}' dosyası bulunamadı.")
        except Exception as e:
            print(f"Bir hata oluştu: {e}")

    def get_all_payloads(self):
        """Tüm payload'ları döner."""
        if not self.payloads:
            print("No payloads available.")
            return []
        return self.payloads  # Tüm payload'ları döndür

    def filter_restricted_payloads(self, payload):
        """Kısıtlı karakter kontrolü uygular."""
        restricted_chars = ['<', '>', '{', '}', '[', ']', '(', ')']  # Kısıtlı karakterler
        return not any(char in payload for char in restricted_chars)

    def get_encoded_payloads(self):
        """Payload'ları URL encode eder."""
        return [urllib.parse.quote(payload) for payload in self.payloads if self.filter_restricted_payloads(payload)]
                       
        
class UserInterface:

    def collect_user_input(self):
        """Kullanıcıdan hedef URL'leri toplar."""
        urls = input("Target URLs (comma-separated): ").split(',')
        valid_urls = [url.strip() for url in urls if self.is_valid_url(url.strip())]

        if not valid_urls:
            print("Hata: Geçerli URL girilmedi. Lütfen en az bir geçerli URL sağlayın.")
            return {'urls': []}  # Boş bir liste döner

        print(f"{len(valid_urls)} geçerli URL toplandı.")
        return {'urls': valid_urls}

    @staticmethod
    def is_valid_url(url):
        """Geçerli bir URL'nin formatını kontrol eder."""
        regex = re.compile(
            r'^(?:http|https|ftp)://'  # http:// veya https:// veya ftp://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,})|'  # host name
            r'localhost|'  # localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # IPv4
            r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # IPv6
            r'(:\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)  # path

        return re.match(regex, url) is not None
                
    def display_status(self, message):
        """Gerçek zamanlı durumu kullanıcıya gösterir."""
        print(f"Status: {message}")

    def collect_proxy_file(self):
        """Kullanıcıdan proxy wordlist dosyasının ismini alır (opsiyonel)."""
        proxy_file = input("Enter proxy (leave blank if not used, or enter multiple separated by commas): ").strip()
        if proxy_file and not os.path.isfile(proxy_file):
            print("The specified proxy file could not be found. Please provide a valid file.")
            return None  # Geçersiz dosya durumu

        return proxy_file  # Dosya geçerli ise geri döner
                
        
class ProxyRotator:

    def __init__(self, proxy_file):
        self.proxy_file = proxy_file
        self.proxies = self.load_proxy_list()

    def load_proxy_list(self):
        """Proxy listesini dosyadan yükler ve geçerli formatta olanları döndürür."""
        try:
            with open(self.proxy_file, 'r') as file:
                proxy_list = [line.strip() for line in file if line.strip() and self.is_valid_proxy(line.strip())]
            print(f"{len(proxy_list)} valid proxies loaded successfully.")
            return proxy_list
        except FileNotFoundError:
            print(f"Error: '{self.proxy_file}' not found.")
            return []
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            return []

    def is_valid_proxy(self, proxy):
        """Basit bir proxy format kontrolü yapar."""
        return re.match(r'^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$', proxy) is not None

    def rotate_proxy(self):
        """Rastgele proxy adreslerinden birini döndürür."""
        if not self.proxies:
            print("No proxies available.")
            return None
        proxy = random.choice(self.proxies)
        return {"http": proxy, "https": proxy}

    def test_proxy(self, proxy):
        """Verilen proxy'nin çalışıp çalışmadığını test eder."""
        try:
            response = requests.get('http://httpbin.org/ip', proxies=proxy, timeout=5)
            return response.status_code == 200
        except requests.RequestException:
            return False
        
    def clean_proxies(self):
        """Geçersiz proxy'leri kaldırır."""
        valid_proxies = []
        for proxy in self.proxies:
            if self.test_proxy({"http": proxy, "https": proxy}):
                valid_proxies.append(proxy)
            else:
                print(f"Proxy {proxy} is invalid and will be removed.")
        self.proxies = valid_proxies
        print(f"{len(self.proxies)} valid proxies remain after cleanup.")
                       

class Main:

    def __init__(self):
        print_banner()
        self.ui = UserInterface()
        self.proxy_rotator = None
        self.user_agent_rotator = UserAgentRotator()
        self.report_generator = ReportGenerator()
        self.logger = Logger()
        self.exception_handler = ExceptionHandler()

        # Başlangıç işlemleri
        self.collect_input_and_run()

    def collect_input_and_run(self):
        """Kullanıcıdan giriş alır ve çalıştırılır."""
        payload_file = self.get_payload_file()
        pm = PayloadManager(payload_file)

        # Proxy rotator'u ayarla
        self.proxy_rotator = self.setup_proxy_rotator()
        self.selenium_driver_manager = SeleniumDriverManager(self.proxy_rotator, self.user_agent_rotator)

        # Hedef URL'leri al
        urls = self.get_target_urls()

        if urls:
            logging.info("Input validated, proceeding...")
            self.run_tests(pm, urls)
        else:
            logging.warning("No valid URLs provided.")

    def get_payload_file(self):
        """Payload dosyasını kullanıcıdan alır ve geçerliliğini kontrol eder."""
        while True:
            payload_file = input("Enter the payload file path (e.g., payloads.txt): ")
            if os.path.isfile(payload_file):
                return payload_file
            logging.warning("Geçersiz dosya. Lütfen tekrar girin.")

    def setup_proxy_rotator(self):
        """Proxy dosyasını kullanıcıdan alır ve ProxyRotator oluşturur."""
        proxy_file = self.ui.collect_proxy_file()
        if proxy_file:
            return ProxyRotator(proxy_file)
        logging.info("No proxy file provided.")
        return None

    def get_target_urls(self):
        """Kullanıcıdan hedef URL'leri alır."""
        urls = self.ui.collect_user_input().get('urls', [])
        return [url.strip() for url in urls if self.ui.is_valid_url(url.strip())]

    def run_tests(self, pm, urls):
        """Belirtilen URL'lere test yükleri gönderir."""
        payloads = pm.get_encoded_payloads()  # URL encode edilmiş payload'ları al
        if not payloads:
            logging.warning("No payloads available to test.")
            return

        checker = VulnerabilityChecker(self.selenium_driver_manager.driver)

        # Çoklu iş parçacığı ile test
        with ThreadPoolExecutor(max_workers=5) as executor:
            for url in urls:
                for payload in payloads:
                    executor.submit(self.test_url_with_payload, url, payload, checker)

        logging.info("All tests completed.")
        self.generate_reports()

    def generate_reports(self):
        """Test sonuç raporlarını oluşturur."""
        self.report_generator.generate_html_report()
        self.report_generator.generate_json_report()
        self.report_generator.generate_plaintext_report()

    def test_url_with_payload(self, url, payload, checker):
        """Belirli bir URL üzerinde yük ile test yapar."""
        logging.warning(f"Testing payload: {payload}")

        handler = RequestHandler(url, self.proxy_rotator.rotate_proxy() if self.proxy_rotator else None)
        user_agent = self.user_agent_rotator.rotate_user_agent()
        handler.set_user_agent(user_agent)

        try:
            self.logger.log_request(url, payload, handler.headers, None)

            if handler.perform_test(payload):
                response = handler.send_request(payload)
                self.check_vulnerabilities(url, payload, response, checker)
            else:
                logging.warning(f"No vulnerability found with payload: {payload}")

        except Exception as e:
            self.handle_exception(e)

    def check_vulnerabilities(self, url, payload, response, checker):
        """Yanıt üzerinde güvenlik açıklarını kontrol eder."""
        for check in [
            checker.check_response_for_xss,
            checker.check_dom_changes,
            checker.detect_javascript_alerts
        ]:
            if check(response, payload):
                self.handle_vulnerability(url, payload, response)

    def handle_vulnerability(self, url, payload, response):
        """Bulunan güvenlik açığını raporlar."""
        self.report_generator.add_vulnerability(url, payload, response.text)
        self.logger.log_vulnerability_found(url, payload, response.text)
        logging.info(f"Vulnerability found for {url} with payload: {payload}")

    def handle_exception(self, exception):
        """Bağlantı hatalarını yönetir."""
        if isinstance(exception, TimeoutError):
            self.exception_handler.handle_timeout_exception()
            self.logger.log_error("Timeout occurred during the request.")
        elif isinstance(exception, InvalidProxyError):
            self.exception_handler.handle_invalid_proxy_exception()
            self.logger.log_error("Invalid proxy detected.")
        elif isinstance(exception, SeleniumException):
            self.exception_handler.handle_selenium_exception()
            self.logger.log_error("Selenium encountered an issue.")
        else:
            self.logger.log_error(f"Hata mesajı: {str(exception)}")
            logging.error(f"Unexpected error: {str(exception)}")
                                                                               

# Ana program akışı
if __name__ == "__main__":
    Main()
