import hashlib
import ssl
from bs4 import BeautifulSoup
import requests
from difflib import SequenceMatcher
from concurrent.futures import ThreadPoolExecutor
from ..data.webpage import Webpage
from urllib.parse import urlparse
from ..constants import Constants


class PhishAlgorithm:
    def test_url_for_phishing(self, url: str) -> dict:
        # TODO implement phishing test algorithm here
        # until algorithm implemented, if url contains 'phish' - it is phishing
        is_phishing = "phish" in url.lower()
        return {"is_phishing": is_phishing}

    def get_component_hash(self, content):
        return hashlib.sha256(content.encode()).hexdigest()

    def get_page_components(self, url):
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string if soup.title else ""
        header = soup.find('header').text if soup.find('header') else ""
        footer = soup.find('footer').text if soup.find('footer') else ""
        return {
            "title": self.get_component_hash(title),
            "header": self.get_component_hash(header),
            "footer": self.get_component_hash(footer)
        }

    def compare_hashes(self, hash1, hash2):
        return SequenceMatcher(None, hash1, hash2).ratio()

    def get_ssl_cert(self, url):
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        cert = ssl.get_server_certificate((hostname, 443))
        return hashlib.sha256(cert.encode()).hexdigest()  # Hash the certificate for easier comparison

    def compare_site(self, legit_site: Webpage, components, cert_hash):
        total_similarity = 0
        num_components = 3  # We have 3 components: title, header, footer

        total_similarity += self.compare_hashes(components.get("title", ""), legit_site.title_hash)
        total_similarity += self.compare_hashes(components.get("header", ""), legit_site.header_hash)
        total_similarity += self.compare_hashes(components.get("footer", ""), legit_site.footer_hash)

        average_similarity = total_similarity / num_components

        if average_similarity >= Constants.DESIRED_SIMILARITY_PERCENTAGE:
            legit_cert_hash = self.get_ssl_cert(legit_site.url)
            if cert_hash != legit_cert_hash:
                return True  # Potential phishing site
        return False  # Site is safe

    def is_phishing(self, url: str, legitimate_sites: list[Webpage]):
        components = self.get_page_components(url)
        cert_hash = self.get_ssl_cert(url)
        potential_phishing = False

        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.compare_site, legit_site, components, cert_hash) for legit_site in legitimate_sites]  # noqa501
            for future in futures:
                if future.result():
                    potential_phishing = True
                    break

        return potential_phishing


# url_to_check = "https://facebook.com"
# print(PhishAlgorithm().is_phishing(url=url_to_check))
