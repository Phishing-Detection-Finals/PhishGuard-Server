import hashlib
import ssl
from bs4 import BeautifulSoup
import requests
from difflib import SequenceMatcher
from concurrent.futures import ThreadPoolExecutor
from ..data.website import Webpage
from urllib.parse import urlparse


class PhishAlgorithm:
    def test_url_for_phishing(self, url: str) -> dict:
        # TODO implement phishing test algorithm here
        # until algorithm implemented, if url contains 'phish' - it is phishing
        is_phishing = "phish" in url.lower()
        return {"is_phishing": is_phishing}

    # TODO get legitimate sites list from the DB
    legitimate_sites = [
        Webpage(
            "https://facebook.com",
            "7a8d46bf55a2b547e0658cb1e0c2b6d5cab2ec69fe51f1ca61eb8d895d1070bc",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "e0c2bd376fea4045bc3d23cafe10246c018409cbf4a0ad2316efea035f786dc1"
        )
    ]

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

    def compare_site(self, legit_site, components, cert_hash):
        total_similarity = 0
        num_components = 3  # We have 3 components: title, header, footer

        total_similarity += self.compare_hashes(components.get("title", ""), legit_site.titleComponentHash)
        total_similarity += self.compare_hashes(components.get("header", ""), legit_site.headerComponentHash)
        total_similarity += self.compare_hashes(components.get("footer", ""), legit_site.footerComponentHash)

        average_similarity = total_similarity / num_components

        if average_similarity >= 0.8 and cert_hash != legit_site.certificateHash:
            return True  # Potential phishing site

        return False  # Site is safe

    def is_phishing(self, url):
        components = self.get_page_components(url)
        cert_hash = self.get_ssl_cert(url)
        potential_phishing = False

        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.compare_site, legit_site, components, cert_hash) for legit_site in self.legitimate_sites]  # noqa501
            for future in futures:
                if future.result():
                    potential_phishing = True
                    break

        return potential_phishing


url_to_check = "https://facebook.com"
print(PhishAlgorithm().is_phishing(url=url_to_check))
