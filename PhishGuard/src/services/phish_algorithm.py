import hashlib
import ssl
from bs4 import BeautifulSoup
import requests
from difflib import SequenceMatcher
from concurrent.futures import ThreadPoolExecutor
from ..data.webpage import Webpage
from urllib.parse import urlparse
from ..constants import Constants
from ..enums.phish_response_enum import PhishResponse
from ..exceptions.webpage_inaccessible_exception import WebpageInaccessibleException


class PhishAlgorithm:
    def test_url_for_phishing(self, url: str) -> dict:
        # TODO implement phishing test algorithm here
        # until algorithm implemented, if url contains 'phish' - it is phishing
        is_phishing = "phish" in url.lower()
        return {"is_phishing": is_phishing}

    def get_component_hash(self, content):
        return hashlib.sha256(content.encode()).hexdigest()

    def get_page_components(self, url: str) -> Webpage:
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            webpage = Webpage()
            webpage.title_hash = soup.title.string if soup.title else ""
            webpage.header_hash = soup.find('header').text if soup.find('header') else ""
            webpage.footer_hash = soup.find('footer').text if soup.find('footer') else ""
            return webpage
        except Exception:
            raise WebpageInaccessibleException(url=url)

    def normalize_url(self, url: str) -> str:
        parsed_url = urlparse(url)
        # Remove 'www.' prefix if present
        netloc = parsed_url.netloc.replace('www.', '') if parsed_url.netloc.startswith('www.') else parsed_url.netloc
        return parsed_url._replace(netloc=netloc).geturl()

    def compare_hashes(self, hash1, hash2):
        return SequenceMatcher(None, hash1, hash2).ratio()

    def get_ssl_cert(self, url):
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        cert = ssl.get_server_certificate((hostname, 443))
        return hashlib.sha256(cert.encode()).hexdigest()  # Hash the certificate for easier comparison

    def compare_site(self, legit_site: Webpage, checked_webpage: Webpage, cert_hash) -> PhishResponse:
        normalized_legit_url = self.normalize_url(legit_site.url)
        normalized_checked_url = self.normalize_url(checked_webpage.url)
        if normalized_legit_url == normalized_checked_url:
            return PhishResponse.GREEN

        total_similarity = 0
        num_components = 3  # We have 3 components: title, header, footer

        total_similarity += self.compare_hashes(checked_webpage.title_hash, legit_site.title_hash)
        total_similarity += self.compare_hashes(checked_webpage.header_hash, legit_site.header_hash)
        total_similarity += self.compare_hashes(checked_webpage.footer_hash, legit_site.footer_hash)

        average_similarity = total_similarity / num_components

        if average_similarity >= Constants.DESIRED_SIMILARITY_PERCENTAGE:
            legit_cert_hash = self.get_ssl_cert(legit_site.url)
            if cert_hash != legit_cert_hash:
                return PhishResponse.RED  # Potential phishing site
        return PhishResponse.YELLOW  # Site cannot be determined

    def is_phishing(self, url: str, legitimate_sites: list[Webpage]) -> PhishResponse:
        checked_webpage = self.get_page_components(url)
        checked_webpage.url = url
        cert_hash = self.get_ssl_cert(url)
        found_red = False

        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.compare_site, legit_site, checked_webpage,
                                       cert_hash) for legit_site in legitimate_sites]
            for future in futures:
                result = future.result()
                if result == PhishResponse.GREEN:
                    return PhishResponse.GREEN  # Immediate return if any site is determined to be not phishing
                elif result == PhishResponse.RED:
                    found_red = True

        return PhishResponse.RED if found_red else PhishResponse.YELLOW


# url_to_check = "https://facebook.com"
# print(PhishAlgorithm().is_phishing(url=url_to_check))
