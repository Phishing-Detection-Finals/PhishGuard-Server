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
import logging


class PhishAlgorithm:

    def get_component_hash(self, content):
        hash_value = hashlib.sha256(content.encode()).hexdigest()
        logging.debug(f"Generated hash for content: {hash_value}")
        return hash_value

    def get_page_components(self, url: str) -> Webpage:
        try:
            logging.debug(f"Fetching page components from URL: {url}")
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            webpage = Webpage()
            webpage.title_hash = self.get_component_hash(soup.title.string if soup.title else "")
            webpage.body_hash = self.get_component_hash(content=soup.find('body').text if soup.find('body') else "")
            webpage.header_hash = self.get_component_hash(soup.find('header').text if soup.find('header') else "")
            webpage.footer_hash = self.get_component_hash(soup.find('footer').text if soup.find('footer') else "")
            logging.debug(f"Extracted page components from URL: {url}")
            return webpage
        except Exception as e:
            logging.error(f"Failed to get page components for URL {url}: {e}")
            raise WebpageInaccessibleException(url=url)

    def normalize_url(self, url: str) -> str:
        parsed_url = urlparse(url)
        # Remove 'www.' prefix if present
        netloc = parsed_url.netloc.replace('www.', '') if parsed_url.netloc.startswith('www.') else parsed_url.netloc
        normalized_url = parsed_url._replace(netloc=netloc).geturl()
        logging.debug(f"Normalized URL: {url} -> {normalized_url}")
        return normalized_url

    def compare_hashes(self, hash1, hash2):
        ratio = SequenceMatcher(None, hash1, hash2).ratio()
        logging.debug(f"Comparing hashes: {hash1} and {hash2}. Similarity ratio: {ratio}")
        return ratio

    def get_ssl_cert(self, url):
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        cert = ssl.get_server_certificate((hostname, 443))
        cert_hash = hashlib.sha256(cert.encode()).hexdigest()
        logging.debug(f"Retrieved SSL certificate hash for {url}: {cert_hash}")
        return cert_hash  # Hash the certificate for easier comparison

    def compare_site(self, legit_site: Webpage, checked_webpage: Webpage, cert_hash) -> PhishResponse:
        normalized_legit_url = self.normalize_url(legit_site.url)
        normalized_checked_url = self.normalize_url(checked_webpage.url)
        if normalized_legit_url == normalized_checked_url:
            logging.debug(f"URLs match: {normalized_legit_url} == {normalized_checked_url}. Returning GREEN.")
            return PhishResponse.GREEN

        total_similarity = 0
        num_components = 3  # We have 3 components: title, header, footer

        total_similarity += self.compare_hashes(checked_webpage.title_hash, legit_site.title_hash)
        total_similarity += self.compare_hashes(checked_webpage.header_hash, legit_site.header_hash)
        total_similarity += self.compare_hashes(checked_webpage.footer_hash, legit_site.footer_hash)

        average_similarity = total_similarity / num_components
        logging.debug(f"Average similarity for site comparison: {average_similarity}")

        if average_similarity >= Constants.DESIRED_SIMILARITY_PERCENTAGE:
            legit_cert_hash = self.get_ssl_cert(legit_site.url)
            if cert_hash != legit_cert_hash:
                logging.debug("Certificate hashes do not match. Returning RED.")
                return PhishResponse.RED  # Potential phishing site
        logging.debug("Site cannot be determined as phishing. Returning YELLOW.")
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
                    logging.debug("Phishing check result: GREEN")
                    return PhishResponse.GREEN  # Immediate return if any site is determined to be not phishing
                elif result == PhishResponse.RED:
                    found_red = True
        logging.debug(f"Phishing check result: {'RED' if found_red else 'YELLOW'}")
        return PhishResponse.RED if found_red else PhishResponse.YELLOW


# We had a problem in our similarity check - the code below was supposed to be the main algorithm as noted in our docs
    # def fetch_dom(self):
    #     logging.info(f"Fetching DOM for {self.url}")
    #     try:
    #         response = requests.get(f"https://{self.url}")
    #         if response.status_code == 200:
    #             soup = BeautifulSoup(response.text, 'html.parser')
    #             text = soup.get_text()
    #             # Create a set of hashes of the words in the DOM
    #             self.dom_hashes = [self.hash_string_murmur3(word) for word in text.split()]
    #         else:
    #             logging.error(f"Failed to fetch DOM for {self.url}, status code: {response.status_code}")
    #     except Exception as e:
    #         logging.error(f"Error fetching DOM for {self.url}: {str(e)}")

    # def hash_string_murmur3(self, value, seed=0):
    #     """Create a MurmurHash3 hash of the given value with an optional seed."""
    #     # Convert value to string if it's not already
    #     if isinstance(value, int):
    #         value = str(value)
    #     # Encode the string as bytes
    #     value_bytes = value.encode('utf-8')
    #     return mmh3.hash(value_bytes, seed)

    # def calculate_minhash(self):
    #     if self.dom_hashes:
    #         logging.info(f"Calculating MinHash for {self.url}")
    #         minhash_values = []
    #         for i in range(self.num_hashes):
    #             # Use a different seed for each hash function simulation
    #             seed = i
    #             minhash_values.append(min([self.hash_string_murmur3(hd, seed) for hd in self.dom_hashes]))
    #         self.minhash_signature = minhash_values
    #         # Use first 128 bits as the MinHash signature (simulating MinHash for demonstration)
    #         # self.minhash = int(self.dom_hash[:32], 16)
    #         logging.info(f"MinHash value for {self.url}: {self.minhash_signature}")
    #     else:
    #         logging.error(f"No DOM hash available for {self.url}")

    # def get_minhash(self):
    #     return self.minhash_signature

    # def fetch_certificate(self):
    #     logging.info(f"Fetching certificate for {self.url}")
    #     try:
    #         cert = ssl.get_server_certificate((self.url, 443))
    #         x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    #         return x509
    #     except Exception as e:
    #         logging.error(f"Error fetching certificate for {self.url}: {str(e)}")
    #         return None

    # def compare_certificates(self, cert1, cert2):
    #     try:
    #         # Compare certificates by digest (SHA-256 in this example)
    #         digest_algorithm = 'sha256'

    #         cert1_digest = cert1.digest(digest_algorithm).decode()
    #         cert2_digest = cert2.digest(digest_algorithm).decode()

    #         return cert1_digest == cert2_digest
    #     except Exception as e:
    #         logging.error(f"Error comparing certificates: {str(e)}")
    #         return False

    # def print_certificate_details(self, cert):
    #     logging.info(f"Certificate details for {self.url}:")
    #     logging.info(f"Issuer: {cert.get_issuer()}")
    #     logging.info(f"Subject: {cert.get_subject()}")
    #     logging.info(f"Serial Number: {cert.get_serial_number()}")
    #     logging.info(f"SHA1 fingerprint: {cert.digest('sha1').decode()}")

    # def jaccard_similarity(self, signature1, signature2):
    #     """Calculate the Jaccard similarity between two MinHash signatures."""
    #     if not len(signature1) or not len(signature2):
    #         return 0.0

    #     matching_hashes = sum(1 for s1, s2 in zip(signature1, signature2) if s1 == s2)
    #     return matching_hashes / len(signature1)

    # def isPhishing():
    #     original_site = "youtube.com"
    #     comparison_sites = ["google.com", "google.co.il", "youtube.com", "facebook.com"]

    #     minhash_results = {}
    #     minhash_original = MinHash(original_site)
    #     minhash_original_value = minhash_original.get_minhash()

    #     for site in comparison_sites:
    #         minhash = MinHash(site)
    #         minhash_value = minhash.get_minhash()

    #         # Calculate Jaccard similarity using numpy arrays
    #         similarity = 1.0 - jaccard_similarity(np.array(minhash_original_value), np.array(minhash_value))
    #         # jaccard_similarity = len(bin(minhash_original_value ^ minhash_value)) / 128.0

    #         # Adjust to directly compare MinHash values for the original site
    #         if site == original_site:
    #             similarity = 1.0  # Set similarity to 1.0 for self-comparison

    #         minhash_results[site] = similarity
    #         logging.info(f"MinHash value for {site}: {minhash_value}")

    #     most_similar_site = max(minhash_results, key=minhash_results.get)
    #     logging.info(
    #         f"The most similar site to {original_site} is {most_similar_site} with
    # Jaccard similarity {minhash_results[most_similar_site]}")

    #     cert_checker_original = CertificateChecker(original_site)
    #     cert_checker_similar = CertificateChecker(most_similar_site)

    #     cert_original = cert_checker_original.fetch_certificate()
    #     cert_similar = cert_checker_similar.fetch_certificate()

    #     if cert_original and cert_similar:
    #         cert_match = cert_checker_original.compare_certificates(cert_original, cert_similar)
    #         if cert_match:
    #             logging.info("Certificates match!")
    #         else:
    #             logging.warning("Certificates do not match. The site seems suspicious.")
    #     else:
    #         logging.warning("Unable to compare certificates.")

    #     if cert_original:
    #         cert_checker_original.print_certificate_details(cert_original)
    #     if cert_similar:
    #         cert_checker_similar.print_certificate_details(cert_similar)
