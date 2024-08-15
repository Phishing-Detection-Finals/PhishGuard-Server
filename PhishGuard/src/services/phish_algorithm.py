import logging
import ssl
from urllib.parse import urlparse

import requests
from OpenSSL import crypto
from bs4 import BeautifulSoup
from datasketch import MinHash

from ..data.webpage import Webpage
from ..enums.phish_response_enum import PhishResponse


class CertificateHandler:
    def __init__(self, url):
        self.url = url

    def fetch_certificate(self):
        logging.info(f"Fetching certificate for {self.url}")
        try:
            cert = ssl.get_server_certificate((self.url, 443))
            x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
            logging.info(f"Successfully fetched certificate for {self.url}")
            return x509
        except Exception as e:
            logging.error(f"Error fetching certificate for {self.url}: {str(e)}")
            return None

    def compare_certificates(self, cert1, cert2):
        try:
            # Compare certificates by issuer and subject (or other attributes)
            digest_algorithm = 'sha256'
            cert1_digest = cert1.digest(digest_algorithm).decode()
            cert2_digest = cert2.digest(digest_algorithm).decode()
            return cert1_digest == cert2_digest
        except Exception as e:
            logging.error(f"Error comparing certificates: {str(e)}")
            return False

    def print_certificate_details(self, cert):
        logging.info(f"Certificate details for {self.url}:")
        logging.info(f"Issuer: {cert.get_issuer()}")
        logging.info(f"Subject: {cert.get_subject()}")
        logging.info(f"Serial Number: {cert.get_serial_number()}")
        logging.info(f"SHA1 fingerprint: {cert.digest('sha1').decode()}")


class PhishAlgorithm:

    # Function to fetch and parse the DOM from a URL
    def fetch_and_parse(self, url):
        logging.info(f"Fetching URL: {url}")
        try:
            response = requests.get(url)
            response.raise_for_status()  # Check if the request was successful
            soup = BeautifulSoup(response.text, 'html.parser')
            logging.info(f"Successfully fetched and parsed {url}")
            return soup
        except requests.RequestException as e:
            logging.error(f"Error fetching {url}: {e}")
            return None

    def normalize_url(self, url: str) -> str:
        # Remove 'https://.' protocol if present
        parsed_url = urlparse(url)
        url_hostname = parsed_url.hostname
        logging.debug(f"Normalized hostname URL: {url} -> {url_hostname}")
        return url_hostname

    # Function to tokenize the DOM by extracting tags, classes, and IDs
    def tokenize_dom(self, soup):
        tokens = set()
        if soup:
            logging.info("Tokenizing DOM")
            for element in soup.find_all(True):  # True finds all tags
                tokens.add(element.name)  # Add tag names as tokens
                tokens.update(element.get('class', []))  # Add classes if any
                tokens.update(element.get('id', []))  # Add IDs if any
        logging.info(f"Extracted {len(tokens)} tokens")
        return tokens

    # Function to compute MinHash signature for a set of tokens
    def compute_minhash(self, tokens):
        logging.info("Computing MinHash")
        minhash = MinHash()
        for token in tokens:
            minhash.update(token.encode('utf8'))  # Encode token for hashing
        return minhash

    # Function to compare the similarity between two sets of MinHash signatures
    def compute_similarity(self, url, legitimate_site):
        logging.info(f"Comparing {url} with {legitimate_site}")
        soup1 = self.fetch_and_parse(legitimate_site)
        soup2 = self.fetch_and_parse(url)

        if soup1 is None or soup2 is None:
            logging.error("One of the DOMs could not be fetched. Skipping similarity calculation.")
            return None

        tokens1 = self.tokenize_dom(soup1)
        tokens2 = self.tokenize_dom(soup2)

        minhash1 = self.compute_minhash(tokens1)
        minhash2 = self.compute_minhash(tokens2)

        similarity = minhash1.jaccard(minhash2)
        logging.info(f"Similarity between {url} and {legitimate_site}: {similarity:.4f}")
        return similarity

    # Function to compute similarities and find the most similar website
    def is_phishing(self, url: str, legitimate_sites: list[Webpage]) -> PhishResponse:
        logging.info(f"Finding the most similar website to {url}")
        best_similarity = -1
        most_similar_url = None

        for legitimate_site in legitimate_sites:
            logging.info(f"Testing legitimate_site - {legitimate_site.url}")
            similarity = self.compute_similarity(url, legitimate_site.url)
            if similarity is not None and similarity > best_similarity:
                best_similarity = similarity
                most_similar_url = legitimate_site.url

        if most_similar_url:
            # Compare SSL certificates only for the most similar website
            normalized_legitimate_url = self.normalize_url(most_similar_url)
            normalized_url = self.normalize_url(url)

            handler1 = CertificateHandler(normalized_legitimate_url)
            handler2 = CertificateHandler(normalized_url)

            cert1 = handler1.fetch_certificate()
            cert2 = handler2.fetch_certificate()

            if cert1 and cert2:
                # are_similar = handler1.compare_certificates(cert1, cert2)
                are_certificates_identical = handler1.compare_certificates(cert1, cert2)
                logging.info(f"Certificates comparison result: {'Match' if are_certificates_identical else 'Do not match'}")
                handler1.print_certificate_details(cert1)
                handler2.print_certificate_details(cert2)

                if are_certificates_identical:
                    status = PhishResponse.GREEN  # Certificates are the same
                elif best_similarity >= 0.85:  # Threshold for similarity
                    status = PhishResponse.RED  # Certificates are different but sites are similar enough
                else:
                    status = PhishResponse.YELLOW  # No valid comparisons or similarity not high enough
            else:
                status = PhishResponse.YELLOW  # No similar site found

        if most_similar_url:
            logging.info(
                f"The most similar website to {url} is {most_similar_url} with a similarity score of {best_similarity:.4f}. Status: {status}")
        else:
            logging.info(f"No valid comparisons were made. Status: {status}")

        return status
