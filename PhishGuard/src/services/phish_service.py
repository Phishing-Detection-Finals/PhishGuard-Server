from PhishGuard.src.services.phish_algorithm import PhishAlgorithm
from ..validator import Validator
from ..data.webpage import Webpage
from ..dal.webpage_crud import WebpageCRUD
import logging


class PhishService:
    def __init__(self) -> None:
        logging.debug("Initializing PhishService")
        pass

    def check_phish_by_url(self, url: str) -> dict:
        logging.debug(f"Received URL to check: {url}")
        Validator.validate_url(url=url)
        logging.debug("URL validation passed")

        result = PhishAlgorithm().is_phishing(
            url=url,
            legitimate_sites=self.get_known_website_list()
        )
        logging.debug(f"Phishing check result: {result.name}")
        return {"phish_result": result.name}

    def get_known_website_list(self) -> list[Webpage]:
        logging.debug("Fetching known trusted websites list")
        webpages = WebpageCRUD().get_trusted_webpages_list()
        logging.debug(f"Fetched {len(webpages)} trusted websites")
        for w in webpages:
            logging.debug(f"Trusted website URL: {w.url}")
        return webpages
