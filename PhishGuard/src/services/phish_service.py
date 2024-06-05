from PhishGuard.src.services.phish_algorithm import PhishAlgorithm
from ..validator import Validator


class PhishService():
    def __init__(self) -> None:
        pass

    def check_phish_by_url(self, url: str) -> dict:
        Validator.validate_url(url=url)

        return PhishAlgorithm().test_url_for_phishing(url=url)
