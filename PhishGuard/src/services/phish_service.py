from PhishGuard.src.services.phish_algorithm import PhishAlgorithm
from ..validator import Validator
from ..data.webpage import Webpage
from ..dal.webpage_crud import WebpageCRUD


class PhishService():
    def __init__(self) -> None:
        pass

    def check_phish_by_url(self, url: str) -> dict:
        Validator.validate_url(url=url)

        return PhishAlgorithm().is_phishing(url=url, legitimate_sites=self.get_known_website_list())

    def get_known_website_list(self) -> list[Webpage]:
        Webpages = WebpageCRUD().get_trusted_webpages_list()
        return Webpages
