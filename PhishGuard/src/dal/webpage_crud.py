from ..data.webpage import Webpage
# from ..exceptions.wrong_password_or_email_exception import WrongPasswordsOrEmail
from ..exceptions.webpages_list_not_loads_exception import WebpagesListNotLoadsException


class WebpageCRUD():

    @staticmethod
    def get_trusted_webpages_list() -> list[Webpage]:
        webpages = Webpage.objects()
        if webpages:
            return webpages
        raise WebpagesListNotLoadsException()
