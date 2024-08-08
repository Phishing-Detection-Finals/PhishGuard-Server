from ..data.webpage import Webpage
from ..exceptions.webpages_list_not_loads_exception import WebpagesListNotLoadsException
import logging


class WebpageCRUD:

    @staticmethod
    def get_trusted_webpages_list() -> list[Webpage]:
        logging.debug("Attempting to retrieve the list of trusted webpages.")
        webpages = Webpage.objects()
        if webpages:
            logging.info(f"Retrieved {len(webpages)} trusted webpages.")
            return webpages
        logging.warning("No trusted webpages found.")
        raise WebpagesListNotLoadsException()
