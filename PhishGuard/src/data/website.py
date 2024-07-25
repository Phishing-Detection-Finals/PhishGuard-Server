class Webpage:
    def __init__(self, url, title_hash, header_hash, footer_hash, cert_hash):
        self.url = url
        self.titleComponentHash = title_hash
        self.headerComponentHash = header_hash
        self.footerComponentHash = footer_hash
        self.certificateHash = cert_hash
