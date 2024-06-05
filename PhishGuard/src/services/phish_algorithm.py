class PhishAlgorithm:
    def test_url_for_phishing(self, url: str) -> dict:
        # TODO implement phishing test algorithm here
        # until algorithm implemented, if url contains 'phish' - it is phishing
        is_phishing = "phish" in url.lower()
        return {"is_phishing": is_phishing}
