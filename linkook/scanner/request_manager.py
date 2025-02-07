# request_manager.py

import time
import random
import logging
from typing import Dict, Optional, List, Any, Union
from requests import Session
from requests.exceptions import RequestException
from linkook.scanner.rate_limiter import RateLimiter
from linkook.scanner.proxy_manager import ProxyManager


class RequestManager:
    """
    Manages HTTP requests with anti-detection measures including:
    - User agent rotation
    - Request delays
    - Rate limiting
    - Proxy rotation
    - Header randomization
    """

    # Common user agents for popular browsers
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    ]

    # Common request headers
    COMMON_HEADERS = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
    }

    def __init__(
        self,
        min_delay: float = 1.0,
        max_delay: float = 3.0,
        proxies: Optional[Union[str, List[str]]] = None,
        timeout: int = 10,
        default_rate: int = 30,
        default_burst: int = 10,
    ):
        """
        Initialize the RequestManager.

        :param min_delay: Minimum delay between requests in seconds
        :param max_delay: Maximum delay between requests in seconds
        :param proxies: Proxy string, list of proxies, or path to proxy file
        :param timeout: Request timeout in seconds
        :param default_rate: Default requests per minute for unknown providers
        :param default_burst: Default burst size for unknown providers
        """
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.timeout = timeout
        self.session = Session()
        self.last_request_time = 0
        
        # Initialize proxy manager
        self.proxy_manager = ProxyManager(proxies)
        
        # Initialize rate limiter
        self.rate_limiter = RateLimiter(
            default_rate=default_rate,
            default_burst=default_burst
        )

    def _get_random_user_agent(self) -> str:
        """Get a random user agent from the list."""
        return random.choice(self.USER_AGENTS)

    def _randomize_headers(self, base_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Create a set of randomized headers.
        
        :param base_headers: Base headers to extend
        :return: Dictionary of headers
        """
        headers = self.COMMON_HEADERS.copy()
        headers["User-Agent"] = self._get_random_user_agent()
        
        if base_headers:
            headers.update(base_headers)
            
        return headers

    def _enforce_rate_limit(self, url: str):
        """
        Enforce both global and per-provider rate limiting.
        
        :param url: Target URL to check rate limits for
        """
        # Get next proxy before rate limiting
        proxy = self.proxy_manager.get_next()
        
        # First check provider-specific rate limit with proxy info
        wait_time = self.rate_limiter.wait_if_needed(url, proxy)
        if wait_time > 0:
            time.sleep(wait_time)
        
        # Then enforce global delay between requests
        if self.last_request_time:
            elapsed = time.time() - self.last_request_time
            delay = random.uniform(self.min_delay, self.max_delay)
            if elapsed < delay:
                time.sleep(delay - elapsed)
        
        self.last_request_time = time.time()
        return proxy

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> Optional[Any]:
        """
        Make an HTTP request with anti-detection measures.

        :param method: HTTP method (GET, POST, etc.)
        :param url: Target URL
        :param headers: Additional headers to include
        :param kwargs: Additional arguments to pass to requests
        :return: Response object or None if request fails
        """
        # Enforce rate limits and get proxy
        proxy = self._enforce_rate_limit(url)
        
        # Prepare request
        final_headers = self._randomize_headers(headers)
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=final_headers,
                proxies=proxy,
                timeout=self.timeout,
                **kwargs
            )
            response.raise_for_status()
            return response
            
        except RequestException as e:
            logging.error(f"Request failed for {url} using proxy {proxy}: {str(e)}")
            return None

    def close(self):
        """Close the session."""
        self.session.close() 