# rate_limiter.py

import time
import logging
from typing import Dict, Optional, Tuple
from collections import defaultdict
from urllib.parse import urlparse


class RateLimiter:
    """
    Rate limiter that implements token bucket algorithm for per-provider and per-proxy rate limiting.
    Each proxy gets its own token bucket for each provider, allowing for higher throughput with multiple proxies.
    """

    def __init__(self, default_rate: int = 30, default_burst: int = 10):
        """
        Initialize rate limiter.

        :param default_rate: Default requests per minute for unknown providers
        :param default_burst: Default burst size for unknown providers
        """
        self.default_rate = default_rate
        self.default_burst = default_burst
        
        # Provider-specific rate limits (requests per minute)
        self.provider_limits = {
            "linkedin.com": {"rate": 12, "burst": 3},  # Very strict
            "github.com": {"rate": 30, "burst": 10},   # 5000/hour authenticated
            "twitter.com": {"rate": 15, "burst": 3},   # Strict
            "instagram.com": {"rate": 20, "burst": 5}, # Moderate
            "facebook.com": {"rate": 15, "burst": 3},  # Strict
            "hackerone.com": {"rate": 20, "burst": 5}, # Moderate
            "bugcrowd.com": {"rate": 20, "burst": 5},  # Moderate
        }
        
        # Token buckets for each provider and proxy combination
        # Structure: {(domain, proxy_id): {"tokens": float, "last_update": float}}
        self.buckets: Dict[Tuple[str, str], Dict] = defaultdict(
            lambda: {"tokens": self.default_burst, "last_update": time.time()}
        )

    def _get_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            domain = urlparse(url).netloc
            # Remove www. prefix if present
            return domain.replace("www.", "")
        except Exception as e:
            logging.warning(f"Failed to parse URL {url}: {e}")
            return url

    def _get_proxy_id(self, proxy: Optional[Dict[str, str]]) -> str:
        """
        Get a unique identifier for a proxy configuration.
        
        :param proxy: Proxy configuration dict or None
        :return: Proxy identifier string
        """
        if not proxy:
            return "direct"
        
        # Use HTTP proxy if available, else HTTPS proxy
        proxy_url = proxy.get("http") or proxy.get("https")
        if not proxy_url:
            return "direct"
            
        return proxy_url

    def _get_provider_limits(self, domain: str) -> Dict[str, int]:
        """Get rate limits for a provider."""
        for provider_domain, limits in self.provider_limits.items():
            if provider_domain in domain:
                return limits
        return {"rate": self.default_rate, "burst": self.default_burst}

    def _get_bucket_key(self, url: str, proxy: Optional[Dict[str, str]]) -> Tuple[str, str]:
        """
        Get the bucket key for a given URL and proxy combination.
        
        :param url: Target URL
        :param proxy: Proxy configuration
        :return: Tuple of (domain, proxy_id)
        """
        domain = self._get_domain(url)
        proxy_id = self._get_proxy_id(proxy)
        return (domain, proxy_id)

    def _refill_tokens(self, bucket_key: Tuple[str, str]):
        """
        Refill tokens based on time elapsed.
        
        :param bucket_key: Tuple of (domain, proxy_id)
        """
        bucket = self.buckets[bucket_key]
        now = time.time()
        limits = self._get_provider_limits(bucket_key[0])
        
        time_passed = now - bucket["last_update"]
        tokens_to_add = (time_passed * limits["rate"]) / 60.0  # Convert rate to tokens per second
        
        bucket["tokens"] = min(
            limits["burst"],
            bucket["tokens"] + tokens_to_add
        )
        bucket["last_update"] = now

    def wait_if_needed(self, url: str, proxy: Optional[Dict[str, str]] = None) -> float:
        """
        Check if request can be made and return wait time if needed.
        
        :param url: Target URL
        :param proxy: Optional proxy configuration
        :return: Time to wait in seconds
        """
        bucket_key = self._get_bucket_key(url, proxy)
        bucket = self.buckets[bucket_key]
        limits = self._get_provider_limits(bucket_key[0])
        
        self._refill_tokens(bucket_key)
        
        if bucket["tokens"] >= 1:
            bucket["tokens"] -= 1
            return 0
        
        # Calculate time needed for one token
        time_for_token = (1 - bucket["tokens"]) * (60.0 / limits["rate"])
        logging.warning(
            f"Rate limit reached for {bucket_key[0]} using proxy {bucket_key[1]}. "
            f"Need to wait {time_for_token:.2f} seconds"
        )
        return time_for_token 