# proxy_manager.py

import os
import random
import logging
from typing import Dict, List, Optional, Union
from urllib.parse import urlparse


class ProxyManager:
    """
    Manages proxy rotation and validation with support for multiple protocols:
    - HTTP/HTTPS
    - SOCKS4
    - SOCKS5
    """

    def __init__(self, proxies: Optional[Union[str, List[str]]] = None):
        """
        Initialize proxy manager.
        
        :param proxies: Single proxy string or list of proxy strings
                     Format: IP:PORT, socks4://IP:PORT, socks5://IP:PORT, or file path
        """
        self.proxies: List[str] = []
        self._current_index = 0
        
        if proxies:
            if isinstance(proxies, str):
                # Check if it's a file path
                if os.path.isfile(proxies):
                    self.load_from_file(proxies)
                else:
                    self.add_proxy(proxies)
            else:
                for proxy in proxies:
                    self.add_proxy(proxy)

    def load_from_file(self, filepath: str):
        """
        Load proxies from a file.
        
        :param filepath: Path to proxy file (one proxy per line)
        """
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    proxy = line.strip()
                    if proxy and not proxy.startswith('#'):
                        self.add_proxy(proxy)
        except Exception as e:
            logging.error(f"Failed to load proxies from {filepath}: {e}")

    def add_proxy(self, proxy: str):
        """
        Add a single proxy to the list.
        
        :param proxy: Proxy string (IP:PORT or protocol://IP:PORT)
        """
        try:
            # Basic validation
            if '://' in proxy:
                parsed = urlparse(proxy)
                if parsed.scheme not in ['http', 'https', 'socks4', 'socks5']:
                    logging.warning(f"Unsupported proxy protocol in {proxy}")
                    return
            else:
                # Validate IP:PORT format
                host, port = proxy.split(':')
                port = int(port)
                if not (0 < port < 65536):
                    logging.warning(f"Invalid port in proxy {proxy}")
                    return
            
            self.proxies.append(proxy)
            logging.debug(f"Added proxy: {proxy}")
            
        except Exception as e:
            logging.warning(f"Invalid proxy format {proxy}: {e}")

    def _format_proxy_url(self, proxy: str) -> Dict[str, str]:
        """
        Format proxy string into requests-compatible dictionary.
        
        :param proxy: Proxy string
        :return: Dictionary with proxy configuration
        """
        if '://' not in proxy:
            # Default to HTTP proxy if no protocol specified
            proxy_url = f'http://{proxy}'
        else:
            proxy_url = proxy
            
        return {
            'http': proxy_url,
            'https': proxy_url
        }

    def get_next(self) -> Optional[Dict[str, str]]:
        """
        Get next proxy in rotation.
        
        :return: Proxy configuration dictionary or None if no proxies available
        """
        if not self.proxies:
            return None
            
        proxy = self.proxies[self._current_index]
        self._current_index = (self._current_index + 1) % len(self.proxies)
        
        return self._format_proxy_url(proxy)

    def get_random(self) -> Optional[Dict[str, str]]:
        """
        Get random proxy from the list.
        
        :return: Proxy configuration dictionary or None if no proxies available
        """
        if not self.proxies:
            return None
            
        proxy = random.choice(self.proxies)
        return self._format_proxy_url(proxy)

    def remove_proxy(self, proxy: str):
        """
        Remove a proxy from the list.
        
        :param proxy: Proxy string to remove
        """
        if proxy in self.proxies:
            self.proxies.remove(proxy)
            if self._current_index >= len(self.proxies):
                self._current_index = 0

    def get_proxy_count(self) -> int:
        """Get number of available proxies."""
        return len(self.proxies) 