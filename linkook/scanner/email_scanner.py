import asyncio
import logging
from typing import Dict, Any, List, Optional
import trio
from holehe.core import get_functions, import_submodules
from holehe.localuseragent import ua

class EmailScanner:
    """
    A class to handle email-based account discovery using Holehe.
    """
    def __init__(self, proxy: Optional[str] = None):
        """
        Initialize the EmailScanner with optional proxy support.
        
        Args:
            proxy (str, optional): Proxy URL to use for requests
        """
        self.proxy = proxy
        self.modules = import_submodules("holehe.modules")
        self.websites = get_functions()
        self.results = {}
        
    async def scan_email(self, email: str) -> Dict[str, Any]:
        """
        Scan an email address across multiple services using Holehe.
        
        Args:
            email (str): The email address to scan
            
        Returns:
            Dict[str, Any]: Dictionary containing results for each service
        """
        results = {}
        
        async def _check_service(func, email: str):
            try:
                out = []
                await func(email, out, self.proxy)
                if out and out[0]['exists']:
                    results[out[0]['name']] = {
                        'exists': True,
                        'rateLimit': out[0].get('rateLimit', False),
                        'emailrecovery': out[0].get('emailrecovery', None),
                        'phoneNumber': out[0].get('phoneNumber', None),
                        'others': out[0].get('others', None)
                    }
            except Exception as e:
                logging.error(f"Error checking {func.__name__}: {str(e)}")
        
        # Create tasks for all services
        async with trio.open_nursery() as nursery:
            for website in self.websites:
                nursery.start_soon(_check_service, website, email)
        
        return results
    
    def scan_email_sync(self, email: str) -> Dict[str, Any]:
        """
        Synchronous wrapper for scan_email.
        
        Args:
            email (str): The email address to scan
            
        Returns:
            Dict[str, Any]: Dictionary containing results for each service
        """
        return trio.run(self.scan_email, email)
    
    def get_supported_services(self) -> List[str]:
        """
        Get a list of services supported by Holehe.
        
        Returns:
            List[str]: List of service names
        """
        return [func.__name__.replace("check_", "") for func in self.websites] 