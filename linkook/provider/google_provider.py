# google_provider.py

import logging
from typing import Dict, Any, Optional, List, Union
import asyncio
import aiohttp
from ghunt.apis.peoplepa import PeoplePaHunter
from ghunt.objects.base import GHuntCreds
from ghunt import globals as ghunt_globals
from linkook.scanner.proxy_manager import ProxyManager


class GoogleProvider:
    """
    Provider for Google services using GHunt library.
    Handles email lookups and Google account information gathering.
    """

    def __init__(self, proxies: Optional[Union[str, List[str]]] = None):
        """
        Initialize the Google provider.
        
        :param proxies: Optional proxy or list of proxies to use
        """
        self.is_authenticated = False
        self.hunter = None
        self.creds = None
        self.proxy_manager = ProxyManager(proxies) if proxies else None
        self._session = None

    async def _create_proxied_session(self) -> aiohttp.ClientSession:
        """
        Create an aiohttp session with proxy support.
        
        :return: Configured aiohttp session
        """
        if not self._session:
            # Get next proxy if available
            proxy_config = self.proxy_manager.get_next() if self.proxy_manager else None
            proxy_url = None
            
            if proxy_config:
                # Use HTTPS proxy if available, fallback to HTTP
                proxy_url = proxy_config.get('https') or proxy_config.get('http')
            
            # Create session with proxy if configured
            self._session = aiohttp.ClientSession(
                trust_env=True,  # Allow environment proxy settings
                proxy=proxy_url
            )
            
            if proxy_url:
                logging.info(f"Created Google session with proxy: {proxy_url}")
            
        return self._session

    async def authenticate(self, cookies_dict: Dict[str, str]):
        """
        Authenticate with Google using provided cookies.
        
        :param cookies_dict: Dictionary of Google cookies
        """
        try:
            # Create proxied session first
            session = await self._create_proxied_session()
            
            # Initialize GHunt with our session
            self.creds = GHuntCreds(cookies_dict)
            ghunt_globals.set_creds(self.creds)
            ghunt_globals.set_client_session(session)
            
            # Initialize hunter with our session
            self.hunter = PeoplePaHunter()
            self.is_authenticated = True
            logging.info("Successfully authenticated with Google")
            
        except Exception as e:
            logging.error(f"Failed to authenticate with Google: {e}")
            self.is_authenticated = False

    async def get_account_info(self, email: str, retry_count: int = 3) -> Optional[Dict[str, Any]]:
        """
        Get Google account information for an email address.
        
        :param email: Email address to look up
        :param retry_count: Number of retries with different proxies
        :return: Dictionary containing account information or None if not found
        """
        if not self.is_authenticated:
            logging.error("Not authenticated with Google")
            return None

        for attempt in range(retry_count):
            try:
                person = await self.hunter.email_hunt(email)
                if not person:
                    return None

                # Extract relevant information
                info = {
                    "account_found": True,
                    "full_name": person.name if person.name else None,
                    "profile_pic": person.profile_pic if person.profile_pic else None,
                    "cover_pic": person.cover_pic if person.cover_pic else None,
                    "gaia_id": person.gaia_id if person.gaia_id else None,
                    "last_edit": person.last_edit.isoformat() if person.last_edit else None,
                    "locations": [],
                    "jobs": [],
                    "educations": [],
                    "linked_accounts": {}
                }

                # Extract locations
                if person.locations:
                    info["locations"] = [
                        {
                            "name": loc.name,
                            "type": loc.type,
                            "coordinates": loc.coordinates
                        } for loc in person.locations
                    ]

                # Extract jobs
                if person.jobs:
                    info["jobs"] = [
                        {
                            "company": job.company,
                            "title": job.title,
                            "period": job.period
                        } for job in person.jobs
                    ]

                # Extract education
                if person.educations:
                    info["educations"] = [
                        {
                            "school": edu.school,
                            "period": edu.period
                        } for edu in person.educations
                    ]

                # Extract linked accounts
                if person.links:
                    for platform, link in person.links.items():
                        if link and link.url:
                            info["linked_accounts"][platform] = link.url

                return info

            except Exception as e:
                logging.error(f"Error getting account info for {email} (attempt {attempt + 1}/{retry_count}): {e}")
                
                if self.proxy_manager and attempt < retry_count - 1:
                    # Try with a different proxy
                    await self._rotate_proxy()
                    continue
                    
                if attempt == retry_count - 1:
                    return None

    async def _rotate_proxy(self):
        """Rotate to a new proxy and recreate the session."""
        if self._session:
            await self._session.close()
            self._session = None
        
        # Next call to _create_proxied_session will use a new proxy
        await self._create_proxied_session()
        
        # Update GHunt's session
        ghunt_globals.set_client_session(self._session)

    async def get_linked_accounts(self, email: str) -> Optional[Dict[str, str]]:
        """
        Get linked social media accounts for a Google account.
        
        :param email: Email address to look up
        :return: Dictionary of platform -> profile URL mappings
        """
        info = await self.get_account_info(email)
        if info and "linked_accounts" in info:
            return info["linked_accounts"]
        return None

    async def close(self):
        """Clean up resources."""
        if self.hunter:
            await self.hunter.close()
            self.hunter = None
        
        if self._session:
            await self._session.close()
            self._session = None
            
        self.is_authenticated = False 