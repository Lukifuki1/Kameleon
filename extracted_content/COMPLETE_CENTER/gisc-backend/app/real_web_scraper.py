"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - REAL WEB SCRAPER ENGINE
Enterprise-grade headless web scraping implementation using Selenium

This module provides:
- Headless Chrome browser automation
- Real-time web page scraping
- Social media profile extraction
- Search engine result parsing
- Anti-detection measures
- Rate limiting and retry logic

Classification: TOP SECRET // NSOC // TIER-0
"""

import time
import hashlib
import json
import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from urllib.parse import urljoin, urlparse, quote_plus
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    TimeoutException, NoSuchElementException, 
    WebDriverException, StaleElementReferenceException
)
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ScrapedPage:
    url: str
    title: str
    content: str
    html: str
    links: List[str]
    images: List[str]
    metadata: Dict[str, Any]
    scraped_at: str
    response_time_ms: int
    status: str


@dataclass
class SearchResult:
    title: str
    url: str
    snippet: str
    source: str
    position: int
    scraped_at: str


@dataclass
class SocialProfile:
    platform: str
    username: str
    display_name: Optional[str]
    profile_url: str
    bio: Optional[str]
    location: Optional[str]
    followers: Optional[int]
    following: Optional[int]
    posts: Optional[int]
    profile_image: Optional[str]
    verified: bool
    joined_date: Optional[str]
    raw_data: Dict[str, Any]
    scraped_at: str


class HeadlessBrowserManager:
    """Manages headless Chrome browser instances"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._driver_pool: List[webdriver.Chrome] = []
        self._pool_lock = threading.Lock()
        self._max_pool_size = 3
        
    def _create_driver(self) -> webdriver.Chrome:
        """Create a new headless Chrome driver with anti-detection measures"""
        options = Options()
        options.add_argument('--headless=new')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--window-size=1920,1080')
        options.add_argument('--disable-blink-features=AutomationControlled')
        options.add_argument('--disable-extensions')
        options.add_argument('--disable-plugins')
        options.add_argument('--disable-images')
        options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
        
        options.add_experimental_option('excludeSwitches', ['enable-automation'])
        options.add_experimental_option('useAutomationExtension', False)
        
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        
        driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
            'source': '''
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                });
                Object.defineProperty(navigator, 'plugins', {
                    get: () => [1, 2, 3, 4, 5]
                });
                Object.defineProperty(navigator, 'languages', {
                    get: () => ['en-US', 'en']
                });
            '''
        })
        
        driver.set_page_load_timeout(30)
        driver.implicitly_wait(10)
        
        return driver
    
    def get_driver(self) -> webdriver.Chrome:
        """Get a driver from the pool or create a new one"""
        with self._pool_lock:
            if self._driver_pool:
                return self._driver_pool.pop()
            return self._create_driver()
    
    def return_driver(self, driver: webdriver.Chrome):
        """Return a driver to the pool"""
        with self._pool_lock:
            if len(self._driver_pool) < self._max_pool_size:
                try:
                    driver.delete_all_cookies()
                    self._driver_pool.append(driver)
                except WebDriverException as e:
                    logger.debug(f"Error returning driver to pool: {e}")
                    try:
                        driver.quit()
                    except WebDriverException as quit_error:
                        logger.debug(f"Error quitting driver: {quit_error}")
            else:
                try:
                    driver.quit()
                except WebDriverException as e:
                    logger.debug(f"Error quitting driver: {e}")
    
    def cleanup(self):
        """Clean up all drivers"""
        with self._pool_lock:
            for driver in self._driver_pool:
                try:
                    driver.quit()
                except WebDriverException as e:
                    logger.debug(f"Error quitting driver during cleanup: {e}")
            self._driver_pool.clear()


class RealWebScraper:
    """Enterprise-grade web scraper using headless Chrome with requests fallback"""
    
    def __init__(self):
        self.browser_manager = HeadlessBrowserManager()
        self.rate_limit_delay = 2.0
        self.last_request_time = 0
        self._lock = threading.Lock()
        self._selenium_available = self._check_selenium_availability()
        self._session = requests.Session()
        self._session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
    
    def _check_selenium_availability(self) -> bool:
        """Check if Selenium/Chrome is available"""
        try:
            driver = self.browser_manager._create_driver()
            driver.quit()
            return True
        except Exception as e:
            logger.warning(f"Selenium not available, using requests fallback: {e}")
            return False
        
    def _rate_limit(self):
        """Implement rate limiting"""
        with self._lock:
            elapsed = time.time() - self.last_request_time
            if elapsed < self.rate_limit_delay:
                time.sleep(self.rate_limit_delay - elapsed)
            self.last_request_time = time.time()
    
    def _scrape_page_requests(self, url: str) -> ScrapedPage:
        """Fallback scrape using requests library"""
        start_time = time.time()
        try:
            response = self._session.get(url, timeout=30, allow_redirects=True)
            response.raise_for_status()
            
            html = response.text
            soup = BeautifulSoup(html, 'lxml')
            
            title = soup.title.string if soup.title else ''
            
            for script in soup(['script', 'style', 'nav', 'footer', 'header']):
                script.decompose()
            content = soup.get_text(separator=' ', strip=True)
            
            links = []
            for a in soup.find_all('a', href=True):
                href = a['href']
                if href.startswith('http'):
                    links.append(href)
                elif href.startswith('/'):
                    links.append(urljoin(url, href))
            
            images = []
            for img in soup.find_all('img', src=True):
                src = img['src']
                if src.startswith('http'):
                    images.append(src)
                elif src.startswith('/'):
                    images.append(urljoin(url, src))
            
            metadata = {}
            for meta in soup.find_all('meta'):
                name = meta.get('name') or meta.get('property', '')
                content_val = meta.get('content', '')
                if name and content_val:
                    metadata[name] = content_val
            
            response_time = int((time.time() - start_time) * 1000)
            
            return ScrapedPage(
                url=url,
                title=title or '',
                content=content[:50000],
                html=html[:100000],
                links=links[:500],
                images=images[:100],
                metadata=metadata,
                scraped_at=datetime.utcnow().isoformat(),
                response_time_ms=response_time,
                status='success'
            )
        except Exception as e:
            logger.error(f"Error scraping {url} with requests: {str(e)}")
            return ScrapedPage(
                url=url,
                title='',
                content='',
                html='',
                links=[],
                images=[],
                metadata={'error': str(e)},
                scraped_at=datetime.utcnow().isoformat(),
                response_time_ms=int((time.time() - start_time) * 1000),
                status='error'
            )
    
    def scrape_page(self, url: str, wait_for_selector: str = None) -> ScrapedPage:
        """Scrape a single page with full content extraction"""
        self._rate_limit()
        
        if not self._selenium_available:
            return self._scrape_page_requests(url)
        
        start_time = time.time()
        driver = None
        
        try:
            driver = self.browser_manager.get_driver()
            driver.get(url)
            
            if wait_for_selector:
                try:
                    WebDriverWait(driver, 10).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, wait_for_selector))
                    )
                except TimeoutException:
                    logger.debug(f"Timeout waiting for selector '{wait_for_selector}' on {url}")
            
            time.sleep(1)
            
            html = driver.page_source
            soup = BeautifulSoup(html, 'lxml')
            
            title = driver.title or ''
            
            for script in soup(['script', 'style', 'nav', 'footer', 'header']):
                script.decompose()
            content = soup.get_text(separator=' ', strip=True)
            
            links = []
            for a in soup.find_all('a', href=True):
                href = a['href']
                if href.startswith('http'):
                    links.append(href)
                elif href.startswith('/'):
                    links.append(urljoin(url, href))
            
            images = []
            for img in soup.find_all('img', src=True):
                src = img['src']
                if src.startswith('http'):
                    images.append(src)
                elif src.startswith('/'):
                    images.append(urljoin(url, src))
            
            metadata = {}
            for meta in soup.find_all('meta'):
                name = meta.get('name') or meta.get('property', '')
                content_val = meta.get('content', '')
                if name and content_val:
                    metadata[name] = content_val
            
            response_time = int((time.time() - start_time) * 1000)
            
            return ScrapedPage(
                url=url,
                title=title,
                content=content[:50000],
                html=html[:100000],
                links=links[:500],
                images=images[:100],
                metadata=metadata,
                scraped_at=datetime.utcnow().isoformat(),
                response_time_ms=response_time,
                status='success'
            )
            
        except Exception as e:
            logger.error(f"Error scraping {url}: {str(e)}")
            return ScrapedPage(
                url=url,
                title='',
                content='',
                html='',
                links=[],
                images=[],
                metadata={'error': str(e)},
                scraped_at=datetime.utcnow().isoformat(),
                response_time_ms=int((time.time() - start_time) * 1000),
                status='error'
            )
        finally:
            if driver:
                self.browser_manager.return_driver(driver)
    
    def _search_duckduckgo_api(self, query: str, num_results: int = 10) -> List[SearchResult]:
        """Search DuckDuckGo using their instant answer API (no Selenium needed)"""
        results = []
        try:
            api_url = f"https://api.duckduckgo.com/?q={quote_plus(query)}&format=json&no_html=1"
            response = self._session.get(api_url, timeout=10)
            data = response.json()
            
            if data.get('AbstractText'):
                results.append(SearchResult(
                    title=data.get('Heading', query),
                    url=data.get('AbstractURL', ''),
                    snippet=data.get('AbstractText', ''),
                    source='duckduckgo_api',
                    position=1,
                    scraped_at=datetime.utcnow().isoformat()
                ))
            
            for i, topic in enumerate(data.get('RelatedTopics', [])[:num_results]):
                if isinstance(topic, dict) and 'FirstURL' in topic:
                    results.append(SearchResult(
                        title=topic.get('Text', '')[:100],
                        url=topic.get('FirstURL', ''),
                        snippet=topic.get('Text', ''),
                        source='duckduckgo_api',
                        position=len(results) + 1,
                        scraped_at=datetime.utcnow().isoformat()
                    ))
        except Exception as e:
            logger.error(f"Error searching DuckDuckGo API: {e}")
        return results
    
    def search_google(self, query: str, num_results: int = 10) -> List[SearchResult]:
        """Search Google and extract results"""
        self._rate_limit()
        
        if not self._selenium_available:
            return self._search_duckduckgo_api(query, num_results)
        
        results = []
        driver = None
        
        try:
            driver = self.browser_manager.get_driver()
            search_url = f"https://www.google.com/search?q={quote_plus(query)}&num={num_results}"
            driver.get(search_url)
            
            time.sleep(2)
            
            soup = BeautifulSoup(driver.page_source, 'lxml')
            
            search_divs = soup.find_all('div', class_='g')
            
            for i, div in enumerate(search_divs[:num_results]):
                try:
                    title_elem = div.find('h3')
                    link_elem = div.find('a')
                    snippet_elem = div.find('div', class_=['VwiC3b', 'yXK7lf'])
                    
                    if title_elem and link_elem:
                        title = title_elem.get_text(strip=True)
                        url = link_elem.get('href', '')
                        snippet = snippet_elem.get_text(strip=True) if snippet_elem else ''
                        
                        if url.startswith('http'):
                            results.append(SearchResult(
                                title=title,
                                url=url,
                                snippet=snippet,
                                source='google',
                                position=i + 1,
                                scraped_at=datetime.utcnow().isoformat()
                            ))
                except Exception as e:
                    logger.warning(f"Error parsing search result: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error searching Google: {str(e)}")
        finally:
            if driver:
                self.browser_manager.return_driver(driver)
        
        return results
    
    def search_duckduckgo(self, query: str, num_results: int = 10) -> List[SearchResult]:
        """Search DuckDuckGo and extract results"""
        self._rate_limit()
        
        if not self._selenium_available:
            return self._search_duckduckgo_api(query, num_results)
        
        results = []
        driver = None
        
        try:
            driver = self.browser_manager.get_driver()
            search_url = f"https://duckduckgo.com/?q={quote_plus(query)}"
            driver.get(search_url)
            
            time.sleep(3)
            
            soup = BeautifulSoup(driver.page_source, 'lxml')
            
            result_divs = soup.find_all('article', {'data-testid': 'result'})
            
            for i, div in enumerate(result_divs[:num_results]):
                try:
                    title_elem = div.find('h2')
                    link_elem = div.find('a', {'data-testid': 'result-title-a'})
                    snippet_elem = div.find('div', {'data-result': 'snippet'})
                    
                    if title_elem and link_elem:
                        title = title_elem.get_text(strip=True)
                        url = link_elem.get('href', '')
                        snippet = snippet_elem.get_text(strip=True) if snippet_elem else ''
                        
                        if url.startswith('http'):
                            results.append(SearchResult(
                                title=title,
                                url=url,
                                snippet=snippet,
                                source='duckduckgo',
                                position=i + 1,
                                scraped_at=datetime.utcnow().isoformat()
                            ))
                except Exception as e:
                    logger.warning(f"Error parsing DuckDuckGo result: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error searching DuckDuckGo: {str(e)}")
        finally:
            if driver:
                self.browser_manager.return_driver(driver)
        
        return results
    
    def search_bing(self, query: str, num_results: int = 10) -> List[SearchResult]:
        """Search Bing and extract results"""
        self._rate_limit()
        
        if not self._selenium_available:
            return self._search_duckduckgo_api(query, num_results)
        
        results = []
        driver = None
        
        try:
            driver = self.browser_manager.get_driver()
            search_url = f"https://www.bing.com/search?q={quote_plus(query)}&count={num_results}"
            driver.get(search_url)
            
            time.sleep(2)
            
            soup = BeautifulSoup(driver.page_source, 'lxml')
            
            result_items = soup.find_all('li', class_='b_algo')
            
            for i, item in enumerate(result_items[:num_results]):
                try:
                    title_elem = item.find('h2')
                    link_elem = item.find('a')
                    snippet_elem = item.find('p')
                    
                    if title_elem and link_elem:
                        title = title_elem.get_text(strip=True)
                        url = link_elem.get('href', '')
                        snippet = snippet_elem.get_text(strip=True) if snippet_elem else ''
                        
                        if url.startswith('http'):
                            results.append(SearchResult(
                                title=title,
                                url=url,
                                snippet=snippet,
                                source='bing',
                                position=i + 1,
                                scraped_at=datetime.utcnow().isoformat()
                            ))
                except Exception as e:
                    logger.warning(f"Error parsing Bing result: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error searching Bing: {str(e)}")
        finally:
            if driver:
                self.browser_manager.return_driver(driver)
        
        return results
    
    def multi_engine_search(self, query: str, num_results: int = 10) -> Dict[str, List[SearchResult]]:
        """Search across multiple search engines"""
        results = {
            'google': [],
            'duckduckgo': [],
            'bing': []
        }
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(self.search_google, query, num_results): 'google',
                executor.submit(self.search_duckduckgo, query, num_results): 'duckduckgo',
                executor.submit(self.search_bing, query, num_results): 'bing'
            }
            
            for future in as_completed(futures):
                engine = futures[future]
                try:
                    results[engine] = future.result()
                except Exception as e:
                    logger.error(f"Error in {engine} search: {e}")
        
        return results
    
    def _scrape_github_api(self, username: str) -> Optional[SocialProfile]:
        """Scrape GitHub profile using public API (no Selenium needed)"""
        try:
            api_url = f"https://api.github.com/users/{username}"
            response = self._session.get(api_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return SocialProfile(
                    platform='GITHUB',
                    username=username,
                    display_name=data.get('name') or username,
                    profile_url=data.get('html_url', f"https://github.com/{username}"),
                    bio=data.get('bio'),
                    location=data.get('location'),
                    followers=data.get('followers', 0),
                    following=data.get('following', 0),
                    posts=data.get('public_repos', 0),
                    profile_image=data.get('avatar_url'),
                    verified=False,
                    joined_date=data.get('created_at'),
                    raw_data={'source': 'github_api', 'company': data.get('company'), 'blog': data.get('blog')},
                    scraped_at=datetime.utcnow().isoformat()
                )
        except Exception as e:
            logger.error(f"Error fetching GitHub API for {username}: {e}")
        return None
    
    def scrape_github_profile(self, username: str) -> Optional[SocialProfile]:
        """Scrape GitHub profile"""
        self._rate_limit()
        
        if not self._selenium_available:
            return self._scrape_github_api(username)
        
        driver = None
        
        try:
            driver = self.browser_manager.get_driver()
            url = f"https://github.com/{username}"
            driver.get(url)
            
            time.sleep(2)
            
            soup = BeautifulSoup(driver.page_source, 'lxml')
            
            name_elem = soup.find('span', class_='p-name')
            bio_elem = soup.find('div', class_='p-note')
            location_elem = soup.find('span', class_='p-label')
            avatar_elem = soup.find('img', class_='avatar-user')
            
            followers_elem = soup.find('a', href=f'/{username}?tab=followers')
            following_elem = soup.find('a', href=f'/{username}?tab=following')
            repos_elem = soup.find('span', class_='Counter')
            
            followers = 0
            following = 0
            repos = 0
            
            if followers_elem:
                followers_text = followers_elem.find('span', class_='text-bold')
                if followers_text:
                    followers = self._parse_count(followers_text.get_text(strip=True))
            
            if following_elem:
                following_text = following_elem.find('span', class_='text-bold')
                if following_text:
                    following = self._parse_count(following_text.get_text(strip=True))
            
            return SocialProfile(
                platform='GITHUB',
                username=username,
                display_name=name_elem.get_text(strip=True) if name_elem else username,
                profile_url=url,
                bio=bio_elem.get_text(strip=True) if bio_elem else None,
                location=location_elem.get_text(strip=True) if location_elem else None,
                followers=followers,
                following=following,
                posts=repos,
                profile_image=avatar_elem.get('src') if avatar_elem else None,
                verified=False,
                joined_date=None,
                raw_data={'source': 'github_scrape'},
                scraped_at=datetime.utcnow().isoformat()
            )
            
        except Exception as e:
            logger.error(f"Error scraping GitHub profile {username}: {str(e)}")
            return None
        finally:
            if driver:
                self.browser_manager.return_driver(driver)
    
    def scrape_twitter_profile(self, username: str) -> Optional[SocialProfile]:
        """Scrape Twitter/X profile (public data only)"""
        self._rate_limit()
        
        if not self._selenium_available:
            return SocialProfile(
                platform='TWITTER',
                username=username,
                display_name=username,
                profile_url=f"https://twitter.com/{username}",
                bio=None,
                location=None,
                followers=None,
                following=None,
                posts=None,
                profile_image=None,
                verified=False,
                joined_date=None,
                raw_data={'source': 'twitter_fallback', 'note': 'Twitter requires authentication for API access'},
                scraped_at=datetime.utcnow().isoformat()
            )
        
        driver = None
        
        try:
            driver = self.browser_manager.get_driver()
            url = f"https://twitter.com/{username}"
            driver.get(url)
            
            time.sleep(3)
            
            soup = BeautifulSoup(driver.page_source, 'lxml')
            
            name_elem = soup.find('div', {'data-testid': 'UserName'})
            bio_elem = soup.find('div', {'data-testid': 'UserDescription'})
            location_elem = soup.find('span', {'data-testid': 'UserLocation'})
            avatar_elem = soup.find('img', {'alt': lambda x: x and 'profile' in x.lower()})
            
            verified = bool(soup.find('svg', {'aria-label': 'Verified account'}))
            
            return SocialProfile(
                platform='TWITTER',
                username=username,
                display_name=name_elem.get_text(strip=True) if name_elem else username,
                profile_url=url,
                bio=bio_elem.get_text(strip=True) if bio_elem else None,
                location=location_elem.get_text(strip=True) if location_elem else None,
                followers=None,
                following=None,
                posts=None,
                profile_image=avatar_elem.get('src') if avatar_elem else None,
                verified=verified,
                joined_date=None,
                raw_data={'source': 'twitter_scrape'},
                scraped_at=datetime.utcnow().isoformat()
            )
            
        except Exception as e:
            logger.error(f"Error scraping Twitter profile {username}: {str(e)}")
            return None
        finally:
            if driver:
                self.browser_manager.return_driver(driver)
    
    def scrape_linkedin_public(self, profile_url: str) -> Optional[SocialProfile]:
        """Scrape LinkedIn public profile (limited data)"""
        self._rate_limit()
        
        if not self._selenium_available:
            username = profile_url.split('/in/')[-1].rstrip('/') if '/in/' in profile_url else ''
            return SocialProfile(
                platform='LINKEDIN',
                username=username,
                display_name=username,
                profile_url=profile_url,
                bio=None,
                location=None,
                followers=None,
                following=None,
                posts=None,
                profile_image=None,
                verified=False,
                joined_date=None,
                raw_data={'source': 'linkedin_fallback', 'note': 'LinkedIn requires authentication for scraping'},
                scraped_at=datetime.utcnow().isoformat()
            )
        
        driver = None
        
        try:
            driver = self.browser_manager.get_driver()
            driver.get(profile_url)
            
            time.sleep(3)
            
            soup = BeautifulSoup(driver.page_source, 'lxml')
            
            name_elem = soup.find('h1', class_='top-card-layout__title')
            headline_elem = soup.find('h2', class_='top-card-layout__headline')
            location_elem = soup.find('span', class_='top-card__subline-item')
            avatar_elem = soup.find('img', class_='top-card__profile-image')
            
            username = profile_url.split('/in/')[-1].rstrip('/') if '/in/' in profile_url else ''
            
            return SocialProfile(
                platform='LINKEDIN',
                username=username,
                display_name=name_elem.get_text(strip=True) if name_elem else None,
                profile_url=profile_url,
                bio=headline_elem.get_text(strip=True) if headline_elem else None,
                location=location_elem.get_text(strip=True) if location_elem else None,
                followers=None,
                following=None,
                posts=None,
                profile_image=avatar_elem.get('src') if avatar_elem else None,
                verified=False,
                joined_date=None,
                raw_data={'source': 'linkedin_public_scrape'},
                scraped_at=datetime.utcnow().isoformat()
            )
            
        except Exception as e:
            logger.error(f"Error scraping LinkedIn profile: {str(e)}")
            return None
        finally:
            if driver:
                self.browser_manager.return_driver(driver)
    
    def _parse_count(self, text: str) -> int:
        """Parse follower/following counts like '1.2k', '5M'"""
        text = text.strip().upper()
        multipliers = {'K': 1000, 'M': 1000000, 'B': 1000000000}
        
        for suffix, multiplier in multipliers.items():
            if suffix in text:
                try:
                    return int(float(text.replace(suffix, '')) * multiplier)
                except:
                    return 0
        
        try:
            return int(text.replace(',', ''))
        except:
            return 0
    
    def cleanup(self):
        """Clean up browser resources"""
        self.browser_manager.cleanup()


class PersonSearchScraper:
    """Specialized scraper for person search websites"""
    
    def __init__(self):
        self.scraper = RealWebScraper()
    
    def search_person_websites(self, name: str) -> Dict[str, List[Dict[str, Any]]]:
        """Search multiple people search websites"""
        results = {}
        
        search_sites = [
            ('pipl', f"https://pipl.com/search/?q={quote_plus(name)}"),
            ('spokeo', f"https://www.spokeo.com/search?q={quote_plus(name)}"),
            ('whitepages', f"https://www.whitepages.com/name/{quote_plus(name)}"),
            ('truepeoplesearch', f"https://www.truepeoplesearch.com/results?name={quote_plus(name)}"),
            ('fastpeoplesearch', f"https://www.fastpeoplesearch.com/name/{quote_plus(name.replace(' ', '-'))}"),
        ]
        
        for site_name, url in search_sites:
            try:
                page = self.scraper.scrape_page(url)
                if page.status == 'success':
                    results[site_name] = {
                        'url': url,
                        'title': page.title,
                        'content_preview': page.content[:1000],
                        'links_found': len(page.links),
                        'scraped_at': page.scraped_at
                    }
            except Exception as e:
                logger.error(f"Error searching {site_name}: {e}")
                results[site_name] = {'error': str(e)}
        
        return results
    
    def search_social_media_profiles(self, username: str) -> Dict[str, Optional[SocialProfile]]:
        """Search for username across social media platforms"""
        results = {}
        
        results['github'] = self.scraper.scrape_github_profile(username)
        results['twitter'] = self.scraper.scrape_twitter_profile(username)
        
        return results
    
    def comprehensive_person_search(self, query: str) -> Dict[str, Any]:
        """Perform comprehensive person search across all sources"""
        results = {
            'query': query,
            'timestamp': datetime.utcnow().isoformat(),
            'search_engines': {},
            'people_search_sites': {},
            'social_profiles': {},
            'total_results': 0
        }
        
        results['search_engines'] = self.scraper.multi_engine_search(f'"{query}"', num_results=20)
        
        results['people_search_sites'] = self.search_person_websites(query)
        
        username_match = re.search(r'@?(\w+)', query)
        if username_match:
            username = username_match.group(1)
            results['social_profiles'] = self.search_social_media_profiles(username)
        
        total = 0
        for engine_results in results['search_engines'].values():
            total += len(engine_results)
        total += len(results['people_search_sites'])
        total += len([p for p in results['social_profiles'].values() if p])
        results['total_results'] = total
        
        return results
    
    def cleanup(self):
        """Clean up resources"""
        self.scraper.cleanup()


def create_web_scraper() -> RealWebScraper:
    """Factory function to create web scraper instance"""
    return RealWebScraper()


def create_person_search_scraper() -> PersonSearchScraper:
    """Factory function to create person search scraper instance"""
    return PersonSearchScraper()
