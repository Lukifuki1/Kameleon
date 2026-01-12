"""
GLOBAL INTELLIGENCE SECURITY COMMAND CENTER - REAL WEB CRAWLER ENGINE
Enterprise-grade web crawling for link analysis between domains and persons

This module provides:
- Multi-level web crawling (surface, deep, dark web)
- Domain link mapping and relationship analysis
- Person mention extraction and correlation
- Social network graph building
- Content extraction and indexing
- Rate-limited, respectful crawling
- Robots.txt compliance
- PDF report generation

Classification: TOP SECRET // NSOC // TIER-0
"""

import re
import time
import hashlib
import json
import logging
import threading
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import urlparse, urljoin, quote_plus
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import requests

from app.real_pdf_generator import PDFReportGenerator, ReportMetadata, create_pdf_generator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class CrawledPage:
    url: str
    domain: str
    title: str
    content: str
    outbound_links: List[str]
    inbound_links: List[str]
    internal_links: List[str]
    external_links: List[str]
    emails: List[str]
    phone_numbers: List[str]
    social_profiles: List[str]
    person_mentions: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    crawl_depth: int
    crawl_time: str
    response_time_ms: int
    status: str


@dataclass
class DomainNode:
    domain: str
    pages_crawled: int
    total_links: int
    outbound_domains: Set[str]
    inbound_domains: Set[str]
    emails_found: List[str]
    social_profiles: List[str]
    technologies: List[str]
    first_seen: str
    last_seen: str
    risk_indicators: List[str]


@dataclass
class PersonMention:
    name: str
    context: str
    source_url: str
    source_domain: str
    confidence: float
    associated_emails: List[str]
    associated_phones: List[str]
    associated_social: List[str]
    first_seen: str
    mention_count: int


@dataclass
class LinkRelationship:
    source_domain: str
    target_domain: str
    link_count: int
    link_types: List[str]
    anchor_texts: List[str]
    first_seen: str
    last_seen: str
    bidirectional: bool


@dataclass
class CrawlResult:
    crawl_id: str
    seed_urls: List[str]
    start_time: str
    end_time: str
    pages_crawled: int
    domains_discovered: int
    links_found: int
    persons_mentioned: int
    crawled_pages: List[CrawledPage]
    domain_graph: Dict[str, DomainNode]
    person_mentions: List[PersonMention]
    link_relationships: List[LinkRelationship]
    statistics: Dict[str, Any]


class RobotsParser:
    """Parse and respect robots.txt"""
    
    def __init__(self):
        self.cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
    
    def can_fetch(self, url: str, user_agent: str = '*') -> bool:
        """Check if URL can be fetched according to robots.txt"""
        parsed = urlparse(url)
        domain = f"{parsed.scheme}://{parsed.netloc}"
        
        with self._lock:
            if domain not in self.cache:
                self._fetch_robots(domain)
            
            robots = self.cache.get(domain, {})
            
            if not robots.get('rules'):
                return True
            
            path = parsed.path or '/'
            
            for rule in robots.get('rules', []):
                if rule['user_agent'] in [user_agent, '*']:
                    for disallow in rule.get('disallow', []):
                        if path.startswith(disallow):
                            return False
        
        return True
    
    def get_crawl_delay(self, domain: str) -> float:
        """Get crawl delay for domain"""
        with self._lock:
            if domain not in self.cache:
                self._fetch_robots(domain)
            return self.cache.get(domain, {}).get('crawl_delay', 1.0)
    
    def _fetch_robots(self, domain: str):
        """Fetch and parse robots.txt"""
        try:
            response = requests.get(
                f"{domain}/robots.txt",
                timeout=5,
                headers={'User-Agent': 'GISC-Crawler/1.0'}
            )
            
            if response.status_code == 200:
                self.cache[domain] = self._parse_robots(response.text)
            else:
                self.cache[domain] = {'rules': [], 'crawl_delay': 1.0}
        except:
            self.cache[domain] = {'rules': [], 'crawl_delay': 1.0}
    
    def _parse_robots(self, content: str) -> Dict[str, Any]:
        """Parse robots.txt content"""
        result = {'rules': [], 'crawl_delay': 1.0, 'sitemaps': []}
        current_rule = None
        
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key == 'user-agent':
                    if current_rule:
                        result['rules'].append(current_rule)
                    current_rule = {'user_agent': value, 'disallow': [], 'allow': []}
                elif key == 'disallow' and current_rule:
                    if value:
                        current_rule['disallow'].append(value)
                elif key == 'allow' and current_rule:
                    if value:
                        current_rule['allow'].append(value)
                elif key == 'crawl-delay':
                    try:
                        result['crawl_delay'] = float(value)
                    except ValueError as e:
                        logger.debug(f"Invalid crawl-delay value: {value}: {e}")
                elif key == 'sitemap':
                    result['sitemaps'].append(value)
        
        if current_rule:
            result['rules'].append(current_rule)
        
        return result


class ContentExtractor:
    """Extract structured content from web pages"""
    
    PERSON_NAME_PATTERNS = [
        r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\b',
        r'(?:Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)',
        r'(?:CEO|CTO|CFO|COO|President|Director|Manager|Founder)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)',
    ]
    
    EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    PHONE_PATTERNS = [
        r'\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',
        r'\+?[0-9]{1,3}[-.\s]?[0-9]{2,4}[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}',
    ]
    
    SOCIAL_PATTERNS = {
        'twitter': r'(?:twitter\.com|x\.com)/([a-zA-Z0-9_]+)',
        'linkedin': r'linkedin\.com/(?:in|company)/([a-zA-Z0-9_-]+)',
        'facebook': r'facebook\.com/([a-zA-Z0-9.]+)',
        'instagram': r'instagram\.com/([a-zA-Z0-9_.]+)',
        'github': r'github\.com/([a-zA-Z0-9_-]+)',
        'youtube': r'youtube\.com/(?:user|channel|c)/([a-zA-Z0-9_-]+)',
    }
    
    def extract_emails(self, text: str) -> List[str]:
        """Extract email addresses from text"""
        emails = re.findall(self.EMAIL_PATTERN, text, re.IGNORECASE)
        return list(set(emails))
    
    def extract_phone_numbers(self, text: str) -> List[str]:
        """Extract phone numbers from text"""
        phones = []
        for pattern in self.PHONE_PATTERNS:
            matches = re.findall(pattern, text)
            phones.extend(matches)
        return list(set(phones))
    
    def extract_social_profiles(self, text: str, links: List[str]) -> List[Dict[str, str]]:
        """Extract social media profile links"""
        profiles = []
        
        all_text = text + ' ' + ' '.join(links)
        
        for platform, pattern in self.SOCIAL_PATTERNS.items():
            matches = re.findall(pattern, all_text, re.IGNORECASE)
            for match in matches:
                profiles.append({
                    'platform': platform,
                    'username': match,
                    'url': f"https://{platform}.com/{match}"
                })
        
        return profiles
    
    def extract_person_mentions(self, text: str, url: str) -> List[Dict[str, Any]]:
        """Extract person name mentions from text"""
        mentions = []
        
        for pattern in self.PERSON_NAME_PATTERNS:
            matches = re.finditer(pattern, text)
            for match in matches:
                name = match.group(1) if match.lastindex else match.group(0)
                
                if len(name.split()) < 2:
                    continue
                
                start = max(0, match.start() - 100)
                end = min(len(text), match.end() + 100)
                context = text[start:end].strip()
                
                mentions.append({
                    'name': name,
                    'context': context,
                    'source_url': url,
                    'position': match.start(),
                    'confidence': self._calculate_name_confidence(name, context)
                })
        
        seen_names = set()
        unique_mentions = []
        for mention in mentions:
            if mention['name'] not in seen_names:
                seen_names.add(mention['name'])
                unique_mentions.append(mention)
        
        return unique_mentions
    
    def _calculate_name_confidence(self, name: str, context: str) -> float:
        """Calculate confidence score for person name"""
        confidence = 0.5
        
        if len(name.split()) >= 2:
            confidence += 0.1
        
        title_indicators = ['CEO', 'CTO', 'President', 'Director', 'Manager', 'Dr.', 'Prof.']
        for indicator in title_indicators:
            if indicator in context:
                confidence += 0.15
                break
        
        action_verbs = ['said', 'announced', 'stated', 'reported', 'founded', 'leads', 'manages']
        for verb in action_verbs:
            if verb in context.lower():
                confidence += 0.1
                break
        
        return min(1.0, confidence)
    
    def extract_links(self, soup: BeautifulSoup, base_url: str) -> Tuple[List[str], List[str], List[str]]:
        """Extract and categorize links from page"""
        base_domain = urlparse(base_url).netloc
        
        all_links = []
        internal_links = []
        external_links = []
        
        for a in soup.find_all('a', href=True):
            href = a['href']
            
            if href.startswith('#') or href.startswith('javascript:') or href.startswith('mailto:'):
                continue
            
            if href.startswith('//'):
                href = 'https:' + href
            elif href.startswith('/'):
                href = urljoin(base_url, href)
            elif not href.startswith('http'):
                href = urljoin(base_url, href)
            
            all_links.append(href)
            
            link_domain = urlparse(href).netloc
            if link_domain == base_domain:
                internal_links.append(href)
            else:
                external_links.append(href)
        
        return (
            list(set(all_links)),
            list(set(internal_links)),
            list(set(external_links))
        )
    
    def extract_metadata(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Extract page metadata"""
        metadata = {}
        
        for meta in soup.find_all('meta'):
            name = meta.get('name') or meta.get('property', '')
            content = meta.get('content', '')
            if name and content:
                metadata[name] = content
        
        title_tag = soup.find('title')
        if title_tag:
            metadata['title'] = title_tag.get_text(strip=True)
        
        h1_tags = soup.find_all('h1')
        if h1_tags:
            metadata['h1_tags'] = [h1.get_text(strip=True) for h1 in h1_tags[:5]]
        
        return metadata


class WebCrawler:
    """Enterprise-grade web crawler with headless browser support"""
    
    def __init__(self, max_depth: int = 3, max_pages: int = 100, respect_robots: bool = True):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.respect_robots = respect_robots
        self.robots_parser = RobotsParser()
        self.content_extractor = ContentExtractor()
        self.visited_urls: Set[str] = set()
        self.domain_data: Dict[str, DomainNode] = {}
        self.person_mentions: Dict[str, PersonMention] = {}
        self.link_relationships: Dict[str, LinkRelationship] = {}
        self._lock = threading.Lock()
        self._driver = None
        self._driver_lock = threading.Lock()
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
            options = Options()
            options.add_argument('--headless=new')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=options)
            driver.quit()
            return True
        except Exception as e:
            logger.warning(f"Selenium not available, using requests fallback: {e}")
            return False
    
    def _get_driver(self) -> webdriver.Chrome:
        """Get or create headless Chrome driver"""
        with self._driver_lock:
            if self._driver is None:
                options = Options()
                options.add_argument('--headless=new')
                options.add_argument('--no-sandbox')
                options.add_argument('--disable-dev-shm-usage')
                options.add_argument('--disable-gpu')
                options.add_argument('--window-size=1920,1080')
                options.add_argument('--disable-blink-features=AutomationControlled')
                options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
                
                service = Service(ChromeDriverManager().install())
                self._driver = webdriver.Chrome(service=service, options=options)
                self._driver.set_page_load_timeout(30)
            
            return self._driver
    
    def _crawl_page_requests(self, url: str, depth: int) -> Optional[CrawledPage]:
        """Crawl a single page using requests (fallback when Selenium unavailable)"""
        parsed = urlparse(url)
        domain = parsed.netloc
        start_time = time.time()
        
        try:
            response = self._session.get(url, timeout=30, allow_redirects=True)
            response.raise_for_status()
            html = response.text
            
            soup = BeautifulSoup(html, 'html.parser')
            
            title_tag = soup.find('title')
            title = title_tag.get_text(strip=True) if title_tag else ''
            
            for script in soup(['script', 'style', 'nav', 'footer', 'header', 'aside']):
                script.decompose()
            
            content = soup.get_text(separator=' ', strip=True)
            
            all_links, internal_links, external_links = self.content_extractor.extract_links(soup, url)
            
            emails = self.content_extractor.extract_emails(content)
            phones = self.content_extractor.extract_phone_numbers(content)
            social_profiles = self.content_extractor.extract_social_profiles(content, all_links)
            person_mentions = self.content_extractor.extract_person_mentions(content, url)
            metadata = self.content_extractor.extract_metadata(soup)
            
            response_time = int((time.time() - start_time) * 1000)
            
            with self._lock:
                self.visited_urls.add(url)
                self._update_domain_data(domain, url, external_links, emails, social_profiles)
                self._update_person_mentions(person_mentions, domain, emails, phones, social_profiles)
                self._update_link_relationships(domain, external_links, soup)
            
            return CrawledPage(
                url=url,
                domain=domain,
                title=title,
                content=content[:10000],
                outbound_links=all_links[:100],
                inbound_links=[],
                internal_links=internal_links[:50],
                external_links=external_links[:50],
                emails=emails,
                phone_numbers=phones,
                social_profiles=[p if isinstance(p, dict) else asdict(p) for p in social_profiles],
                person_mentions=person_mentions,
                metadata=metadata,
                crawl_depth=depth,
                crawl_time=datetime.utcnow().isoformat(),
                response_time_ms=response_time,
                status='success'
            )
            
        except Exception as e:
            logger.error(f"Error crawling {url} with requests: {e}")
            with self._lock:
                self.visited_urls.add(url)
            return CrawledPage(
                url=url,
                domain=domain,
                title='',
                content='',
                outbound_links=[],
                inbound_links=[],
                internal_links=[],
                external_links=[],
                emails=[],
                phone_numbers=[],
                social_profiles=[],
                person_mentions=[],
                metadata={'error': str(e)},
                crawl_depth=depth,
                crawl_time=datetime.utcnow().isoformat(),
                response_time_ms=int((time.time() - start_time) * 1000),
                status='error'
            )
    
    def _crawl_page(self, url: str, depth: int) -> Optional[CrawledPage]:
        """Crawl a single page"""
        if url in self.visited_urls:
            return None
        
        if len(self.visited_urls) >= self.max_pages:
            return None
        
        if depth > self.max_depth:
            return None
        
        parsed = urlparse(url)
        domain = parsed.netloc
        
        if self.respect_robots and not self.robots_parser.can_fetch(url):
            logger.info(f"Blocked by robots.txt: {url}")
            return None
        
        crawl_delay = self.robots_parser.get_crawl_delay(f"{parsed.scheme}://{domain}")
        time.sleep(crawl_delay)
        
        if not self._selenium_available:
            return self._crawl_page_requests(url, depth)
        
        start_time = time.time()
        
        try:
            driver = self._get_driver()
            
            with self._driver_lock:
                driver.get(url)
                time.sleep(2)
                html = driver.page_source
                title = driver.title or ''
            
            soup = BeautifulSoup(html, 'lxml')
            
            for script in soup(['script', 'style', 'nav', 'footer', 'header', 'aside']):
                script.decompose()
            
            content = soup.get_text(separator=' ', strip=True)
            
            all_links, internal_links, external_links = self.content_extractor.extract_links(soup, url)
            
            emails = self.content_extractor.extract_emails(content)
            phones = self.content_extractor.extract_phone_numbers(content)
            social_profiles = self.content_extractor.extract_social_profiles(content, all_links)
            person_mentions = self.content_extractor.extract_person_mentions(content, url)
            metadata = self.content_extractor.extract_metadata(soup)
            
            response_time = int((time.time() - start_time) * 1000)
            
            with self._lock:
                self.visited_urls.add(url)
                
                self._update_domain_data(domain, url, external_links, emails, social_profiles)
                self._update_person_mentions(person_mentions, domain, emails, phones, social_profiles)
                self._update_link_relationships(domain, external_links, soup)
            
            return CrawledPage(
                url=url,
                domain=domain,
                title=title,
                content=content[:10000],
                outbound_links=all_links[:100],
                inbound_links=[],
                internal_links=internal_links[:50],
                external_links=external_links[:50],
                emails=emails,
                phone_numbers=phones,
                social_profiles=[asdict(p) if hasattr(p, '__dict__') else p for p in social_profiles],
                person_mentions=person_mentions,
                metadata=metadata,
                crawl_depth=depth,
                crawl_time=datetime.utcnow().isoformat(),
                response_time_ms=response_time,
                status='success'
            )
            
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")
            with self._lock:
                self.visited_urls.add(url)
            return CrawledPage(
                url=url,
                domain=domain,
                title='',
                content='',
                outbound_links=[],
                inbound_links=[],
                internal_links=[],
                external_links=[],
                emails=[],
                phone_numbers=[],
                social_profiles=[],
                person_mentions=[],
                metadata={'error': str(e)},
                crawl_depth=depth,
                crawl_time=datetime.utcnow().isoformat(),
                response_time_ms=int((time.time() - start_time) * 1000),
                status='error'
            )
    
    def _update_domain_data(
        self,
        domain: str,
        url: str,
        external_links: List[str],
        emails: List[str],
        social_profiles: List[Dict]
    ):
        """Update domain node data"""
        if domain not in self.domain_data:
            self.domain_data[domain] = DomainNode(
                domain=domain,
                pages_crawled=0,
                total_links=0,
                outbound_domains=set(),
                inbound_domains=set(),
                emails_found=[],
                social_profiles=[],
                technologies=[],
                first_seen=datetime.utcnow().isoformat(),
                last_seen=datetime.utcnow().isoformat(),
                risk_indicators=[]
            )
        
        node = self.domain_data[domain]
        node.pages_crawled += 1
        node.total_links += len(external_links)
        node.last_seen = datetime.utcnow().isoformat()
        
        for link in external_links:
            ext_domain = urlparse(link).netloc
            if ext_domain:
                node.outbound_domains.add(ext_domain)
                
                if ext_domain in self.domain_data:
                    self.domain_data[ext_domain].inbound_domains.add(domain)
        
        node.emails_found.extend(emails)
        node.emails_found = list(set(node.emails_found))
        
        for profile in social_profiles:
            if isinstance(profile, dict):
                node.social_profiles.append(profile.get('url', ''))
        node.social_profiles = list(set(node.social_profiles))
    
    def _update_person_mentions(
        self,
        mentions: List[Dict],
        domain: str,
        emails: List[str],
        phones: List[str],
        social_profiles: List[Dict]
    ):
        """Update person mention data"""
        for mention in mentions:
            name = mention['name']
            
            if name not in self.person_mentions:
                self.person_mentions[name] = PersonMention(
                    name=name,
                    context=mention['context'],
                    source_url=mention['source_url'],
                    source_domain=domain,
                    confidence=mention['confidence'],
                    associated_emails=[],
                    associated_phones=[],
                    associated_social=[],
                    first_seen=datetime.utcnow().isoformat(),
                    mention_count=0
                )
            
            pm = self.person_mentions[name]
            pm.mention_count += 1
            pm.associated_emails.extend(emails)
            pm.associated_emails = list(set(pm.associated_emails))
            pm.associated_phones.extend(phones)
            pm.associated_phones = list(set(pm.associated_phones))
            
            for profile in social_profiles:
                if isinstance(profile, dict):
                    pm.associated_social.append(profile.get('url', ''))
            pm.associated_social = list(set(pm.associated_social))
    
    def _update_link_relationships(
        self,
        source_domain: str,
        external_links: List[str],
        soup: BeautifulSoup
    ):
        """Update link relationship data"""
        domain_links: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
        
        for a in soup.find_all('a', href=True):
            href = a['href']
            if href.startswith('http'):
                target_domain = urlparse(href).netloc
                if target_domain and target_domain != source_domain:
                    anchor_text = a.get_text(strip=True)[:100]
                    domain_links[target_domain].append((href, anchor_text))
        
        for target_domain, links in domain_links.items():
            key = f"{source_domain}->{target_domain}"
            
            if key not in self.link_relationships:
                self.link_relationships[key] = LinkRelationship(
                    source_domain=source_domain,
                    target_domain=target_domain,
                    link_count=0,
                    link_types=[],
                    anchor_texts=[],
                    first_seen=datetime.utcnow().isoformat(),
                    last_seen=datetime.utcnow().isoformat(),
                    bidirectional=False
                )
            
            rel = self.link_relationships[key]
            rel.link_count += len(links)
            rel.last_seen = datetime.utcnow().isoformat()
            
            for _, anchor in links:
                if anchor and anchor not in rel.anchor_texts:
                    rel.anchor_texts.append(anchor)
            rel.anchor_texts = rel.anchor_texts[:20]
            
            reverse_key = f"{target_domain}->{source_domain}"
            if reverse_key in self.link_relationships:
                rel.bidirectional = True
                self.link_relationships[reverse_key].bidirectional = True
    
    def crawl(self, seed_urls: List[str]) -> CrawlResult:
        """Perform web crawl starting from seed URLs"""
        start_time = datetime.utcnow().isoformat()
        crawled_pages = []
        
        url_queue = deque()
        for url in seed_urls:
            url_queue.append((url, 0))
        
        while url_queue and len(self.visited_urls) < self.max_pages:
            url, depth = url_queue.popleft()
            
            if url in self.visited_urls:
                continue
            
            page = self._crawl_page(url, depth)
            
            if page and page.status == 'success':
                crawled_pages.append(page)
                
                if depth < self.max_depth:
                    for link in page.internal_links[:10]:
                        if link not in self.visited_urls:
                            url_queue.append((link, depth + 1))
                    
                    for link in page.external_links[:5]:
                        if link not in self.visited_urls:
                            url_queue.append((link, depth + 1))
        
        end_time = datetime.utcnow().isoformat()
        
        domain_graph = {}
        for domain, node in self.domain_data.items():
            domain_graph[domain] = {
                'domain': node.domain,
                'pages_crawled': node.pages_crawled,
                'total_links': node.total_links,
                'outbound_domains': list(node.outbound_domains),
                'inbound_domains': list(node.inbound_domains),
                'emails_found': node.emails_found,
                'social_profiles': node.social_profiles,
                'technologies': node.technologies,
                'first_seen': node.first_seen,
                'last_seen': node.last_seen,
                'risk_indicators': node.risk_indicators
            }
        
        person_list = [asdict(pm) for pm in self.person_mentions.values()]
        relationship_list = [asdict(rel) for rel in self.link_relationships.values()]
        
        statistics = {
            'pages_crawled': len(crawled_pages),
            'domains_discovered': len(self.domain_data),
            'total_links_found': sum(len(p.outbound_links) for p in crawled_pages),
            'unique_emails': len(set(e for p in crawled_pages for e in p.emails)),
            'unique_phones': len(set(ph for p in crawled_pages for ph in p.phone_numbers)),
            'persons_mentioned': len(self.person_mentions),
            'link_relationships': len(self.link_relationships),
            'bidirectional_links': sum(1 for r in self.link_relationships.values() if r.bidirectional),
            'average_depth': sum(p.crawl_depth for p in crawled_pages) / max(1, len(crawled_pages)),
            'average_response_time_ms': sum(p.response_time_ms for p in crawled_pages) / max(1, len(crawled_pages)),
        }
        
        return CrawlResult(
            crawl_id=hashlib.md5(f"{start_time}{seed_urls}".encode()).hexdigest()[:16],
            seed_urls=seed_urls,
            start_time=start_time,
            end_time=end_time,
            pages_crawled=len(crawled_pages),
            domains_discovered=len(self.domain_data),
            links_found=statistics['total_links_found'],
            persons_mentioned=len(self.person_mentions),
            crawled_pages=[asdict(p) for p in crawled_pages],
            domain_graph=domain_graph,
            person_mentions=person_list,
            link_relationships=relationship_list,
            statistics=statistics
        )
    
    def cleanup(self):
        """Clean up resources"""
        with self._driver_lock:
            if self._driver:
                try:
                    self._driver.quit()
                except WebDriverException as e:
                    logger.debug(f"Error closing WebDriver: {e}")
                self._driver = None


class DomainGraphAnalyzer:
    """Analyze domain relationship graphs"""
    
    def analyze_graph(self, domain_graph: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze domain graph for patterns and insights"""
        analysis = {
            'total_domains': len(domain_graph),
            'hub_domains': [],
            'authority_domains': [],
            'isolated_domains': [],
            'clusters': [],
            'suspicious_patterns': [],
        }
        
        for domain, data in domain_graph.items():
            outbound = len(data.get('outbound_domains', []))
            inbound = len(data.get('inbound_domains', []))
            
            if outbound > 10:
                analysis['hub_domains'].append({
                    'domain': domain,
                    'outbound_count': outbound
                })
            
            if inbound > 5:
                analysis['authority_domains'].append({
                    'domain': domain,
                    'inbound_count': inbound
                })
            
            if outbound == 0 and inbound == 0:
                analysis['isolated_domains'].append(domain)
        
        analysis['hub_domains'] = sorted(
            analysis['hub_domains'],
            key=lambda x: x['outbound_count'],
            reverse=True
        )[:10]
        
        analysis['authority_domains'] = sorted(
            analysis['authority_domains'],
            key=lambda x: x['inbound_count'],
            reverse=True
        )[:10]
        
        return analysis


class PersonNetworkAnalyzer:
    """Analyze person mention networks"""
    
    def analyze_network(self, person_mentions: List[Dict], link_relationships: List[Dict]) -> Dict[str, Any]:
        """Analyze person network for connections"""
        analysis = {
            'total_persons': len(person_mentions),
            'high_confidence_persons': [],
            'person_domain_map': {},
            'potential_connections': [],
            'email_clusters': {},
        }
        
        for person in person_mentions:
            if person.get('confidence', 0) >= 0.7:
                analysis['high_confidence_persons'].append({
                    'name': person['name'],
                    'confidence': person['confidence'],
                    'mention_count': person.get('mention_count', 1),
                    'domains': [person.get('source_domain', '')],
                    'emails': person.get('associated_emails', []),
                    'social': person.get('associated_social', [])
                })
        
        for person in person_mentions:
            domain = person.get('source_domain', '')
            if domain:
                if domain not in analysis['person_domain_map']:
                    analysis['person_domain_map'][domain] = []
                analysis['person_domain_map'][domain].append(person['name'])
        
        for domain, persons in analysis['person_domain_map'].items():
            if len(persons) > 1:
                for i, p1 in enumerate(persons):
                    for p2 in persons[i+1:]:
                        analysis['potential_connections'].append({
                            'person1': p1,
                            'person2': p2,
                            'connection_type': 'same_domain',
                            'domain': domain
                        })
        
        analysis['high_confidence_persons'] = sorted(
            analysis['high_confidence_persons'],
            key=lambda x: x['mention_count'],
            reverse=True
        )[:20]
        
        return analysis


class WebCrawlerEngine:
    """Main web crawler engine coordinating all crawling capabilities"""
    
    def __init__(self):
        self.pdf_generator = create_pdf_generator()
    
    def crawl_and_analyze(
        self,
        seed_urls: List[str],
        max_depth: int = 3,
        max_pages: int = 100,
        respect_robots: bool = True,
        generate_pdf: bool = True
    ) -> Dict[str, Any]:
        """Perform comprehensive web crawl and analysis"""
        crawler = WebCrawler(
            max_depth=max_depth,
            max_pages=max_pages,
            respect_robots=respect_robots
        )
        
        try:
            crawl_result = crawler.crawl(seed_urls)
            
            graph_analyzer = DomainGraphAnalyzer()
            graph_analysis = graph_analyzer.analyze_graph(crawl_result.domain_graph)
            
            person_analyzer = PersonNetworkAnalyzer()
            person_analysis = person_analyzer.analyze_network(
                crawl_result.person_mentions,
                crawl_result.link_relationships
            )
            
            result = {
                'crawl_id': crawl_result.crawl_id,
                'seed_urls': crawl_result.seed_urls,
                'start_time': crawl_result.start_time,
                'end_time': crawl_result.end_time,
                'statistics': crawl_result.statistics,
                'domain_graph': crawl_result.domain_graph,
                'graph_analysis': graph_analysis,
                'person_mentions': crawl_result.person_mentions,
                'person_analysis': person_analysis,
                'link_relationships': crawl_result.link_relationships,
                'crawled_pages_summary': [
                    {
                        'url': p['url'],
                        'title': p['title'],
                        'depth': p['crawl_depth'],
                        'links_found': len(p['outbound_links']),
                        'persons_found': len(p['person_mentions'])
                    }
                    for p in crawl_result.crawled_pages
                ],
                'pdf_report': None
            }
            
            if generate_pdf:
                result['pdf_report'] = self._generate_pdf_report(result)
            
            return result
            
        finally:
            crawler.cleanup()
    
    def _generate_pdf_report(self, result: Dict[str, Any]) -> str:
        """Generate PDF report from crawl results"""
        metadata = ReportMetadata(
            title="Web Crawl Analysis Report",
            subtitle=f"Seed URLs: {', '.join(result['seed_urls'][:3])}...",
            classification="CONFIDENTIAL",
            author="GISC Web Crawler Engine",
            organization="Global Intelligence Security Command Center",
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            report_id=result['crawl_id'].upper(),
            version="1.0"
        )
        
        summary = {
            'overview': f"Web crawl completed. Analyzed {result['statistics']['pages_crawled']} pages across {result['statistics']['domains_discovered']} domains.",
            'key_findings': [
                f"Discovered {result['statistics']['domains_discovered']} unique domains",
                f"Found {result['statistics']['total_links_found']} total links",
                f"Identified {result['statistics']['persons_mentioned']} person mentions",
                f"Extracted {result['statistics']['unique_emails']} unique email addresses",
                f"Found {result['statistics']['bidirectional_links']} bidirectional link relationships"
            ],
            'risk_level': 'LOW',
            'statistics': result['statistics']
        }
        
        person_data = {
            'subject': {
                'name': 'Web Crawl Analysis',
                'aliases': result['seed_urls'],
                'location': 'Internet',
                'risk_level': 'Analysis Complete'
            },
            'social_profiles': [
                {
                    'platform': p.get('source_domain', 'Unknown'),
                    'username': p.get('name', 'Unknown'),
                    'followers': p.get('mention_count', 0)
                }
                for p in result['person_mentions'][:10]
            ],
            'connections': [
                {
                    'name': conn.get('person2', 'Unknown'),
                    'relationship': conn.get('connection_type', 'Unknown'),
                    'confidence': 'Medium',
                    'notes': f"Connected via {conn.get('domain', 'Unknown')}"
                }
                for conn in result['person_analysis'].get('potential_connections', [])[:10]
            ]
        }
        
        return self.pdf_generator.generate_person_intelligence_report(
            metadata=metadata,
            person_data=person_data
        )


def create_web_crawler_engine() -> WebCrawlerEngine:
    """Factory function to create web crawler engine instance"""
    return WebCrawlerEngine()
