"""
Wrappers around SerperDevTool and ScrapeWebsiteTool so that when Bedrock/CrewAI
calls them without parameters, we supply sensible defaults instead of failing.
"""
from typing import Any

from crewai.tools import BaseTool


# Defaults when the agent doesn't pass arguments (e.g. Bedrock tool call without params)
DEFAULT_SEARCH_QUERY = "AWS cloud security best practices and common vulnerabilities"
DEFAULT_SCRAPE_URL = "https://docs.aws.amazon.com/security/"


class SerperSearchWithDefaults(BaseTool):
    """Serper search wrapper: uses default search_query when not provided."""
    name: str = "search_the_internet_with_serper"
    description: str = (
        "Search the internet using Google search (Serper API). "
        "Call with search_query set to the topic to search (e.g. AWS S3 encryption, CVE for a product). "
        "Returns search results and snippets."
    )

    def _run(self, **kwargs: Any) -> str:
        from crewai_tools import SerperDevTool
        search_query = (kwargs.get("search_query") or kwargs.get("query") or "").strip()
        if not search_query:
            search_query = DEFAULT_SEARCH_QUERY
        tool = SerperDevTool()
        return tool.run(search_query=search_query)


class ScrapeWebsiteWithDefaults(BaseTool):
    """ScrapeWebsite wrapper: uses default URL when not provided."""
    name: str = "read_website_content"
    description: str = (
        "Fetch and read the text content of a webpage. Call with url set to the full URL. "
        "Use this to read AWS docs, security advisories, or any URL."
    )

    def _run(self, **kwargs: Any) -> str:
        from crewai_tools import ScrapeWebsiteTool
        url = (kwargs.get("url") or kwargs.get("URL") or "").strip()
        if not url:
            url = DEFAULT_SCRAPE_URL
        tool = ScrapeWebsiteTool()
        return tool.run(url=url)
