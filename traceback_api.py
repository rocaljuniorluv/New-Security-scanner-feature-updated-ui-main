import os
from dotenv import load_dotenv
from typing import Dict, List, Optional, Union
import json
import asyncio
import aiohttp
from aiohttp import ClientTimeout

class TracebackAPI:
    def __init__(self):
        load_dotenv()
        self.api_key = os.getenv('TRACEBACK_API_KEY')
        self.base_url = 'https://traceback.sh/api'
        
        if not self.api_key:
            raise ValueError("TRACEBACK_API_KEY not found in environment variables")
        
        # Configure timeout for all requests
        self.timeout = ClientTimeout(total=60)  # 60 second timeout
    
    async def _make_request(self, endpoint: str, data: Dict) -> Dict:
        """Make an async request to the Traceback API"""
        headers = {
            'X-API-KEY': self.api_key,
            'Content-Type': 'application/json'
        }
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            try:
                async with session.post(
                    f"{self.base_url}{endpoint}",
                    headers=headers,
                    json=data
                ) as response:
                    if response.status == 200:
                        try:
                            response_data = await response.json()
                            # Validate response format
                            if not isinstance(response_data, dict):
                                return {"error": "Invalid response format", "data": response_data}
                            return response_data
                        except json.JSONDecodeError:
                            return {"error": "Invalid JSON response", "raw": await response.text()}
                    else:
                        print(f"HTTP error while making request to {endpoint}")
                        print(f"Status code: {response.status}")
                        response_text = await response.text()
                        print(f"Response: {response_text}")
                        return {"error": f"HTTP error: {response.status} - {response_text}"}
            except asyncio.TimeoutError:
                print(f"Timeout error while making request to {endpoint}")
                return {"error": "Request timed out after 60 seconds"}
            except aiohttp.ClientError as e:
                print(f"Connection error while making request to {endpoint}")
                print(f"Error: {str(e)}")
                return {"error": f"Connection error: {str(e)}"}
    
    async def database_lookup(
        self,
        query: str,
        field: str,
        limit: int = 100,
        use_wildcard: bool = False,
        use_regex: bool = False
    ) -> Dict:
        """
        Perform a database lookup for a specific field and query
        
        Args:
            query: The search query
            field: The field to search in (username, email, password, url, ip_address, domain, country, discord, phone)
            limit: Maximum number of results to return
            use_wildcard: Whether to use wildcard matching
            use_regex: Whether to use regex matching
            
        Returns:
            Dict containing the lookup results
        """
        valid_fields = {
            'username', 'email', 'password', 'url', 'ip_address',
            'domain', 'country', 'discord', 'phone'
        }
        
        if field not in valid_fields:
            raise ValueError(f"Invalid field. Must be one of: {', '.join(valid_fields)}")
        
        data = {
            "query": query,
            "field": field,
            "limit": limit,
            "use_wildcard": use_wildcard,
            "use_regex": use_regex
        }
        
        result = await self._make_request('/v1/dblookups', data)
        if 'error' in result:
            return result
        
        # Format the response to match expected structure
        return {
            "status": "success",
            "type": "database_lookup",
            "field": field,
            "query": query,
            "results": result.get("results", []),
            "count": len(result.get("results", []))
        }
    
    async def realtime_lookup(self, query: str, field: str) -> Dict:
        """
        Perform a realtime lookup using custom modules and CSINT module data
        
        Args:
            query: The search query
            field: The field to search in (username, email, ip_address, domain, name, minecraft)
            
        Returns:
            Dict containing the realtime lookup results
        """
        valid_fields = {
            'username', 'email', 'ip_address', 'domain', 'name', 'minecraft'
        }
        
        if field not in valid_fields:
            raise ValueError(f"Invalid field. Must be one of: {', '.join(valid_fields)}")
        
        data = {
            "query": query,
            "field": field
        }
        
        result = await self._make_request('/v1/realtime', data)
        if 'error' in result:
            return result
        
        # Format the response to match expected structure
        return {
            "status": "success",
            "type": "realtime_lookup",
            "field": field,
            "query": query,
            "results": result.get("results", []),
            "count": len(result.get("results", []))
        }
    
    async def intelx_lookup(self, query: str, field: str = 'email') -> Dict:
        """
        Perform an IntelX lookup for an email or system ID
        
        Args:
            query: The search query (email or system ID)
            field: The field to search in (email or systemid)
            
        Returns:
            Dict containing the IntelX lookup results
        """
        valid_fields = {'email', 'systemid'}
        
        if field not in valid_fields:
            raise ValueError(f"Invalid field. Must be one of: {', '.join(valid_fields)}")
        
        data = {
            "query": query,
            "field": field
        }
        
        result = await self._make_request('/v1/intelx', data)
        if 'error' in result:
            return result
        
        # Format the response to match expected structure
        return {
            "status": "success",
            "type": "intelx_lookup",
            "field": field,
            "query": query,
            "results": result.get("results", []),
            "count": len(result.get("results", []))
        }
    
    async def perform_all_lookups(self, query: str, email: str) -> Dict:
        """
        Perform all available lookups concurrently
        
        Args:
            query: The search query (domain or other identifier)
            email: The email to search for
            
        Returns:
            Dict containing results from all lookups
        """
        tasks = [
            self.database_lookup(email, 'email'),
            self.database_lookup(query, 'domain'),
            self.realtime_lookup(query, 'domain'),
            self.intelx_lookup(email)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results and format them properly
        formatted_results = {
            'email_leaks': results[0] if not isinstance(results[0], Exception) else {"error": str(results[0])},
            'domain_leaks': results[1] if not isinstance(results[1], Exception) else {"error": str(results[1])},
            'realtime_intel': results[2] if not isinstance(results[2], Exception) else {"error": str(results[2])},
            'intelx_results': results[3] if not isinstance(results[3], Exception) else {"error": str(results[3])}
        }
        
        # Check if any of the lookups were successful
        has_success = any(
            isinstance(result, dict) and result.get('status') == 'success'
            for result in results
            if not isinstance(result, Exception)
        )
        
        return {
            "status": "success" if has_success else "error",
            "message": "Data leak assessment completed" if has_success else "All lookups failed",
            "findings": formatted_results
        } 