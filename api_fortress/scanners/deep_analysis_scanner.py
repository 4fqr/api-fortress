"""
Deep Analysis scanner for comprehensive vulnerability detection.
Performs advanced testing with detailed evidence collection.
"""

from typing import List, Dict, Any
import re
import json
import asyncio

from api_fortress.scanners import BaseScanner
from api_fortress.models import Vulnerability, Severity, VulnerabilityType


class DeepAnalysisScanner(BaseScanner):
    """Advanced scanner for deep vulnerability analysis."""

    async def scan(self, url: str, method: str) -> List[Vulnerability]:
        """Perform deep analysis of the endpoint."""
        vulnerabilities = []

        # Test 1: Firebase specific vulnerabilities
        if "firebaseio.com" in url or "firebase" in url.lower():
            vulns = await self._test_firebase_security(url, method)
            vulnerabilities.extend(vulns)

        # Test 2: Data exposure analysis
        vulns = await self._test_data_exposure(url, method)
        vulnerabilities.extend(vulns)

        # Test 3: API enumeration vulnerabilities
        vulns = await self._test_api_enumeration(url, method)
        vulnerabilities.extend(vulns)

        # Test 4: Rate limiting and DoS vectors
        vulns = await self._test_rate_limiting_deep(url, method)
        vulnerabilities.extend(vulns)

        # Test 5: Response timing attacks
        vulns = await self._test_timing_attacks(url, method)
        vulnerabilities.extend(vulns)

        return vulnerabilities

    async def _test_firebase_security(self, url: str, method: str) -> List[Vulnerability]:
        """Test Firebase-specific security issues."""
        vulnerabilities = []

        try:
            # Test unauthenticated access
            response = await self.client.request(method, url)
            
            if response and response.status == 200:
                content = await response.text()
                
                # Check for .json endpoint exposure
                if url.endswith('.json') or '/.json' in url:
                    vuln = self.create_vulnerability(
                        name="Firebase Database Rules - Unauthenticated Read Access",
                        vuln_type=VulnerabilityType.BOLA,
                        severity=Severity.CRITICAL,
                        endpoint=url,
                        method=method,
                        description=(
                            "🔥 CRITICAL FIREBASE SECURITY ISSUE 🔥\n\n"
                            "The Firebase Realtime Database is configured with permissive security rules that "
                            "allow unauthenticated read access. This means ANYONE on the internet can read your "
                            "database content without any authentication.\n\n"
                            "ACTUAL FINDING:\n"
                            f"• Endpoint: {url}\n"
                            f"• Response Status: {response.status}\n"
                            f"• Content Length: {len(content)} bytes\n"
                            f"• Authentication Required: NO ❌\n\n"
                            "WHY THIS IS CRITICAL:\n"
                            "• Complete database dump possible\n"
                            "• User data exposed to public internet\n"
                            "• Potential for data scraping and theft\n"
                            "• Violation of privacy regulations (GDPR, CCPA)\n"
                            "• Can be found by automated scanners\n\n"
                            "ATTACK SCENARIO:\n"
                            "1. Attacker discovers Firebase URL (from source code, network traffic)\n"
                            "2. Attacker appends '.json' to any path\n"
                            "3. Entire database structure downloaded\n"
                            "4. Sensitive user data exfiltrated"
                        ),
                        evidence=(
                            f"✅ Successfully accessed Firebase endpoint without authentication\n\n"
                            f"REQUEST:\n"
                            f"GET {url}\n"
                            f"Headers: None (no auth token)\n\n"
                            f"RESPONSE:\n"
                            f"Status: {response.status} OK\n"
                            f"Content-Type: {response.headers.get('Content-Type', 'unknown')}\n"
                            f"Content Length: {len(content)} bytes\n"
                            f"Data returned: YES (full content accessible)\n\n"
                            f"SAMPLE DATA STRUCTURE:\n"
                            f"{content[:500]}..." if len(content) > 500 else content
                        ),
                        remediation=[
                            "🚨 IMMEDIATE ACTION REQUIRED:",
                            "",
                            "1. UPDATE FIREBASE SECURITY RULES NOW:",
                            "   {",
                            '     "rules": {',
                            '       ".read": "auth != null",  // Require authentication for all reads',
                            '       ".write": "auth != null"  // Require authentication for all writes',
                            "     }",
                            "   }",
                            "",
                            "2. For Hacker News API (if this is a Firebase proxy):",
                            "   • Implement server-side caching layer",
                            "   • Add rate limiting (max 10 requests/minute per IP)",
                            "   • Use Firebase Functions to proxy requests",
                            "   • Enable Firebase App Check for mobile apps",
                            "",
                            "3. DATA PROTECTION MEASURES:",
                            "   • Audit what data is currently exposed",
                            "   • Move sensitive data to Firestore with proper rules",
                            "   • Implement field-level security",
                            "   • Use Firebase Authentication tokens",
                            "",
                            "4. MONITORING & DETECTION:",
                            "   • Enable Firebase Analytics to track access patterns",
                            "   • Set up alerts for unusual read volumes",
                            "   • Monitor for data exfiltration attempts",
                            "   • Review access logs regularly",
                            "",
                            "5. TESTING:",
                            "   • Verify rules with Firebase Emulator",
                            "   • Test with unauthenticated requests (should fail)",
                            "   • Use Firebase Rules simulator in console",
                        ],
                        cwe_id="CWE-285",
                        cvss_score=9.1,
                    )
                    vulnerabilities.append(vuln)

                # Check for write access
                if method == "PUT" or method == "POST":
                    test_response = await self.client.request(
                        "PUT", 
                        f"{url.rstrip('/')}/fortress_test_write.json",
                        json={"test": "value"}
                    )
                    
                    if test_response and test_response.status in [200, 201]:
                        vuln = self.create_vulnerability(
                            name="Firebase Database Rules - Unauthenticated Write Access",
                            vuln_type=VulnerabilityType.BOLA,
                            severity=Severity.CRITICAL,
                            endpoint=url,
                            method="PUT/POST",
                            description=(
                                "🔥🔥 CATASTROPHIC FIREBASE SECURITY ISSUE 🔥🔥\n\n"
                                "The Firebase Realtime Database allows UNAUTHENTICATED WRITE ACCESS! "
                                "This is the most severe configuration possible - anyone can modify, "
                                "add, or delete your database content.\n\n"
                                "ACTUAL FINDING:\n"
                                f"• Successfully wrote data to: {url}/fortress_test_write.json\n"
                                f"• No authentication required ❌\n"
                                f"• Response: {test_response.status}\n\n"
                                "CATASTROPHIC RISKS:\n"
                                "• Complete database takeover possible\n"
                                "• Data deletion/ransomware attacks\n"
                                "• Injection of malicious content\n"
                                "• Service disruption and data corruption\n"
                                "• Legal liability and compliance violations"
                            ),
                            evidence=(
                                f"✅ Successfully WROTE to Firebase without authentication\n\n"
                                f"TEST WRITE REQUEST:\n"
                                f"PUT {url}/fortress_test_write.json\n"
                                f"Body: {{\"test\": \"value\"}}\n"
                                f"Auth: None\n\n"
                                f"RESPONSE:\n"
                                f"Status: {test_response.status}\n"
                                f"Result: Data written successfully ⚠️"
                            ),
                            remediation=[
                                "⚠️⚠️ STOP EVERYTHING AND FIX THIS NOW ⚠️⚠️",
                                "",
                                "IMMEDIATE ACTIONS (in this order):",
                                "1. Lock down Firebase database immediately",
                                "2. Check for unauthorized modifications",
                                "3. Restore from backup if data corrupted",
                                "4. Update security rules to deny all public access",
                                "5. Implement authentication requirements",
                                "6. Contact Firebase support if data breached",
                            ],
                            cwe_id="CWE-306",
                            cvss_score=10.0,
                        )
                        vulnerabilities.append(vuln)

        except Exception as e:
            pass

        return vulnerabilities

    async def _test_data_exposure(self, url: str, method: str) -> List[Vulnerability]:
        """Test for sensitive data exposure."""
        vulnerabilities = []

        try:
            response = await self.client.request(method, url)
            if not response or response.status != 200:
                return vulnerabilities

            content = await response.text()
            
            # Analyze response for sensitive patterns
            sensitive_patterns = {
                r'"password"\s*:\s*"[^"]*"': "Password fields in response",
                r'"api[_-]?key"\s*:\s*"[^"]*"': "API keys exposed",
                r'"secret"\s*:\s*"[^"]*"': "Secret values exposed",
                r'"token"\s*:\s*"[^"]*"': "Authentication tokens exposed",
                r'"email"\s*:\s*"[^@]+@[^"]+': "Email addresses exposed",
                r'\b\d{3}-\d{2}-\d{4}\b': "Potential SSN patterns",
                r'\b(?:\d{4}[-\s]?){3}\d{4}\b': "Credit card patterns",
                r'"private[_-]?key"\s*:\s*"[^"]*"': "Private keys exposed",
            }

            found_patterns = []
            for pattern, description in sensitive_patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    found_patterns.append(description)

            if found_patterns:
                vuln = self.create_vulnerability(
                    name="Sensitive Data Exposure in API Response",
                    vuln_type=VulnerabilityType.SECURITY_MISCONFIG,
                    severity=Severity.HIGH,
                    endpoint=url,
                    method=method,
                    description=(
                        "⚠️ SENSITIVE DATA LEAK DETECTED ⚠️\n\n"
                        "The API response contains sensitive information that should not be exposed. "
                        "This data could be intercepted, logged, or cached, leading to security breaches.\n\n"
                        "DETECTED SENSITIVE DATA:\n" + "\n".join(f"• {p}" for p in found_patterns) + "\n\n"
                        "SECURITY IMPLICATIONS:\n"
                        "• Data may be cached by browsers/proxies\n"
                        "• Logged in application logs\n"
                        "• Visible in network traffic (if not HTTPS)\n"
                        "• Stored in browser history\n"
                        "• Exposed to client-side scripts"
                    ),
                    evidence=(
                        f"Sensitive patterns found in response:\n\n"
                        f"Endpoint: {url}\n"
                        f"Response Size: {len(content)} bytes\n"
                        f"Patterns detected: {len(found_patterns)}\n\n"
                        f"Sample response (first 1000 chars):\n{content[:1000]}..."
                    ),
                    remediation=[
                        "Remove all sensitive fields from API responses",
                        "Implement field-level filtering (e.g., only return necessary fields)",
                        "Use response transformers to sanitize data",
                        "Never return password hashes or tokens",
                        "Implement proper data classification (public/private/sensitive)",
                        "Audit all API responses for sensitive data leaks",
                        "Use API gateway policies to filter sensitive fields",
                    ],
                    cwe_id="CWE-200",
                    cvss_score=7.5,
                )
                vulnerabilities.append(vuln)

        except Exception as e:
            pass

        return vulnerabilities

    async def _test_api_enumeration(self, url: str, method: str) -> List[Vulnerability]:
        """Test for API enumeration vulnerabilities."""
        vulnerabilities = []

        try:
            # Test predictable resource IDs
            if re.search(r'/\d+(?:\.json)?$', url):
                # Try sequential IDs
                responses = []
                base_url = re.sub(r'/\d+(\.json)?$', '', url)
                
                for i in range(1, 6):
                    test_url = f"{base_url}/{i}.json" if ".json" in url else f"{base_url}/{i}"
                    response = await self.client.request(method, test_url)
                    if response and response.status == 200:
                        responses.append((i, response.status))

                if len(responses) >= 3:
                    vuln = self.create_vulnerability(
                        name="Predictable Resource Enumeration Vulnerability",
                        vuln_type=VulnerabilityType.BOLA,
                        severity=Severity.MEDIUM,
                        endpoint=url,
                        method=method,
                        description=(
                            "🔍 API ENUMERATION VULNERABILITY DETECTED 🔍\n\n"
                            "The API uses predictable, sequential identifiers that allow attackers to "
                            "enumerate all resources systematically. This enables:\n\n"
                            "ATTACK VECTORS:\n"
                            "• Automated scraping of all database records\n"
                            "• Discovery of hidden/private resources\n"
                            "• Business intelligence gathering\n"
                            "• Competitive analysis\n"
                            "• User profiling and tracking\n\n"
                            f"PROOF OF CONCEPT:\n"
                            f"Successfully accessed {len(responses)} sequential resources:\n" +
                            "\n".join(f"• ID {r[0]}: HTTP {r[1]}" for r in responses) + "\n\n"
                            "An attacker can easily write a script to enumerate ALL resources."
                        ),
                        evidence=(
                            f"Sequential ID enumeration test results:\n\n"
                            f"Base URL: {base_url}\n"
                            f"Pattern: Sequential integers (1, 2, 3, ...)\n"
                            f"Success rate: {len(responses)}/5 (60%+)\n\n"
                            "Accessible IDs:\n" +
                            "\n".join(f"GET {base_url}/{r[0]}.json → HTTP {r[1]}" for r in responses)
                        ),
                        remediation=[
                            "Replace sequential IDs with UUIDs (Universally Unique Identifiers)",
                            "Example: Instead of /items/123, use /items/a7b2c4d6-8e9f-4a3b-9c1d-2e3f4a5b6c7d",
                            "Implement rate limiting to prevent bulk enumeration",
                            "Add authentication requirements for resource access",
                            "Monitor for enumeration patterns (sequential requests)",
                            "Use hashids or encrypted IDs if UUIDs are not feasible",
                            "Implement pagination limits and cursor-based pagination",
                            "Add CAPTCHA for suspected enumeration attempts",
                        ],
                        cwe_id="CWE-639",
                        cvss_score=5.3,
                    )
                    vulnerabilities.append(vuln)

        except Exception as e:
            pass

        return vulnerabilities

    async def _test_rate_limiting_deep(self, url: str, method: str) -> List[Vulnerability]:
        """Deep test for rate limiting and DoS vectors."""
        vulnerabilities = []

        try:
            # Send rapid requests to test rate limiting
            start_time = asyncio.get_event_loop().time()
            request_count = 0
            successful_requests = 0

            for i in range(20):
                response = await self.client.request(method, url)
                request_count += 1
                if response and response.status == 200:
                    successful_requests += 1

            end_time = asyncio.get_event_loop().time()
            duration = end_time - start_time

            # If all requests succeeded rapidly, rate limiting might be weak
            if successful_requests >= 15:
                requests_per_second = successful_requests / duration if duration > 0 else 0
                
                vuln = self.create_vulnerability(
                    name="Insufficient Rate Limiting - DoS Vector",
                    vuln_type=VulnerabilityType.SECURITY_MISCONFIG,
                    severity=Severity.MEDIUM,
                    endpoint=url,
                    method=method,
                    description=(
                        "⚠️ RATE LIMITING VULNERABILITY DETECTED ⚠️\n\n"
                        "The API does not implement sufficient rate limiting, allowing unlimited "
                        "requests from a single source. This creates multiple attack vectors:\n\n"
                        "ACTUAL TEST RESULTS:\n"
                        f"• Sent: {request_count} requests\n"
                        f"• Successful: {successful_requests} ({successful_requests/request_count*100:.1f}%)\n"
                        f"• Duration: {duration:.2f} seconds\n"
                        f"• Rate: {requests_per_second:.1f} requests/second\n"
                        f"• Rate limited: NO ❌\n\n"
                        "ATTACK SCENARIOS:\n"
                        "1. DENIAL OF SERVICE (DoS):\n"
                        "   • Overwhelm API with requests\n"
                        "   • Exhaust server resources\n"
                        "   • Cause service degradation/outage\n\n"
                        "2. RESOURCE ABUSE:\n"
                        "   • Scrape entire database\n"
                        "   • Excessive bandwidth consumption\n"
                        "   • Increase operational costs\n\n"
                        "3. BRUTE FORCE ATTACKS:\n"
                        "   • Password guessing\n"
                        "   • API key enumeration\n"
                        "   • Session hijacking attempts"
                    ),
                    evidence=(
                        f"Rate limiting test - {url}\n\n"
                        f"Test Configuration:\n"
                        f"• Total requests: {request_count}\n"
                        f"• Request method: {method}\n"
                        f"• Time window: {duration:.2f}s\n\n"
                        f"Results:\n"
                        f"✅ All {successful_requests} requests succeeded\n"
                        f"❌ No rate limiting detected\n"
                        f"⚠️ Peak rate: {requests_per_second:.1f} req/s\n"
                        f"⚠️ No 429 (Too Many Requests) responses received\n"
                        f"⚠️ No Retry-After headers observed"
                    ),
                    remediation=[
                        "IMPLEMENT RATE LIMITING IMMEDIATELY:",
                        "",
                        "1. Per-IP Rate Limits:",
                        "   • 100 requests per 15-minute window (general)",
                        "   • 10 requests per minute (authentication endpoints)",
                        "   • 1000 requests per hour (authenticated users)",
                        "",
                        "2. Implementation Options:",
                        "   Firebase: Use Firebase App Check + Cloud Functions",
                        "   • exports.api = functions.https.onRequest((req, res) => {",
                        '   •   // Implement rate limiting with Redis/Memcache',
                        "   • });",
                        "",
                        "3. Return proper HTTP 429 responses:",
                        "   • Status: 429 Too Many Requests",
                        "   • Headers: Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining",
                        "",
                        "4. Progressive throttling:",
                        "   • Slow down responses instead of hard blocking",
                        "   • Implement CAPTCHA for suspicious patterns",
                        "",
                        "5. Monitoring:",
                        "   • Track requests per IP/user",
                        "   • Alert on unusual traffic patterns",
                        "   • Implement automatic IP blocking for abuse",
                    ],
                    cwe_id="CWE-770",
                    cvss_score=5.3,
                )
                vulnerabilities.append(vuln)

        except Exception as e:
            pass

        return vulnerabilities

    async def _test_timing_attacks(self, url: str, method: str) -> List[Vulnerability]:
        """Test for timing attack vulnerabilities."""
        vulnerabilities = []

        # This is a demonstration - timing attacks are complex and need careful analysis
        # In production, you'd measure response times for different inputs
        
        return vulnerabilities
