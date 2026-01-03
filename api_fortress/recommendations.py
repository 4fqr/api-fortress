"""
Security Recommendations Engine.
Analyzes scan results and provides tailored security advice.
"""

from typing import List, Dict, Any
from collections import defaultdict

from api_fortress.models import Vulnerability, Severity, ScanResult


class SecurityRecommendations:
    """Generates security recommendations based on scan results."""

    def generate_recommendations(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Generate comprehensive security recommendations."""
        
        recommendations = {
            "critical_actions": [],
            "high_priority": [],
            "medium_priority": [],
            "best_practices": [],
            "api_specific": [],
            "monitoring": [],
            "summary": {}
        }

        # Analyze vulnerabilities
        vuln_by_severity = self._group_by_severity(scan_result.vulnerabilities)
        vuln_by_type = self._group_by_type(scan_result.vulnerabilities)

        # Generate summary
        recommendations["summary"] = {
            "total_issues": len(scan_result.vulnerabilities),
            "critical": len(vuln_by_severity.get(Severity.CRITICAL, [])),
            "high": len(vuln_by_severity.get(Severity.HIGH, [])),
            "medium": len(vuln_by_severity.get(Severity.MEDIUM, [])),
            "low": len(vuln_by_severity.get(Severity.LOW, [])),
            "overall_risk": self._calculate_risk_level(scan_result.vulnerabilities),
        }

        # Critical actions (must do NOW)
        if Severity.CRITICAL in vuln_by_severity:
            recommendations["critical_actions"].extend([
                "🚨 IMMEDIATE ACTION REQUIRED - Critical vulnerabilities detected",
                "⏰ Timeline: Fix within 24 hours",
                "",
                "CRITICAL FINDINGS:",
            ])
            for vuln in vuln_by_severity[Severity.CRITICAL]:
                recommendations["critical_actions"].append(f"  ❌ {vuln.name}")
            recommendations["critical_actions"].extend([
                "",
                "ACTION ITEMS:",
                "1. Alert security team immediately",
                "2. Disable public access if possible",
                "3. Review access logs for exploitation attempts",
                "4. Apply fixes as outlined in vulnerability details",
                "5. Test fixes thoroughly before re-enabling",
            ])

        # High priority actions
        if Severity.HIGH in vuln_by_severity:
            recommendations["high_priority"].extend([
                "⚠️ HIGH PRIORITY - Fix within 1 week",
                "",
                "HIGH SEVERITY FINDINGS:",
            ])
            for vuln in vuln_by_severity[Severity.HIGH]:
                recommendations["high_priority"].append(f"  ⚠️ {vuln.name}")
            recommendations["high_priority"].extend([
                "",
                "RECOMMENDED ACTIONS:",
                "1. Schedule fixes in next sprint",
                "2. Implement compensating controls",
                "3. Increase monitoring on affected endpoints",
            ])

        # Medium priority
        if Severity.MEDIUM in vuln_by_severity:
            recommendations["medium_priority"].extend([
                "📋 MEDIUM PRIORITY - Address within 1 month",
                "",
                "MEDIUM SEVERITY FINDINGS:",
            ])
            for vuln in vuln_by_severity[Severity.MEDIUM]:
                recommendations["medium_priority"].append(f"  • {vuln.name}")

        # API-specific recommendations
        target_url = scan_result.target.lower()
        
        if "firebaseio.com" in target_url or "firebase" in target_url:
            recommendations["api_specific"] = self._get_firebase_recommendations(
                scan_result.vulnerabilities
            )
        else:
            recommendations["api_specific"] = self._get_general_api_recommendations(
                scan_result.vulnerabilities
            )

        # Best practices
        recommendations["best_practices"] = [
            "🛡️ SECURITY BEST PRACTICES FOR YOUR API",
            "",
            "1. AUTHENTICATION & AUTHORIZATION:",
            "   • Implement OAuth 2.0 or JWT-based authentication",
            "   • Require authentication for ALL sensitive endpoints",
            "   • Use role-based access control (RBAC)",
            "   • Rotate credentials regularly",
            "",
            "2. INPUT VALIDATION:",
            "   • Validate ALL user inputs on server-side",
            "   • Use parameterized queries to prevent injection",
            "   • Implement schema validation",
            "   • Sanitize output data",
            "",
            "3. RATE LIMITING:",
            "   • Implement per-IP rate limits",
            "   • Use progressive throttling",
            "   • Add CAPTCHA for suspicious patterns",
            "   • Monitor for abuse patterns",
            "",
            "4. SECURITY HEADERS:",
            "   • X-Content-Type-Options: nosniff",
            "   • X-Frame-Options: DENY",
            "   • Content-Security-Policy: default-src 'self'",
            "   • Strict-Transport-Security: max-age=31536000",
            "",
            "5. CORS CONFIGURATION:",
            "   • Never use Access-Control-Allow-Origin: *",
            "   • Whitelist specific trusted origins",
            "   • Validate Origin header on server",
            "",
            "6. ERROR HANDLING:",
            "   • Never expose stack traces or system details",
            "   • Use generic error messages",
            "   • Log detailed errors securely server-side",
            "",
            "7. ENCRYPTION:",
            "   • Always use HTTPS (TLS 1.2+)",
            "   • Encrypt sensitive data at rest",
            "   • Use strong encryption algorithms",
        ]

        # Monitoring recommendations
        recommendations["monitoring"] = [
            "📊 MONITORING & DETECTION RECOMMENDATIONS",
            "",
            "SET UP THE FOLLOWING MONITORING:",
            "",
            "1. Real-time Alerts:",
            "   • Failed authentication attempts (>5 in 5 min)",
            "   • Unusual traffic spikes",
            "   • 4xx/5xx error rate increases",
            "   • Requests from blacklisted IPs",
            "",
            "2. Regular Audits:",
            "   • Weekly access log reviews",
            "   • Monthly security scans (use this tool!)",
            "   • Quarterly penetration tests",
            "   • Annual third-party security audits",
            "",
            "3. Metrics to Track:",
            "   • Requests per endpoint",
            "   • Response time trends",
            "   • Error rates by type",
            "   • Authentication success/failure rates",
            "",
            "4. Security Tools:",
            "   • Web Application Firewall (WAF)",
            "   • Intrusion Detection System (IDS)",
            "   • Security Information and Event Management (SIEM)",
            "   • API Gateway with security policies",
        ]

        return recommendations

    def _get_firebase_recommendations(self, vulnerabilities: List[Vulnerability]) -> List[str]:
        """Get Firebase-specific recommendations."""
        return [
            "🔥 FIREBASE SECURITY HARDENING GUIDE",
            "",
            "YOUR API IS FIREBASE-BASED. Follow these specific steps:",
            "",
            "1. FIREBASE SECURITY RULES (CRITICAL):",
            "",
            "   Current State: Rules appear to be open/permissive",
            "   Required Action: Update rules in Firebase Console",
            "",
            "   Recommended Rules Structure:",
            "   ```json",
            "   {",
            '     "rules": {',
            '       // Require authentication for all operations',
            '       ".read": "auth != null",',
            '       ".write": "auth != null",',
            "       ",
            '       // Or for public read-only data (like Hacker News):',
            '       ".read": true,',
            '       ".write": "auth != null && auth.uid == $uid",',
            "       ",
            "       // Specific paths with granular control",
            '       "users": {',
            '         "$uid": {',
            '           ".read": "auth != null && auth.uid == $uid",',
            '           ".write": "auth != null && auth.uid == $uid"',
            "         }",
            "       }",
            "     }",
            "   }",
            "   ```",
            "",
            "2. FIREBASE AUTHENTICATION:",
            "   • Enable Firebase Authentication",
            "   • Supported methods: Email/Password, Google, GitHub, etc.",
            "   • Generate auth tokens for API access",
            "   • Implement token refresh logic",
            "",
            "3. FIREBASE APP CHECK (Mobile/Web Apps):",
            "   • Protects backend from abuse",
            "   • Verifies requests come from your app",
            "   • Setup: Firebase Console → App Check → Enable",
            "",
            "4. FIREBASE FUNCTIONS (Proxy Layer):",
            "   • Create Cloud Functions to proxy external APIs",
            "   • Implement server-side rate limiting",
            "   • Add authentication middleware",
            "   • Cache responses to reduce external API calls",
            "",
            "   Example Function:",
            "   ```javascript",
            "   const functions = require('firebase-functions');",
            "   const admin = require('firebase-admin');",
            "   ",
            "   exports.hackerNewsProxy = functions.https.onRequest(async (req, res) => {",
            "     // Verify Firebase Authentication token",
            "     const token = req.headers.authorization?.split('Bearer ')[1];",
            "     if (!token) return res.status(401).send('Unauthorized');",
            "     ",
            "     try {",
            "       await admin.auth().verifyIdToken(token);",
            "       // Rate limiting logic here",
            "       // Fetch from Hacker News API",
            "       // Return cached/processed data",
            "     } catch (error) {",
            "       res.status(401).send('Invalid token');",
            "     }",
            "   });",
            "   ```",
            "",
            "5. FIREBASE HOSTING (If serving web content):",
            "   • Configure security headers in firebase.json",
            "   • Enable HTTPS redirect",
            "   • Set up custom domain with SSL",
            "",
            "6. DATA VALIDATION:",
            "   • Use Firebase Security Rules for schema validation",
            "   • Validate data types and structure",
            "   • Set size limits on writes",
            "",
            "7. COST MANAGEMENT:",
            "   • Set up billing alerts",
            "   • Monitor read/write operations",
            "   • Implement caching to reduce database calls",
            "   • Use Firebase Spark (free) plan limits wisely",
            "",
            "8. TESTING:",
            "   • Use Firebase Emulator Suite for local testing",
            "   • Test security rules with Rules Playground",
            "   • Simulate attacks before deploying",
            "",
            "📚 Resources:",
            "   • Firebase Security Rules: https://firebase.google.com/docs/rules",
            "   • App Check: https://firebase.google.com/docs/app-check",
            "   • Best Practices: https://firebase.google.com/docs/rules/security-best-practices",
        ]

    def _get_general_api_recommendations(self, vulnerabilities: List[Vulnerability]) -> List[str]:
        """Get general API security recommendations."""
        return [
            "🔒 API SECURITY HARDENING GUIDE",
            "",
            "SPECIFIC RECOMMENDATIONS FOR YOUR API:",
            "",
            "1. IMPLEMENT API GATEWAY:",
            "   • Use services like Kong, AWS API Gateway, or Azure APIM",
            "   • Centralize authentication, rate limiting, and logging",
            "   • Add request/response transformation",
            "",
            "2. AUTHENTICATION:",
            "   • OAuth 2.0 for user authentication",
            "   • API keys for service-to-service",
            "   • JWT tokens with short expiration (15-60 min)",
            "",
            "3. AUTHORIZATION:",
            "   • Implement RBAC (Role-Based Access Control)",
            "   • Check permissions on EVERY request",
            "   • Use principle of least privilege",
            "",
            "4. INPUT VALIDATION:",
            "   • Whitelist approach (allow only valid inputs)",
            "   • Schema validation (JSON Schema, OpenAPI)",
            "   • Parameterized queries for databases",
            "",
            "5. OUTPUT ENCODING:",
            "   • Escape special characters",
            "   • Use proper Content-Type headers",
            "   • Implement field-level filtering",
        ]

    def _group_by_severity(self, vulnerabilities: List[Vulnerability]) -> Dict[Severity, List[Vulnerability]]:
        """Group vulnerabilities by severity."""
        grouped = defaultdict(list)
        for vuln in vulnerabilities:
            grouped[vuln.severity].append(vuln)
        return dict(grouped)

    def _group_by_type(self, vulnerabilities: List[Vulnerability]) -> Dict[str, List[Vulnerability]]:
        """Group vulnerabilities by type."""
        grouped = defaultdict(list)
        for vuln in vulnerabilities:
            vuln_type = vuln.type if isinstance(vuln.type, str) else vuln.type.value
            grouped[vuln_type].append(vuln)
        return dict(grouped)

    def _calculate_risk_level(self, vulnerabilities: List[Vulnerability]) -> str:
        """Calculate overall risk level."""
        if not vulnerabilities:
            return "LOW"
        
        severity_scores = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 1,
        }
        
        total_score = sum(severity_scores.get(v.severity, 0) for v in vulnerabilities)
        avg_score = total_score / len(vulnerabilities)
        
        if avg_score >= 8:
            return "CRITICAL"
        elif avg_score >= 6:
            return "HIGH"
        elif avg_score >= 3:
            return "MEDIUM"
        else:
            return "LOW"

    def format_recommendations(self, recommendations: Dict[str, Any]) -> str:
        """Format recommendations as readable text."""
        output = []
        
        output.append("=" * 80)
        output.append("🛡️  SECURITY RECOMMENDATIONS & REMEDIATION GUIDE")
        output.append("=" * 80)
        output.append("")
        
        # Summary
        summary = recommendations["summary"]
        output.append("📊 SCAN SUMMARY:")
        output.append(f"   • Total Issues Found: {summary['total_issues']}")
        output.append(f"   • Critical: {summary['critical']}")
        output.append(f"   • High: {summary['high']}")
        output.append(f"   • Medium: {summary['medium']}")
        output.append(f"   • Low: {summary['low']}")
        output.append(f"   • Overall Risk Level: {summary['overall_risk']}")
        output.append("")
        output.append("=" * 80)
        output.append("")
        
        # Critical actions
        if recommendations["critical_actions"]:
            output.extend(recommendations["critical_actions"])
            output.append("")
            output.append("=" * 80)
            output.append("")
        
        # High priority
        if recommendations["high_priority"]:
            output.extend(recommendations["high_priority"])
            output.append("")
            output.append("=" * 80)
            output.append("")
        
        # Medium priority
        if recommendations["medium_priority"]:
            output.extend(recommendations["medium_priority"])
            output.append("")
            output.append("=" * 80)
            output.append("")
        
        # API-specific
        if recommendations["api_specific"]:
            output.extend(recommendations["api_specific"])
            output.append("")
            output.append("=" * 80)
            output.append("")
        
        # Best practices
        output.extend(recommendations["best_practices"])
        output.append("")
        output.append("=" * 80)
        output.append("")
        
        # Monitoring
        output.extend(recommendations["monitoring"])
        output.append("")
        output.append("=" * 80)
        output.append("")
        
        output.append("💡 NEXT STEPS:")
        output.append("   1. Review each vulnerability in detail")
        output.append("   2. Prioritize fixes based on severity")
        output.append("   3. Implement recommendations systematically")
        output.append("   4. Re-scan after fixes to verify")
        output.append("   5. Set up continuous monitoring")
        output.append("")
        output.append("📖 For detailed remediation, review individual vulnerability reports above.")
        output.append("=" * 80)
        
        return "\n".join(output)
