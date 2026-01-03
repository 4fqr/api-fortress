"""
Universal API Adapters for all major platforms and API types.
Supports REST, GraphQL, gRPC, WebSocket, and platform-specific APIs.
"""

from typing import Dict, List, Optional, Any
from enum import Enum
import re


class APIType(str, Enum):
    """Supported API types."""
    REST = "rest"
    GRAPHQL = "graphql"
    GRPC = "grpc"
    WEBSOCKET = "websocket"
    SOAP = "soap"


class APIPlatform(str, Enum):
    """Major API platforms."""
    # AI/ML Platforms
    OPENROUTER = "openrouter"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    HUGGINGFACE = "huggingface"
    REPLICATE = "replicate"
    COHERE = "cohere"
    
    # Cloud Platforms
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    DIGITALOCEAN = "digitalocean"
    RENDER = "render"
    HEROKU = "heroku"
    VERCEL = "vercel"
    NETLIFY = "netlify"
    
    # Databases
    MONGODB = "mongodb"
    FIREBASE = "firebase"
    SUPABASE = "supabase"
    PLANETSCALE = "planetscale"
    AIRTABLE = "airtable"
    
    # Payment/Commerce
    STRIPE = "stripe"
    PAYPAL = "paypal"
    SQUARE = "square"
    SHOPIFY = "shopify"
    
    # Communication
    TWILIO = "twilio"
    SENDGRID = "sendgrid"
    MAILGUN = "mailgun"
    SLACK = "slack"
    DISCORD = "discord"
    
    # Social/Auth
    GITHUB = "github"
    GITLAB = "gitlab"
    GOOGLE = "google"
    FACEBOOK = "facebook"
    TWITTER = "twitter"
    AUTH0 = "auth0"
    
    # General
    GENERIC = "generic"


class APIAdapter:
    """Base adapter for API platform detection and configuration."""
    
    PLATFORM_PATTERNS = {
        # AI/ML
        APIPlatform.OPENROUTER: [r"openrouter\.ai", r"api\.openrouter\.ai"],
        APIPlatform.OPENAI: [r"api\.openai\.com", r"openai\.com/api"],
        APIPlatform.ANTHROPIC: [r"api\.anthropic\.com", r"anthropic\.com"],
        APIPlatform.HUGGINGFACE: [r"huggingface\.co", r"api-inference\.huggingface\.co"],
        APIPlatform.REPLICATE: [r"api\.replicate\.com", r"replicate\.com"],
        APIPlatform.COHERE: [r"api\.cohere\.ai", r"cohere\.ai"],
        
        # Cloud
        APIPlatform.AWS: [r"amazonaws\.com", r"\.aws\.amazon\.com"],
        APIPlatform.AZURE: [r"azure\.com", r"\.azurewebsites\.net"],
        APIPlatform.GCP: [r"googleapis\.com", r"\.cloud\.google\.com"],
        APIPlatform.DIGITALOCEAN: [r"digitalocean\.com", r"\.do\.api"],
        APIPlatform.RENDER: [r"render\.com", r"\.onrender\.com"],
        APIPlatform.HEROKU: [r"herokuapp\.com", r"heroku\.com"],
        APIPlatform.VERCEL: [r"vercel\.app", r"vercel\.com"],
        APIPlatform.NETLIFY: [r"netlify\.app", r"netlify\.com"],
        
        # Databases
        APIPlatform.MONGODB: [r"mongodb\.net", r"mongodb\.com"],
        APIPlatform.FIREBASE: [r"firebaseio\.com", r"firebase\.google\.com"],
        APIPlatform.SUPABASE: [r"supabase\.co", r"supabase\.io"],
        APIPlatform.PLANETSCALE: [r"planetscale\.com", r"\.psdb\.cloud"],
        APIPlatform.AIRTABLE: [r"airtable\.com", r"api\.airtable\.com"],
        
        # Payment
        APIPlatform.STRIPE: [r"stripe\.com", r"api\.stripe\.com"],
        APIPlatform.PAYPAL: [r"paypal\.com", r"api\.paypal\.com"],
        APIPlatform.SQUARE: [r"squareup\.com", r"connect\.squareup\.com"],
        APIPlatform.SHOPIFY: [r"shopify\.com", r"\.myshopify\.com"],
        
        # Communication
        APIPlatform.TWILIO: [r"twilio\.com", r"api\.twilio\.com"],
        APIPlatform.SENDGRID: [r"sendgrid\.com", r"api\.sendgrid\.com"],
        APIPlatform.MAILGUN: [r"mailgun\.net", r"api\.mailgun\.net"],
        APIPlatform.SLACK: [r"slack\.com", r"api\.slack\.com"],
        APIPlatform.DISCORD: [r"discord\.com", r"discord\.gg"],
        
        # Social/Auth
        APIPlatform.GITHUB: [r"github\.com", r"api\.github\.com"],
        APIPlatform.GITLAB: [r"gitlab\.com", r"gitlab\.io"],
        APIPlatform.GOOGLE: [r"google\.com", r"accounts\.google\.com"],
        APIPlatform.FACEBOOK: [r"facebook\.com", r"graph\.facebook\.com"],
        APIPlatform.TWITTER: [r"twitter\.com", r"api\.twitter\.com"],
        APIPlatform.AUTH0: [r"auth0\.com", r"\.auth0\.com"],
    }
    
    @classmethod
    def detect_platform(cls, url: str) -> APIPlatform:
        """Detect API platform from URL."""
        url_lower = url.lower()
        
        for platform, patterns in cls.PLATFORM_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, url_lower):
                    return platform
        
        return APIPlatform.GENERIC
    
    @classmethod
    def get_auth_header_name(cls, platform: APIPlatform) -> str:
        """Get the authentication header name for platform."""
        auth_headers = {
            APIPlatform.OPENROUTER: "Authorization",
            APIPlatform.OPENAI: "Authorization",
            APIPlatform.ANTHROPIC: "x-api-key",
            APIPlatform.HUGGINGFACE: "Authorization",
            APIPlatform.STRIPE: "Authorization",
            APIPlatform.GITHUB: "Authorization",
            APIPlatform.FIREBASE: "Authorization",
            APIPlatform.AWS: "Authorization",
            APIPlatform.AZURE: "Ocp-Apim-Subscription-Key",
            APIPlatform.RENDER: "Authorization",
        }
        return auth_headers.get(platform, "Authorization")
    
    @classmethod
    def get_common_endpoints(cls, platform: APIPlatform) -> List[str]:
        """Get common endpoints for platform."""
        endpoints = {
            APIPlatform.OPENROUTER: [
                "/api/v1/chat/completions",
                "/api/v1/models",
                "/api/v1/auth/key",
            ],
            APIPlatform.OPENAI: [
                "/v1/chat/completions",
                "/v1/models",
                "/v1/embeddings",
                "/v1/images/generations",
            ],
            APIPlatform.STRIPE: [
                "/v1/customers",
                "/v1/charges",
                "/v1/payment_intents",
                "/v1/subscriptions",
            ],
            APIPlatform.GITHUB: [
                "/repos",
                "/users",
                "/orgs",
                "/gists",
            ],
            APIPlatform.RENDER: [
                "/v1/services",
                "/v1/deploys",
                "/v1/jobs",
            ],
        }
        return endpoints.get(platform, [])
    
    @classmethod
    def get_rate_limits(cls, platform: APIPlatform) -> Dict[str, int]:
        """Get rate limits for platform."""
        limits = {
            APIPlatform.OPENROUTER: {"requests_per_minute": 200, "requests_per_day": 20000},
            APIPlatform.OPENAI: {"requests_per_minute": 60, "requests_per_day": 10000},
            APIPlatform.GITHUB: {"requests_per_hour": 5000},
            APIPlatform.STRIPE: {"requests_per_second": 100},
            APIPlatform.TWITTER: {"requests_per_15min": 900},
            APIPlatform.DISCORD: {"requests_per_second": 50},
        }
        return limits.get(platform, {"requests_per_minute": 60})


class ErrorDatabase:
    """Comprehensive database of API errors from all major platforms."""
    
    # HTTP Status Code Errors
    HTTP_ERRORS = {
        400: {
            "name": "Bad Request",
            "description": "The request was malformed or contains invalid parameters",
            "common_causes": [
                "Invalid JSON syntax",
                "Missing required parameters",
                "Invalid parameter types",
                "Malformed request body",
            ],
            "remediation": [
                "Validate request body against API schema",
                "Check all required parameters are present",
                "Ensure correct data types for all fields",
                "Review API documentation for request format",
            ]
        },
        401: {
            "name": "Unauthorized",
            "description": "Authentication credentials are missing or invalid",
            "common_causes": [
                "Missing API key or token",
                "Expired authentication token",
                "Invalid API key format",
                "Revoked credentials",
            ],
            "remediation": [
                "Verify API key is correctly configured",
                "Check token hasn't expired",
                "Regenerate API credentials",
                "Ensure correct authentication header format",
            ]
        },
        403: {
            "name": "Forbidden",
            "description": "Valid credentials but insufficient permissions",
            "common_causes": [
                "Insufficient API permissions",
                "Account limitations or restrictions",
                "IP address blocked",
                "Resource access denied",
            ],
            "remediation": [
                "Verify account has necessary permissions",
                "Check API key scopes/roles",
                "Review IP whitelist settings",
                "Contact support for access issues",
            ]
        },
        404: {
            "name": "Not Found",
            "description": "The requested resource doesn't exist",
            "common_causes": [
                "Incorrect endpoint URL",
                "Resource ID doesn't exist",
                "API version mismatch",
                "Deleted or moved resource",
            ],
            "remediation": [
                "Verify endpoint URL is correct",
                "Check resource ID exists",
                "Ensure using correct API version",
                "Review API changelog for endpoint changes",
            ]
        },
        429: {
            "name": "Too Many Requests",
            "description": "Rate limit exceeded",
            "common_causes": [
                "Exceeded requests per second limit",
                "Exceeded requests per minute/hour limit",
                "Concurrent request limit reached",
                "Quota exhausted",
            ],
            "remediation": [
                "Implement exponential backoff",
                "Add rate limiting to client code",
                "Use Retry-After header value",
                "Upgrade API plan for higher limits",
            ]
        },
        500: {
            "name": "Internal Server Error",
            "description": "Server encountered an unexpected error",
            "common_causes": [
                "Server-side bug or exception",
                "Database connection failure",
                "Timeout processing request",
                "Resource exhaustion",
            ],
            "remediation": [
                "Retry request with exponential backoff",
                "Check API status page",
                "Report issue to API provider",
                "Implement fallback mechanisms",
            ]
        },
        502: {
            "name": "Bad Gateway",
            "description": "Invalid response from upstream server",
            "common_causes": [
                "API gateway timeout",
                "Backend service unavailable",
                "Network connectivity issues",
                "Load balancer problems",
            ],
            "remediation": [
                "Retry request after delay",
                "Check API status dashboard",
                "Implement circuit breaker pattern",
                "Use health check endpoints",
            ]
        },
        503: {
            "name": "Service Unavailable",
            "description": "Service is temporarily unavailable",
            "common_causes": [
                "Scheduled maintenance",
                "System overload",
                "Deployment in progress",
                "Emergency maintenance",
            ],
            "remediation": [
                "Check API status page",
                "Implement retry logic",
                "Use Retry-After header",
                "Subscribe to status notifications",
            ]
        },
    }
    
    # Platform-Specific Errors
    PLATFORM_ERRORS = {
        APIPlatform.OPENROUTER: {
            "invalid_model": {
                "code": "invalid_model",
                "message": "The model specified does not exist or is not available",
                "fix": "Use /api/v1/models endpoint to get list of available models"
            },
            "insufficient_credits": {
                "code": "insufficient_credits",
                "message": "Your account has insufficient credits",
                "fix": "Add credits to your OpenRouter account"
            },
            "model_overloaded": {
                "code": "model_overloaded",
                "message": "The requested model is currently overloaded",
                "fix": "Retry request or use alternative model"
            },
        },
        APIPlatform.OPENAI: {
            "context_length_exceeded": {
                "code": "context_length_exceeded",
                "message": "Request exceeds model's maximum context length",
                "fix": "Reduce input tokens or use model with larger context"
            },
            "invalid_api_key": {
                "code": "invalid_api_key",
                "message": "Incorrect API key provided",
                "fix": "Check API key at https://platform.openai.com/api-keys"
            },
            "rate_limit_exceeded": {
                "code": "rate_limit_exceeded",
                "message": "Rate limit exceeded for requests",
                "fix": "Implement exponential backoff or upgrade tier"
            },
        },
        APIPlatform.STRIPE: {
            "card_declined": {
                "code": "card_declined",
                "message": "The card has been declined",
                "fix": "Request customer to use different payment method"
            },
            "expired_card": {
                "code": "expired_card",
                "message": "The card has expired",
                "fix": "Request updated card information"
            },
            "insufficient_funds": {
                "code": "insufficient_funds",
                "message": "The card has insufficient funds",
                "fix": "Request alternative payment method"
            },
        },
        APIPlatform.GITHUB: {
            "rate_limit": {
                "code": "rate_limit",
                "message": "API rate limit exceeded",
                "fix": "Wait for rate limit reset or authenticate for higher limits"
            },
            "not_found": {
                "code": "not_found",
                "message": "Resource not found or requires authentication",
                "fix": "Verify resource exists and you have access"
            },
        },
        APIPlatform.RENDER: {
            "service_suspended": {
                "code": "service_suspended",
                "message": "Service has been suspended",
                "fix": "Check billing status and resume service"
            },
            "deploy_failed": {
                "code": "deploy_failed",
                "message": "Deployment failed",
                "fix": "Check build logs for errors"
            },
        },
        APIPlatform.AWS: {
            "InvalidSignature": {
                "code": "InvalidSignature",
                "message": "The request signature is invalid",
                "fix": "Verify AWS credentials and signing process"
            },
            "AccessDenied": {
                "code": "AccessDenied",
                "message": "Access denied for this operation",
                "fix": "Check IAM permissions and policies"
            },
        },
        APIPlatform.FIREBASE: {
            "permission_denied": {
                "code": "PERMISSION_DENIED",
                "message": "Client doesn't have permission to access resource",
                "fix": "Update Firebase Security Rules"
            },
            "unauthenticated": {
                "code": "UNAUTHENTICATED",
                "message": "Request doesn't have valid authentication credentials",
                "fix": "Add Firebase Authentication token"
            },
        },
    }
    
    @classmethod
    def get_error_info(cls, status_code: int, platform: APIPlatform, error_code: Optional[str] = None) -> Dict[str, Any]:
        """Get comprehensive error information."""
        error_info = {
            "status_code": status_code,
            "platform": platform.value,
            "http_error": cls.HTTP_ERRORS.get(status_code, {}),
            "platform_specific": {},
        }
        
        if error_code and platform in cls.PLATFORM_ERRORS:
            error_info["platform_specific"] = cls.PLATFORM_ERRORS[platform].get(error_code, {})
        
        return error_info
    
    @classmethod
    def get_all_errors_for_platform(cls, platform: APIPlatform) -> Dict[str, Any]:
        """Get all known errors for a platform."""
        return cls.PLATFORM_ERRORS.get(platform, {})
