# 🌐 WEB API REVERSE ENGINEERING TOOLKIT

**Authority Level:** 11.0
**Category:** Web Security / API Security
**Tools:** 11 Specialized Tools

---

## 🎯 PURPOSE

This toolkit enables you to **reverse engineer web APIs from websites and applications** including:
- Discovering hidden API endpoints
- Analyzing authentication mechanisms
- Decoding JWT tokens
- GraphQL schema introspection
- JavaScript deobfuscation to find API keys
- Intercepting HTTPS traffic
- WebSocket analysis
- Rate limit detection
- Swagger/OpenAPI discovery

**Perfect for:** Security assessments, bug bounties, penetration testing, and understanding undocumented APIs!

---

## 🛠️ TOOLS OVERVIEW

### 1. `prom_api_endpoint_discovery`
**Discover hidden API endpoints through intelligent fuzzing**

```python
prom_api_endpoint_discovery(
    base_url="https://api.target.com",
    wordlist="/path/to/wordlist.txt"  # Optional
)
```

**What it does:**
- Fuzzes common API paths (api, v1, v2, users, auth, etc.)
- Tests multiple HTTP methods (GET, POST, PUT, DELETE, OPTIONS)
- Returns discovered endpoints with status codes
- Identifies allowed methods

**Example Output:**
```json
{
  "base_url": "https://api.target.com",
  "endpoints_found": 15,
  "endpoints": [
    {
      "url": "https://api.target.com/api/v1/users",
      "method": "GET",
      "status_code": 200,
      "content_type": "application/json",
      "allows": "GET, POST, OPTIONS"
    }
  ]
}
```

---

### 2. `prom_api_parameter_fuzzer`
**Discover hidden API parameters**

```python
prom_api_parameter_fuzzer(
    endpoint="https://api.target.com/users",
    method="GET",
    common_params=True
)
```

**What it does:**
- Tests common parameter names (id, token, api_key, debug, admin, etc.)
- Compares responses to detect which parameters affect behavior
- Identifies hidden functionality

**Example Output:**
```json
{
  "endpoint": "https://api.target.com/users",
  "parameters_found": 3,
  "parameters": [
    {
      "parameter": "debug",
      "affects_response": true,
      "status_code": 200,
      "size_difference": 1245
    },
    {
      "parameter": "admin",
      "affects_response": true,
      "status_code": 403,
      "size_difference": -50
    }
  ]
}
```

---

### 3. `prom_graphql_introspection`
**Extract complete GraphQL schema**

```python
prom_graphql_introspection(
    graphql_endpoint="https://api.target.com/graphql"
)
```

**What it does:**
- Performs full GraphQL introspection query
- Extracts all types, queries, mutations, and subscriptions
- Reveals complete API schema
- Identifies deprecated fields

**Example Output:**
```json
{
  "status": "success",
  "introspection_enabled": true,
  "types_found": 25,
  "types": [
    {
      "name": "User",
      "kind": "OBJECT",
      "fields": ["id", "username", "email", "role", "createdAt"]
    },
    {
      "name": "AdminQuery",
      "kind": "OBJECT",
      "fields": ["getAllUsers", "deleteUser", "changeUserRole"]
    }
  ]
}
```

---

### 4. `prom_jwt_analyzer`
**Decode and analyze JWT tokens with security assessment**

```python
prom_jwt_analyzer(
    token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0..."
)
```

**What it does:**
- Decodes JWT header and payload
- Identifies algorithm weaknesses ('none', symmetric HS256)
- Checks expiration
- Detects sensitive data in token
- Analyzes security issues

**Example Output:**
```json
{
  "status": "success",
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "user123",
    "role": "admin",
    "exp": 1735689600
  },
  "algorithm": "HS256",
  "security_issues": [
    "WARNING: Symmetric algorithm - vulnerable to key guessing",
    "Token expires: 2025-01-01 00:00:00",
    "User has admin role"
  ]
}
```

---

### 5. `prom_swagger_discovery`
**Find Swagger/OpenAPI documentation**

```python
prom_swagger_discovery(
    base_url="https://api.target.com"
)
```

**What it does:**
- Tests common Swagger/OpenAPI paths
- Parses JSON/YAML documentation
- Extracts all documented endpoints
- Returns complete API specification

**Common paths checked:**
- `/swagger.json`
- `/swagger.yaml`
- `/api-docs`
- `/openapi.json`
- `/v1/swagger.json`
- `/docs`

---

### 6. `prom_mitmproxy_setup`
**Setup HTTPS traffic interception with mitmproxy**

```python
prom_mitmproxy_setup(
    target_host="api.target.com",
    port=8080
)
```

**What it does:**
- Provides setup instructions for mitmproxy
- Generates automated capture commands
- Enables HTTPS decryption
- Captures all API traffic

**Output includes:**
- Installation steps
- Proxy configuration
- CA certificate setup
- Automated capture commands

---

### 7. `prom_javascript_deobfuscate`
**Deobfuscate JavaScript and extract API endpoints/keys**

```python
prom_javascript_deobfuscate(
    js_code="""var _0x1234=['aHR0cHM6Ly9hcGku..."""
)
```

**What it does:**
- Detects obfuscation techniques (eval, hex encoding, base64)
- Extracts URLs and API endpoints
- Finds hardcoded API keys and secrets
- Decodes hex and unicode strings

**Example Output:**
```json
{
  "obfuscation_indicators": [
    "eval() function detected",
    "Hex/Unicode encoding detected"
  ],
  "extracted_urls": [
    "https://api.target.com/v1/users",
    "https://api.target.com/auth/login"
  ],
  "extracted_api_endpoints": [
    "/api/v1/users",
    "/api/v1/admin"
  ],
  "suspicious_patterns": [
    "sk_live_abc123def456",
    "Bearer eyJhbGciOiJIUzI1NiIs..."
  ],
  "deobfuscated_code": "..."
}
```

---

### 8. `prom_websocket_interceptor`
**Setup WebSocket traffic interception**

```python
prom_websocket_interceptor(
    ws_url="wss://api.target.com/socket"
)
```

**What it does:**
- Provides WebSocket interception setup
- Generates Python example code
- Lists compatible tools (wscat, wsdump)
- Enables real-time message capture

---

### 9. `prom_api_rate_limit_detect`
**Detect API rate limiting behavior**

```python
prom_api_rate_limit_detect(
    endpoint="https://api.target.com/users",
    requests_count=100
)
```

**What it does:**
- Sends multiple requests to detect rate limits
- Identifies 429 (Too Many Requests) threshold
- Extracts rate limit headers
- Measures response times

**Example Output:**
```json
{
  "endpoint": "https://api.target.com/users",
  "total_requests": 50,
  "rate_limited": true,
  "rate_limit_threshold": 50,
  "results": [
    {
      "request_number": 50,
      "status_code": 429,
      "rate_limit_headers": {
        "X-RateLimit-Limit": "50",
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Reset": "1609459200",
        "Retry-After": "3600"
      }
    }
  ]
}
```

---

### 10. `prom_api_auth_analyzer`
**Analyze API authentication mechanisms**

```python
prom_api_auth_analyzer(
    endpoint="https://api.target.com/users"
)
```

**What it does:**
- Tests for WWW-Authenticate headers
- Identifies auth header requirements
- Detects OAuth/Bearer token usage
- Tests API key in query parameters

**Example Output:**
```json
{
  "endpoint": "https://api.target.com/users",
  "status_without_auth": 401,
  "requires_auth": true,
  "auth_mechanisms_detected": 2,
  "mechanisms": [
    {
      "type": "WWW-Authenticate",
      "value": "Bearer realm=\"api\"",
      "schemes": ["Bearer"]
    },
    {
      "type": "Header-based",
      "header": "X-API-Key",
      "affects_response": true
    }
  ]
}
```

---

### 11. `prom_api_response_differ`
**Compare API responses with different values**

```python
prom_api_response_differ(
    endpoint="https://api.target.com/user",
    param="id",
    values=["1", "2", "admin", "-1", "999999"]
)
```

**What it does:**
- Tests parameter with multiple values
- Compares response sizes and content
- Identifies unique responses
- Detects special values (admin, -1, etc.)

---

## 🚀 REAL-WORLD EXAMPLES

### Example 1: Complete API Reconnaissance

```python
# Step 1: Discover API documentation
docs = prom_swagger_discovery(base_url="https://api.target.com")

# Step 2: Discover hidden endpoints
endpoints = prom_api_endpoint_discovery(base_url="https://api.target.com")

# Step 3: Fuzz each endpoint for hidden parameters
for endpoint in endpoints['endpoints']:
    params = prom_api_parameter_fuzzer(
        endpoint=endpoint['url'],
        method=endpoint['method']
    )

# Step 4: Analyze authentication
auth = prom_api_auth_analyzer(endpoint="https://api.target.com/users")
```

---

### Example 2: GraphQL API Analysis

```python
# Introspect GraphQL schema
schema = prom_graphql_introspection(
    graphql_endpoint="https://api.target.com/graphql"
)

# Analyze types and find admin queries
for type_def in schema['types']:
    if 'admin' in type_def['name'].lower():
        print(f"Admin type found: {type_def}")
```

---

### Example 3: JWT Token Exploitation

```python
# Intercept JWT token from traffic
jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Analyze token
analysis = prom_jwt_analyzer(token=jwt_token)

# Check for vulnerabilities
if "CRITICAL" in str(analysis['security_issues']):
    print("Token has critical vulnerabilities!")
    print(analysis['payload'])  # See what data is exposed
```

---

### Example 4: Extract API Keys from JavaScript

```python
# Get obfuscated JavaScript from website
js_code = """
var _0x1234=['aHR0cHM6Ly9hcGkudGFyZ2V0LmNvbQ==','c2tfbGl2ZV9hYmMxMjM='];
eval(atob(_0x1234[0]));
"""

# Deobfuscate and extract secrets
result = prom_javascript_deobfuscate(js_code=js_code)

print("API Keys found:", result['suspicious_patterns'])
print("Endpoints found:", result['extracted_api_endpoints'])
```

---

### Example 5: Rate Limit Testing

```python
# Test rate limits
limits = prom_api_rate_limit_detect(
    endpoint="https://api.target.com/search",
    requests_count=200
)

if limits['rate_limited']:
    print(f"Rate limit: {limits['rate_limit_threshold']} requests")
    print(f"Reset time: {limits['results'][-1]['rate_limit_headers']['X-RateLimit-Reset']}")
```

---

## 📋 DEPENDENCIES

Install required packages:

```bash
pip install requests pyjwt beautifulsoup4 websocket-client --break-system-packages
```

**Optional tools:**
- **mitmproxy** - HTTPS interception: `pip install mitmproxy`
- **wscat** - WebSocket testing: `npm install -g wscat`

---

## ⚠️ AUTHORIZATION REQUIRED

**CRITICAL:** Web API reverse engineering must only be performed on:
- ✅ Your own applications
- ✅ Authorized penetration testing engagements
- ✅ Bug bounty programs with explicit scope
- ✅ Security research with permission

**Unauthorized API access is illegal** under computer fraud laws worldwide.

---

## 💡 PRO TIPS

### Finding Hidden Admin Endpoints
```python
# Many APIs expose admin endpoints with predictable names
endpoints = prom_api_endpoint_discovery(base_url="https://api.target.com")

admin_endpoints = [
    e for e in endpoints['endpoints']
    if 'admin' in e['url'].lower()
]
```

### GraphQL Over-Introspection
```python
# Check if introspection is enabled (security risk)
schema = prom_graphql_introspection(graphql_endpoint="...")

if schema['introspection_enabled']:
    print("WARNING: Introspection enabled - full schema exposed!")
```

### JWT Algorithm Confusion
```python
# Check if JWT uses weak 'none' algorithm
analysis = prom_jwt_analyzer(token="...")

if analysis['algorithm'] == 'none':
    print("CRITICAL: Token can be forged without signature!")
```

---

**PROMETHEUS PRIME - WEB API REVERSE ENGINEERING TOOLKIT**
**Authority Level: 11.0**
**Status: FULLY OPERATIONAL** ✅
