"""
PROMETHEUS PRIME - WEB API REVERSE ENGINEERING TOOLKIT
Authority Level: 11.0
Status: OPERATIONAL

Comprehensive toolkit for reverse engineering web APIs, REST endpoints, GraphQL,
WebSockets, and discovering hidden API functionality.
"""

import subprocess
import requests
import json
import re
import base64
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, parse_qs, urljoin
import jwt as pyjwt
from datetime import datetime


class WebAPIReverseEngineering:
    """Complete web API reverse engineering toolkit."""

    def __init__(self):
        self.session = requests.Session()
        self.discovered_endpoints = []

    def api_endpoint_discovery(self, base_url: str, wordlist: Optional[str] = None) -> Dict[str, Any]:
        """
        Discover API endpoints through intelligent fuzzing.

        Args:
            base_url: Base URL to scan
            wordlist: Custom wordlist file (optional)

        Returns:
            Discovered endpoints with methods
        """
        endpoints = []

        # Common API paths
        common_paths = [
            'api', 'v1', 'v2', 'v3', 'rest', 'graphql',
            'api/v1', 'api/v2', 'api/v3',
            'users', 'auth', 'login', 'register', 'admin',
            'data', 'settings', 'config', 'status', 'health',
            'search', 'query', 'posts', 'comments', 'messages',
            'upload', 'download', 'files', 'images',
            'payment', 'checkout', 'orders', 'products',
            'webhook', 'callback', 'notifications'
        ]

        # Load custom wordlist if provided
        if wordlist:
            try:
                with open(wordlist, 'r') as f:
                    common_paths.extend([line.strip() for line in f if line.strip()])
            except:
                pass

        for path in common_paths:
            test_url = urljoin(base_url, path)

            # Test multiple HTTP methods
            for method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']:
                try:
                    if method == 'GET':
                        response = self.session.get(test_url, timeout=5, verify=False)
                    elif method == 'POST':
                        response = self.session.post(test_url, timeout=5, verify=False)
                    elif method == 'OPTIONS':
                        response = self.session.options(test_url, timeout=5, verify=False)
                    else:
                        continue

                    if response.status_code < 500:  # Endpoint exists
                        endpoints.append({
                            'url': test_url,
                            'method': method,
                            'status_code': response.status_code,
                            'content_type': response.headers.get('Content-Type', 'unknown'),
                            'size': len(response.content),
                            'allows': response.headers.get('Allow', 'unknown')
                        })

                except:
                    continue

        self.discovered_endpoints = endpoints

        return {
            'base_url': base_url,
            'endpoints_found': len(endpoints),
            'endpoints': endpoints
        }

    def api_parameter_fuzzer(self, endpoint: str, method: str = 'GET',
                            common_params: bool = True) -> Dict[str, Any]:
        """
        Fuzz API endpoint to discover hidden parameters.

        Args:
            endpoint: API endpoint URL
            method: HTTP method
            common_params: Use common parameter names

        Returns:
            Discovered parameters and their behaviors
        """
        discovered_params = []

        # Common API parameter names
        param_names = [
            'id', 'user_id', 'token', 'api_key', 'key', 'secret',
            'page', 'limit', 'offset', 'count', 'per_page',
            'sort', 'order', 'filter', 'search', 'q', 'query',
            'format', 'type', 'callback', 'jsonp',
            'debug', 'verbose', 'test', 'admin',
            'lang', 'locale', 'timestamp', 'version'
        ]

        # Test each parameter
        for param in param_names:
            try:
                # Baseline request
                baseline = requests.get(endpoint, timeout=5, verify=False)

                # Request with parameter
                test_params = {param: 'test'}
                test_response = requests.get(endpoint, params=test_params, timeout=5, verify=False)

                # Compare responses
                if test_response.content != baseline.content:
                    discovered_params.append({
                        'parameter': param,
                        'affects_response': True,
                        'status_code': test_response.status_code,
                        'size_difference': len(test_response.content) - len(baseline.content)
                    })

            except:
                continue

        return {
            'endpoint': endpoint,
            'method': method,
            'parameters_found': len(discovered_params),
            'parameters': discovered_params
        }

    def graphql_introspection(self, graphql_endpoint: str) -> Dict[str, Any]:
        """
        Perform GraphQL introspection to discover schema.

        Args:
            graphql_endpoint: GraphQL endpoint URL

        Returns:
            Complete GraphQL schema
        """
        introspection_query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    ...FullType
                }
                directives {
                    name
                    description
                    locations
                    args {
                        ...InputValue
                    }
                }
            }
        }

        fragment FullType on __Type {
            kind
            name
            description
            fields(includeDeprecated: true) {
                name
                description
                args {
                    ...InputValue
                }
                type {
                    ...TypeRef
                }
                isDeprecated
                deprecationReason
            }
            inputFields {
                ...InputValue
            }
            interfaces {
                ...TypeRef
            }
            enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
            }
            possibleTypes {
                ...TypeRef
            }
        }

        fragment InputValue on __InputValue {
            name
            description
            type { ...TypeRef }
            defaultValue
        }

        fragment TypeRef on __Type {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                            }
                        }
                    }
                }
            }
        }
        """

        try:
            response = requests.post(
                graphql_endpoint,
                json={'query': introspection_query},
                headers={'Content-Type': 'application/json'},
                timeout=10,
                verify=False
            )

            if response.status_code == 200:
                schema = response.json()

                # Extract useful information
                types = []
                queries = []
                mutations = []

                if 'data' in schema and '__schema' in schema['data']:
                    schema_data = schema['data']['__schema']

                    for type_def in schema_data.get('types', []):
                        if not type_def['name'].startswith('__'):
                            types.append({
                                'name': type_def['name'],
                                'kind': type_def['kind'],
                                'description': type_def.get('description'),
                                'fields': [f['name'] for f in type_def.get('fields', [])]
                            })

                return {
                    'status': 'success',
                    'endpoint': graphql_endpoint,
                    'introspection_enabled': True,
                    'types_found': len(types),
                    'types': types,
                    'full_schema': schema
                }
            else:
                return {
                    'status': 'failed',
                    'endpoint': graphql_endpoint,
                    'introspection_enabled': False,
                    'error': f"Status code: {response.status_code}"
                }

        except Exception as e:
            return {'error': str(e)}

    def jwt_token_analyzer(self, token: str) -> Dict[str, Any]:
        """
        Analyze and decode JWT tokens.

        Args:
            token: JWT token string

        Returns:
            Decoded token with security analysis
        """
        try:
            # Decode without verification to see contents
            header = pyjwt.get_unverified_header(token)
            payload = pyjwt.decode(token, options={"verify_signature": False})

            # Analyze security
            security_issues = []

            # Check algorithm
            if header.get('alg') == 'none':
                security_issues.append("CRITICAL: 'none' algorithm - token can be forged!")
            elif header.get('alg') in ['HS256', 'HS384', 'HS512']:
                security_issues.append("WARNING: Symmetric algorithm - vulnerable to key guessing")

            # Check expiration
            if 'exp' in payload:
                exp_timestamp = payload['exp']
                exp_datetime = datetime.fromtimestamp(exp_timestamp)
                if datetime.now() > exp_datetime:
                    security_issues.append("Token is EXPIRED")
                else:
                    security_issues.append(f"Token expires: {exp_datetime}")
            else:
                security_issues.append("WARNING: No expiration set - token never expires")

            # Extract sensitive data
            sensitive_keys = ['password', 'secret', 'api_key', 'private_key']
            sensitive_found = [k for k in payload.keys() if any(s in k.lower() for s in sensitive_keys)]

            if sensitive_found:
                security_issues.append(f"CRITICAL: Sensitive data in token: {sensitive_found}")

            return {
                'status': 'success',
                'header': header,
                'payload': payload,
                'algorithm': header.get('alg'),
                'security_issues': security_issues,
                'token_parts': token.split('.')
            }

        except Exception as e:
            return {'error': f"Invalid JWT token: {str(e)}"}

    def swagger_openapi_discovery(self, base_url: str) -> Dict[str, Any]:
        """
        Discover Swagger/OpenAPI documentation.

        Args:
            base_url: Base URL to scan

        Returns:
            Found API documentation
        """
        common_swagger_paths = [
            '/swagger.json',
            '/swagger.yaml',
            '/swagger-ui.html',
            '/api-docs',
            '/api/swagger.json',
            '/api/swagger.yaml',
            '/v1/swagger.json',
            '/v2/swagger.json',
            '/v3/swagger.json',
            '/openapi.json',
            '/openapi.yaml',
            '/api/openapi.json',
            '/docs',
            '/redoc',
            '/__swagger__',
            '/swagger/v1/swagger.json'
        ]

        found_docs = []

        for path in common_swagger_paths:
            test_url = urljoin(base_url, path)

            try:
                response = requests.get(test_url, timeout=5, verify=False)

                if response.status_code == 200:
                    # Try to parse as JSON
                    try:
                        doc_data = response.json()

                        found_docs.append({
                            'url': test_url,
                            'type': 'swagger/openapi',
                            'version': doc_data.get('swagger') or doc_data.get('openapi'),
                            'endpoints': len(doc_data.get('paths', {})),
                            'content': doc_data
                        })
                    except:
                        # Might be YAML or HTML
                        found_docs.append({
                            'url': test_url,
                            'type': 'documentation',
                            'size': len(response.content),
                            'content_type': response.headers.get('Content-Type')
                        })

            except:
                continue

        return {
            'base_url': base_url,
            'documentation_found': len(found_docs),
            'documents': found_docs
        }

    def mitmproxy_intercept(self, target_host: str, port: int = 8080) -> Dict[str, Any]:
        """
        Setup mitmproxy for traffic interception.

        Args:
            target_host: Target host to intercept
            port: Proxy port

        Returns:
            Proxy setup instructions
        """
        return {
            'status': 'info',
            'message': 'mitmproxy setup instructions',
            'steps': [
                f"1. Install mitmproxy: pip install mitmproxy",
                f"2. Start proxy: mitmproxy -p {port}",
                f"3. Configure browser/app to use proxy: 127.0.0.1:{port}",
                f"4. Install mitmproxy CA certificate for HTTPS",
                f"5. Browse to {target_host} to capture traffic",
                "6. Use 'mitmdump' for automated capture",
                "7. Use 'mitmweb' for web-based interface"
            ],
            'automated_command': f"mitmdump -p {port} -w capture.mitm --set flow_detail=3"
        }

    def javascript_deobfuscate(self, js_code: str) -> Dict[str, Any]:
        """
        Attempt to deobfuscate JavaScript code.

        Args:
            js_code: Obfuscated JavaScript code

        Returns:
            Deobfuscated code and analysis
        """
        analysis = {
            'original_length': len(js_code),
            'obfuscation_indicators': [],
            'extracted_urls': [],
            'extracted_api_endpoints': [],
            'suspicious_patterns': []
        }

        # Detect obfuscation patterns
        if 'eval(' in js_code:
            analysis['obfuscation_indicators'].append('eval() function detected')
        if '\\x' in js_code or '\\u' in js_code:
            analysis['obfuscation_indicators'].append('Hex/Unicode encoding detected')
        if 'atob(' in js_code or 'btoa(' in js_code:
            analysis['obfuscation_indicators'].append('Base64 encoding detected')

        # Extract URLs
        url_pattern = r'https?://[^\s\'"<>]+'
        urls = re.findall(url_pattern, js_code)
        analysis['extracted_urls'] = list(set(urls))

        # Extract potential API endpoints
        api_pattern = r'["\']/(api|v\d+)/[^"\']*["\']'
        endpoints = re.findall(api_pattern, js_code)
        analysis['extracted_api_endpoints'] = list(set(endpoints))

        # Look for API keys (common patterns)
        api_key_patterns = [
            r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'secret["\']?\s*[:=]\s*["\']([^"\']+)["\']'
        ]

        for pattern in api_key_patterns:
            matches = re.findall(pattern, js_code, re.IGNORECASE)
            if matches:
                analysis['suspicious_patterns'].extend(matches)

        # Basic deobfuscation attempts
        deobfuscated = js_code

        # Decode hex strings
        hex_pattern = r'\\x([0-9a-fA-F]{2})'
        hex_matches = re.findall(hex_pattern, deobfuscated)
        for hex_code in hex_matches:
            try:
                char = chr(int(hex_code, 16))
                deobfuscated = deobfuscated.replace(f'\\x{hex_code}', char)
            except:
                pass

        analysis['deobfuscated_code'] = deobfuscated
        analysis['deobfuscation_successful'] = len(analysis['obfuscation_indicators']) > 0

        return analysis

    def websocket_interceptor(self, ws_url: str) -> Dict[str, Any]:
        """
        Intercept and analyze WebSocket traffic.

        Args:
            ws_url: WebSocket URL

        Returns:
            WebSocket analysis setup
        """
        return {
            'status': 'info',
            'websocket_url': ws_url,
            'message': 'WebSocket interception setup',
            'tools': [
                {
                    'name': 'wscat',
                    'install': 'npm install -g wscat',
                    'usage': f'wscat -c {ws_url}'
                },
                {
                    'name': 'wsdump',
                    'install': 'pip install websocket-client',
                    'usage': f'wsdump {ws_url}'
                },
                {
                    'name': 'burp_suite',
                    'description': 'Use Burp Suite WebSocket history'
                }
            ],
            'python_example': f'''
import websocket

def on_message(ws, message):
    print(f"Received: {{message}}")

def on_error(ws, error):
    print(f"Error: {{error}}")

def on_close(ws, close_status_code, close_msg):
    print("Connection closed")

def on_open(ws):
    print("Connection opened")

ws = websocket.WebSocketApp("{ws_url}",
                            on_message=on_message,
                            on_error=on_error,
                            on_close=on_close)
ws.on_open = on_open
ws.run_forever()
'''
        }

    def api_rate_limit_detector(self, endpoint: str, requests_count: int = 100) -> Dict[str, Any]:
        """
        Detect API rate limiting behavior.

        Args:
            endpoint: API endpoint to test
            requests_count: Number of requests to send

        Returns:
            Rate limit analysis
        """
        results = []
        rate_limited = False
        rate_limit_threshold = None

        for i in range(requests_count):
            try:
                start_time = datetime.now()
                response = requests.get(endpoint, timeout=5, verify=False)
                end_time = datetime.now()

                response_time = (end_time - start_time).total_seconds()

                results.append({
                    'request_number': i + 1,
                    'status_code': response.status_code,
                    'response_time': response_time,
                    'rate_limit_headers': {
                        'X-RateLimit-Limit': response.headers.get('X-RateLimit-Limit'),
                        'X-RateLimit-Remaining': response.headers.get('X-RateLimit-Remaining'),
                        'X-RateLimit-Reset': response.headers.get('X-RateLimit-Reset'),
                        'Retry-After': response.headers.get('Retry-After')
                    }
                })

                # Detect rate limiting
                if response.status_code == 429:  # Too Many Requests
                    rate_limited = True
                    rate_limit_threshold = i + 1
                    break

            except Exception as e:
                results.append({
                    'request_number': i + 1,
                    'error': str(e)
                })

        return {
            'endpoint': endpoint,
            'total_requests': len(results),
            'rate_limited': rate_limited,
            'rate_limit_threshold': rate_limit_threshold,
            'results': results[-10:]  # Last 10 requests
        }

    def api_authentication_analyzer(self, endpoint: str) -> Dict[str, Any]:
        """
        Analyze API authentication mechanisms.

        Args:
            endpoint: API endpoint

        Returns:
            Authentication analysis
        """
        auth_mechanisms = []

        # Test without authentication
        try:
            response = requests.get(endpoint, timeout=5, verify=False)

            # Check response headers for auth hints
            www_auth = response.headers.get('WWW-Authenticate')
            if www_auth:
                auth_mechanisms.append({
                    'type': 'WWW-Authenticate',
                    'value': www_auth,
                    'schemes': www_auth.split(',')
                })

            # Check for common auth headers in request
            common_auth_headers = [
                'Authorization',
                'X-API-Key',
                'X-Auth-Token',
                'API-Key',
                'Access-Token',
                'X-Access-Token'
            ]

            for header in common_auth_headers:
                test_headers = {header: 'test_value'}
                test_response = requests.get(endpoint, headers=test_headers, timeout=5, verify=False)

                if test_response.status_code != response.status_code:
                    auth_mechanisms.append({
                        'type': 'Header-based',
                        'header': header,
                        'affects_response': True
                    })

            # Check for OAuth indicators
            if 'oauth' in response.text.lower() or 'bearer' in response.headers.get('WWW-Authenticate', '').lower():
                auth_mechanisms.append({
                    'type': 'OAuth/Bearer Token',
                    'indicators': 'OAuth keywords found'
                })

            # Check for API key in query params
            test_params = {'api_key': 'test', 'apikey': 'test', 'key': 'test'}
            param_response = requests.get(endpoint, params=test_params, timeout=5, verify=False)

            if param_response.status_code != response.status_code:
                auth_mechanisms.append({
                    'type': 'Query Parameter',
                    'likely_param': 'api_key or key'
                })

            return {
                'endpoint': endpoint,
                'status_without_auth': response.status_code,
                'auth_mechanisms_detected': len(auth_mechanisms),
                'mechanisms': auth_mechanisms,
                'requires_auth': response.status_code in [401, 403]
            }

        except Exception as e:
            return {'error': str(e)}

    def api_response_differ(self, endpoint: str, param: str, values: List[str]) -> Dict[str, Any]:
        """
        Compare API responses with different parameter values.

        Args:
            endpoint: API endpoint
            param: Parameter to test
            values: List of values to test

        Returns:
            Response differences
        """
        responses = []

        for value in values:
            try:
                params = {param: value}
                response = requests.get(endpoint, params=params, timeout=5, verify=False)

                responses.append({
                    'value': value,
                    'status_code': response.status_code,
                    'size': len(response.content),
                    'content_type': response.headers.get('Content-Type'),
                    'response_hash': hash(response.content)
                })
            except Exception as e:
                responses.append({
                    'value': value,
                    'error': str(e)
                })

        # Detect unique responses
        unique_hashes = set(r.get('response_hash') for r in responses if 'response_hash' in r)

        return {
            'endpoint': endpoint,
            'parameter': param,
            'values_tested': len(values),
            'unique_responses': len(unique_hashes),
            'responses': responses
        }


# Example usage
if __name__ == "__main__":
    toolkit = WebAPIReverseEngineering()

    # Test API endpoint discovery
    print("=== API Endpoint Discovery ===")
    result = toolkit.api_endpoint_discovery("https://api.example.com")
    print(json.dumps(result, indent=2))

    # Test JWT analysis
    print("\n=== JWT Token Analysis ===")
    sample_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = toolkit.jwt_token_analyzer(sample_token)
    print(json.dumps(result, indent=2))
