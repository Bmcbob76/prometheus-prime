#!/usr/bin/env python3
"""
🔥 GS343 PHOENIX HEALING GATEWAY
Auto-recovery, fallbacks, retry logic, and intelligent error handling
Authority Level: 11.0

Provides Phoenix-style healing for all Prometheus Prime OSINT operations
"""

import time
import functools
from typing import Callable, Any, Dict, List, Optional
from datetime import datetime
import traceback


class GS343Gateway:
    """Phoenix healing patterns for auto-recovery and intelligent fallbacks"""
    
    def __init__(self):
        self.healing_history = []
        self.retry_config = {
            'max_retries': 3,
            'backoff_base': 2,
            'backoff_max': 30,
            'retry_on': [
                'timeout', 'connection', 'rate_limit', '429', '503', '504'
            ]
        }
        
        # Fallback chains
        self.fallback_chains = {
            'phone_lookup': ['twilio', 'numverify', 'opencnam'],
            'domain_whois': ['whoisxml', 'whois_api', 'dns_lookup'],
            'email_breach': ['hibp', 'dehashed', 'leakcheck'],
            'ip_geolocation': ['ipapi', 'ipgeolocation', 'ipinfo']
        }
        
        print("🔥 GS343 Phoenix Healing Gateway initialized")
    
    def heal_phoenix(self, error: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze error and provide healing suggestions
        
        Args:
            error: Error message
            context: Operation context (module, target, etc.)
            
        Returns:
            Healing recommendations and recovery actions
        """
        healing = {
            'error': error,
            'context': context,
            'timestamp': datetime.now().isoformat(),
            'analysis': self._analyze_error(error),
            'suggestions': [],
            'fallbacks': [],
            'auto_actions': []
        }
        
        # Analyze error type
        error_lower = error.lower()
        
        # API key errors
        if 'api key' in error_lower or 'unauthorized' in error_lower or '401' in error:
            healing['suggestions'].append('Check API key configuration in .env')
            healing['suggestions'].append('Verify key is valid and not expired')
            healing['fallbacks'] = self._get_fallback_apis(context.get('module'))
            healing['auto_actions'].append('try_fallback_api')
        
        # Rate limiting
        elif 'rate limit' in error_lower or '429' in error:
            healing['suggestions'].append('API rate limit exceeded')
            healing['suggestions'].append(f'Wait {self.retry_config["backoff_max"]} seconds before retry')
            healing['auto_actions'].append('exponential_backoff')
            healing['auto_actions'].append('try_fallback_api')
        
        # Timeout errors
        elif 'timeout' in error_lower or 'timed out' in error_lower:
            healing['suggestions'].append('Increase timeout duration')
            healing['suggestions'].append('Check network connectivity')
            healing['auto_actions'].append('retry_with_longer_timeout')
        
        # Connection errors
        elif 'connection' in error_lower or 'network' in error_lower:
            healing['suggestions'].append('Check internet connection')
            healing['suggestions'].append('Verify API endpoint is accessible')
            healing['auto_actions'].append('retry_with_backoff')
            healing['fallbacks'] = self._get_fallback_apis(context.get('module'))
        
        # Not found errors
        elif '404' in error or 'not found' in error_lower:
            healing['suggestions'].append('Target not found in database')
            healing['suggestions'].append('Try alternative spelling or format')
            healing['auto_actions'].append('try_alternative_format')
        
        # Invalid input
        elif 'invalid' in error_lower or 'bad request' in error_lower:
            healing['suggestions'].append('Validate input format')
            healing['suggestions'].append('Check parameter requirements')
            healing['auto_actions'].append('sanitize_input')
        
        # Log healing attempt
        self.healing_history.append(healing)
        
        return healing
    
    def _analyze_error(self, error: str) -> Dict[str, Any]:
        """Analyze error and categorize"""
        analysis = {
            'severity': 'medium',
            'category': 'unknown',
            'recoverable': True,
            'requires_intervention': False
        }
        
        error_lower = error.lower()
        
        # Categorize
        if 'api key' in error_lower or '401' in error:
            analysis['category'] = 'authentication'
            analysis['severity'] = 'high'
            analysis['requires_intervention'] = True
        elif 'rate limit' in error_lower or '429' in error:
            analysis['category'] = 'rate_limit'
            analysis['severity'] = 'low'
        elif 'timeout' in error_lower:
            analysis['category'] = 'timeout'
            analysis['severity'] = 'medium'
        elif 'connection' in error_lower:
            analysis['category'] = 'network'
            analysis['severity'] = 'medium'
        elif '404' in error:
            analysis['category'] = 'not_found'
            analysis['severity'] = 'low'
            analysis['recoverable'] = False
        
        return analysis
    
    def _get_fallback_apis(self, module: Optional[str]) -> List[str]:
        """Get fallback API chain for a module"""
        if module in self.fallback_chains:
            return self.fallback_chains[module]
        return []
    
    def with_retry(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute function with automatic retry logic
        
        Args:
            func: Function to execute
            *args, **kwargs: Function arguments
            
        Returns:
            Function result or raises exception after max retries
        """
        max_retries = kwargs.pop('max_retries', self.retry_config['max_retries'])
        backoff_base = kwargs.pop('backoff_base', self.retry_config['backoff_base'])
        
        last_error = None
        
        for attempt in range(max_retries):
            try:
                return func(*args, **kwargs)
            
            except Exception as e:
                last_error = e
                error_str = str(e)
                
                # Check if we should retry
                should_retry = any(
                    keyword in error_str.lower() 
                    for keyword in self.retry_config['retry_on']
                )
                
                if not should_retry or attempt == max_retries - 1:
                    raise
                
                # Calculate backoff
                backoff = min(
                    backoff_base ** attempt,
                    self.retry_config['backoff_max']
                )
                
                print(f"⚠️ Retry {attempt + 1}/{max_retries} after {backoff}s: {error_str[:100]}")
                time.sleep(backoff)
        
        raise last_error
    
    def retry_decorator(self, max_retries: int = 3, backoff_base: int = 2):
        """
        Decorator for automatic retry with exponential backoff
        
        Usage:
            @gs343.retry_decorator(max_retries=3)
            def my_api_call():
                ...
        """
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                return self.with_retry(
                    func, *args, 
                    max_retries=max_retries,
                    backoff_base=backoff_base,
                    **kwargs
                )
            return wrapper
        return decorator
    
    def with_fallback(self, primary_func: Callable, fallback_func: Callable, 
                      *args, **kwargs) -> Any:
        """
        Execute primary function with fallback on failure
        
        Args:
            primary_func: Primary function to try
            fallback_func: Fallback function if primary fails
            *args, **kwargs: Function arguments
            
        Returns:
            Result from either primary or fallback
        """
        try:
            return primary_func(*args, **kwargs)
        except Exception as e:
            print(f"⚠️ Primary failed: {str(e)[:100]}")
            print(f"🔄 Trying fallback...")
            return fallback_func(*args, **kwargs)
    
    def chain_fallbacks(self, functions: List[Callable], *args, **kwargs) -> Any:
        """
        Try functions in sequence until one succeeds
        
        Args:
            functions: List of functions to try
            *args, **kwargs: Function arguments
            
        Returns:
            Result from first successful function
        """
        errors = []
        
        for i, func in enumerate(functions):
            try:
                result = func(*args, **kwargs)
                if i > 0:
                    print(f"✅ Fallback {i} succeeded")
                return result
            
            except Exception as e:
                errors.append({'function': func.__name__, 'error': str(e)})
                if i < len(functions) - 1:
                    print(f"⚠️ {func.__name__} failed, trying next...")
        
        # All failed
        raise Exception(f"All fallbacks exhausted: {errors}")
    
    def get_healing_stats(self) -> Dict[str, Any]:
        """Get healing statistics"""
        total = len(self.healing_history)
        
        if total == 0:
            return {
                'total_healings': 0,
                'categories': {},
                'success_rate': 0
            }
        
        # Categorize
        categories = {}
        for healing in self.healing_history:
            category = healing['analysis']['category']
            categories[category] = categories.get(category, 0) + 1
        
        return {
            'total_healings': total,
            'categories': categories,
            'recent_healings': self.healing_history[-10:]  # Last 10
        }
    
    def clear_history(self):
        """Clear healing history"""
        self.healing_history.clear()


# Singleton instance
gs343 = GS343Gateway()


# Convenience decorators
def with_phoenix_retry(max_retries: int = 3):
    """Decorator for automatic Phoenix retry"""
    return gs343.retry_decorator(max_retries=max_retries)


def with_phoenix_healing(module: str):
    """
    Decorator that provides automatic Phoenix healing on errors
    
    Usage:
        @with_phoenix_healing('phone_intel')
        def lookup_phone(number):
            ...
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                healing = gs343.heal_phoenix(
                    error=str(e),
                    context={
                        'module': module,
                        'function': func.__name__,
                        'args': str(args)[:100]
                    }
                )
                
                # Log healing
                print(f"🔥 Phoenix Healing Applied:")
                print(f"   Error: {str(e)[:100]}")
                print(f"   Suggestions: {', '.join(healing['suggestions'][:3])}")
                
                # Re-raise with healing context
                raise Exception(f"{str(e)} | Healing: {healing['suggestions'][0] if healing['suggestions'] else 'No suggestions'}") from e
        
        return wrapper
    return decorator


def main():
    """Test GS343 healing"""
    
    # Test retry logic
    @with_phoenix_retry(max_retries=3)
    def flaky_function():
        import random
        if random.random() < 0.7:
            raise Exception("Simulated API timeout")
        return "Success!"
    
    # Test healing
    @with_phoenix_healing('test_module')
    def failing_function():
        raise Exception("401: Invalid API key")
    
    print("Testing GS343 Phoenix Healing...")
    print("\n1. Testing retry logic:")
    try:
        result = flaky_function()
        print(f"✅ {result}")
    except Exception as e:
        print(f"❌ Failed after retries: {e}")
    
    print("\n2. Testing healing suggestions:")
    try:
        failing_function()
    except Exception as e:
        print(f"❌ Error with healing context: {e}")
    
    print("\n3. Healing Statistics:")
    stats = gs343.get_healing_stats()
    print(f"   Total healings: {stats['total_healings']}")
    print(f"   Categories: {stats['categories']}")


if __name__ == '__main__':
    main()
