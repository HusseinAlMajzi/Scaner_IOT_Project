// API Configuration
export const API_BASE_URL = 'http://localhost:5000/api';

// API Helper function with credentials
export const apiRequest = async (endpoint, options = {}) => {
  const url = endpoint.startsWith('http') ? endpoint : `${API_BASE_URL}${endpoint}`;
  
  const config = {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    ...options,
  };

  try {
    console.log(`[API] ${config.method || 'GET'} ${url}`);
    const response = await fetch(url, config);
    
    console.log(`[API] Response status: ${response.status}`);
    
    // DON'T redirect on 401 for /auth/me endpoint - it's expected when not logged in!
    const isAuthCheck = endpoint.includes('/auth/me');
    
    // Handle redirects (302, 301, etc.) - but not for auth checks
    if (!isAuthCheck && (response.redirected || response.status === 302 || response.status === 301)) {
      console.warn('[API] Response was redirected - likely not authenticated');
      // Don't redirect here - let the component handle it
      throw new Error('Session expired or not authenticated');
    }
    
    // Handle 401 Unauthorized - but NOT for auth checks (that's expected!)
    if (!isAuthCheck && response.status === 401) {
      console.warn('[API] 401 Unauthorized - authentication required');
      // Don't force redirect - let PrivateRoute handle it
      throw new Error('Unauthorized');
    }
    
    // Check if response is ok
    if (!response.ok) {
      console.warn(`[API] Response not OK: ${response.status} ${response.statusText}`);
      throw new Error(`API Error: ${response.status} ${response.statusText}`);
    }
    
    // Check content type before parsing
    const contentType = response.headers.get('content-type');
    if (!contentType || !contentType.includes('application/json')) {
      console.error('[API] Response is not JSON:', contentType);
      const text = await response.text();
      console.error('[API] Response text:', text.substring(0, 200));
      throw new Error('Response is not JSON - possible redirect or error page');
    }
    
    const data = await response.json();
    console.log(`[API] Success! Items:`, data.devices?.length || data.vulnerabilities?.length || data.reports?.length || 'N/A');
    return { response, data };
  } catch (error) {
    console.error('[API] Request Error:', error.message);
    throw error;
  }
};

// Convenience methods
export const api = {
  get: (endpoint) => apiRequest(endpoint, { method: 'GET' }),
  
  post: (endpoint, body) => apiRequest(endpoint, {
    method: 'POST',
    body: JSON.stringify(body),
  }),
  
  put: (endpoint, body) => apiRequest(endpoint, {
    method: 'PUT',
    body: JSON.stringify(body),
  }),
  
  delete: (endpoint) => apiRequest(endpoint, { method: 'DELETE' }),
};
