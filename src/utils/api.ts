/**
 * Stateless wrapped fetch client which automatically injects Supabase's
 * authorization access token and provider token from the frontend state.
 */
export async function apiFetch(url: string, options: RequestInit = {}): Promise<Response> {
  const sbAccessToken = window.localStorage.getItem('audi_sb_access_token') || '';
  const sbProviderToken = window.localStorage.getItem('audi_sb_provider_token') || '';

  const headers = new Headers(options.headers || {});

  if (sbAccessToken) {
    headers.set('Authorization', `Bearer ${sbAccessToken}`);
  }
  if (sbProviderToken) {
    headers.set('x-provider-token', sbProviderToken);
  }

  return fetch(url, {
    ...options,
    headers
  });
}
