/** Decodes a JWT payload WITHOUT verification (client-side display only;
 *  the server is the authority and every API call re-verifies the token). */
export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const json = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(decodeURIComponent(escape(json))) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function tokenExpiresAt(token: string): Date | null {
  const payload = decodeJwtPayload(token);
  if (!payload || typeof payload.exp !== 'number') return null;
  return new Date(payload.exp * 1000);
}

export function isTokenExpired(token: string, slackSeconds = 30): boolean {
  const exp = tokenExpiresAt(token);
  if (!exp) return true;
  return exp.getTime() - Date.now() < slackSeconds * 1000;
}
