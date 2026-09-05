export function signingURL(value: string | undefined, label: string, pathname: string): URL {
  if (!value) throw new Error(`${label} is not configured`);
  const origin = new URL(value);
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname);
  if (origin.username || origin.password || origin.search || origin.hash ||
      (origin.protocol !== 'https:' && !(local && origin.protocol === 'http:'))) {
    throw new Error(`${label} must use HTTPS (HTTP is allowed only for loopback development)`);
  }
  const url = new URL(pathname, origin);
  if (url.origin !== origin.origin) throw new Error('signing request escaped configured origin');
  return url;
}
