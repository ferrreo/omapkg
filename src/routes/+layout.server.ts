import type { LayoutServerLoad } from './$types';
export const load: LayoutServerLoad = ({ locals }) => ({ user: locals.user, role: locals.actor?.role ?? 'public', authReady: locals.authReady });
