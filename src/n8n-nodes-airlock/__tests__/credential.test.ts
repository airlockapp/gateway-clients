import { resolveAuth } from '../utils/authResolver';

describe('authResolver', () => {
	it('should return PAT and clientId together when both provided', () => {
		const credentials = { pat: 'my-pat', clientId: 'client', clientSecret: 'secret' };
		const auth = resolveAuth(credentials);
		expect(auth.pat).toBe('my-pat');
		expect(auth.clientId).toBe('client');
		expect(auth.clientSecret).toBe('secret');
	});

	it('should return clientId/clientSecret when PAT is absent', () => {
		const credentials = { clientId: 'client', clientSecret: 'secret' };
		const auth = resolveAuth(credentials);
		expect(auth.pat).toBeUndefined();
		expect(auth.clientId).toBe('client');
		expect(auth.clientSecret).toBe('secret');
	});

	it('should allow PAT-only auth (clientId provided)', () => {
		const credentials = { pat: 'my-pat', clientId: 'client' };
		const auth = resolveAuth(credentials);
		expect(auth.pat).toBe('my-pat');
		expect(auth.clientId).toBe('client');
	});

	it('should throw error when neither clientId nor PAT provided', () => {
		const credentials = { clientSecret: 'secret' };
		expect(() => resolveAuth(credentials)).toThrow(/must include a Client ID/);
	});
});
