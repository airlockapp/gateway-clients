jest.mock('@airlockapp/gateway-sdk', () => {
	return {
		AirlockGatewayError: class AirlockGatewayError extends Error {
			errorCode: string;
			responseBody: string;
			statusCode: number;
			constructor(message: string, details: any) {
				super(message);
				this.errorCode = details.errorCode;
				this.responseBody = details.responseBody;
				this.statusCode = details.statusCode;
			}
		}
	};
});

import { normalizeConsentStatusWithError } from '../utils/consentNormalizer';
import { mapDecisionOutput } from '../utils/outputMapper';
import { AirlockGatewayError } from '@airlockapp/gateway-sdk';

describe('consentNormalizer', () => {
	it('maps approved status correctly', () => {
		expect(normalizeConsentStatusWithError('approved')).toBe('approved');
	});

	it('maps SDK consent errors correctly', () => {
		const error = new AirlockGatewayError('Consent required', { errorCode: 'app_consent_required', responseBody: '', statusCode: 403 });
		expect(normalizeConsentStatusWithError(undefined, error)).toBe('required');
	});

	it('throws non-consent errors', () => {
		const error = new AirlockGatewayError('Internal error', { errorCode: 'internal', responseBody: '', statusCode: 500 });
		expect(() => normalizeConsentStatusWithError(undefined, error)).toThrow();
	});
});

describe('outputMapper', () => {
	it('maps decision output correctly', () => {
		const raw = {
			msgType: 'decision.deliver',
			requestId: 'req-1',
			body: { decision: 'approve', reason: 'looks good', artifactHash: '123' },
		};
		const out = mapDecisionOutput('Deploy', 'env-1', 'req-1', 'cmd', 'ws', 'repo', raw as any);
		
		expect(out.requestLabel).toBe('Deploy');
		expect(out.decision).toBe('approve');
		expect(out.status).toBe('completed');
		expect(out.reason).toBe('looks good');
		expect(out.enforcerId).toBe('env-1');
	});

	it('handles pending decision output', () => {
		const out = mapDecisionOutput('Deploy', 'env-1', 'req-1', 'cmd', 'ws', 'repo', null);
		
		expect(out.decision).toBeNull();
		expect(out.status).toBe('pending');
		expect(out.rawDecision).toBeNull();
	});
});
