import { AirlockGatewayError } from '@airlockapp/gateway-sdk';

export type ConsentStatus = 'approved' | 'required' | 'pending' | 'denied' | 'unknown';

export function normalizeConsentStatusWithError(
	status: string | undefined,
	error?: any
): ConsentStatus {
	if (error) {
		if (error instanceof AirlockGatewayError) {
			const errorCode = error.errorCode;
			if (errorCode === 'app_consent_required') return 'required';
			if (errorCode === 'app_consent_pending') return 'pending';
			if (errorCode === 'app_consent_denied') return 'denied';
		}
		throw error;
	}

	if (status === 'approved') return 'approved';
	if (status === 'required') return 'required';
	if (status === 'pending') return 'pending';
	if (status === 'denied') return 'denied';

	return 'unknown';
}
