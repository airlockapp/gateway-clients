import { INodeExecutionData } from 'n8n-workflow';

export interface ResolvedAuth {
	pat?: string;
	clientId?: string;
	clientSecret?: string;
}

export function resolveAuth(credentials: any): ResolvedAuth {
	const pat = credentials.pat as string | undefined;
	const clientId = credentials.clientId as string | undefined;
	const clientSecret = credentials.clientSecret as string | undefined;

	if (!clientId?.trim() && !pat?.trim()) {
		throw new Error('Airlock Credentials must include a Client ID and either a Client Secret (for applications) or a Personal Access Token (for user sessions).');
	}

	return {
		pat: pat?.trim() || undefined,
		clientId: clientId?.trim() || undefined,
		clientSecret: clientSecret?.trim() || undefined,
	};
}
