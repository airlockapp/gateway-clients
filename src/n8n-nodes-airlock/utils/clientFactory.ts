import { AirlockGatewayClient } from '@airlockapp/gateway-sdk';
import { IExecuteFunctions, ILoadOptionsFunctions, IHookFunctions, IWebhookFunctions } from 'n8n-workflow';
import { resolveAuth } from './authResolver';

export type ContextFunctions = IExecuteFunctions | ILoadOptionsFunctions | IHookFunctions | IWebhookFunctions;

export async function getAirlockClient(context: ContextFunctions): Promise<AirlockGatewayClient> {
	const credentials = await context.getCredentials('airlockGatewayApi');
	if (!credentials) {
		throw new Error('No credentials returned for airlockGatewayApi');
	}

	const baseUrl = credentials.gatewayUrl as string;
	if (!baseUrl) {
		throw new Error('Gateway URL is required in credentials');
	}

	const auth = resolveAuth(credentials);

	return new AirlockGatewayClient({
		baseUrl,
		pat: auth.pat,
		clientId: auth.clientId,
		clientSecret: auth.clientSecret,
	});
}
