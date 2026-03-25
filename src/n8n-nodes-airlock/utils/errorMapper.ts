import { NodeApiError, NodeOperationError } from 'n8n-workflow';
import { AirlockGatewayError } from '@airlockapp/gateway-sdk';
import { ContextFunctions } from './clientFactory';

export function mapAirlockError(context: ContextFunctions, error: any): Error {
	if (error instanceof AirlockGatewayError) {
		const response = {
			statusCode: error.statusCode || 500,
			body: error.responseBody || null,
		};

		return new NodeApiError(context.getNode(), response, {
			message: error.message,
			description: `Airlock Gateway Error Code: ${error.errorCode || 'unknown'}`,
		});
	}

	if (error instanceof Error) {
		return new NodeOperationError(context.getNode(), error);
	}

	return new NodeOperationError(context.getNode(), 'Unknown error occurred while interacting with Airlock Gateway');
}
