import {
	ICredentialType,
	INodeProperties,
} from 'n8n-workflow';

export class AirlockGatewayApi implements ICredentialType {
	name = 'airlockGatewayApi';
	displayName = 'Airlock Gateway API';
	documentationUrl = 'https://github.com/harp-protocol/harp-samples';
	properties: INodeProperties[] = [
		{
			displayName: 'Gateway URL',
			name: 'gatewayUrl',
			type: 'string',
			default: 'https://igw.airlocks.io',
			required: true,
			description: 'The base URL for the Airlock Integrations Gateway',
		},
		{
			displayName: 'Enforcer ID',
			name: 'enforcerId',
			type: 'string',
			default: '',
			required: true,
			description: 'The unique Enforcer ID for this application',
		},
		{
			displayName: 'Workspace Name',
			name: 'workspaceName',
			type: 'string',
			default: '',
			description: 'Optional Workspace Name (for metadata)',
		},
		{
			displayName: 'Repository Name',
			name: 'repoName',
			type: 'string',
			default: '',
			description: 'Optional Repository Name (for metadata)',
		},
		{
			displayName: 'Personal Access Token (PAT)',
			name: 'pat',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			description: 'Recommended: User PAT. Replaces client ID/secret if provided.',
		},
		{
			displayName: 'Client ID',
			name: 'clientId',
			type: 'string',
			default: '',
			description: 'Enforcer app Client ID. Required if PAT is not provided.',
		},
		{
			displayName: 'Client Secret',
			name: 'clientSecret',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			description: 'Enforcer app Client Secret. Required if PAT is not provided.',
		},
		{
			displayName: 'Encryption Key (Base64URL)',
			name: 'encryptionKeyBase64Url',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			description: 'AES-256-GCM encryption key. Run the Echo Node in Pair mode to generate.',
		},
		{
			displayName: 'Routing Token',
			name: 'routingToken',
			type: 'string',
			typeOptions: { password: true },
			default: '',
			description: 'Opaque Gateway routing token matching your mobile pairing session.',
		},
		{
			displayName: 'Wait Timeout (Seconds)',
			name: 'approvalTimeoutSeconds',
			type: 'number',
			default: 60,
			description: 'Maximum time to wait for mobile approval before timing out',
		},
		{
			displayName: 'Fail Mode',
			name: 'failMode',
			type: 'options',
			options: [
				{ name: 'Fail Closed (Deny/Stop)', value: 'failClosed' },
				{ name: 'Fail Open (Allow/Continue)', value: 'failOpen' },
			],
			default: 'failClosed',
			description: 'Behavior when the approval times out or a network error occurs',
		},
		{
			displayName: 'Pre-generated Device Code',
			name: 'deviceCode',
			type: 'string',
			default: '',
			description: 'Required in Sprint 1 for pairing config, visible locally',
		},
	];
}
