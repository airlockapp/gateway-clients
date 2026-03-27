import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeOperationError,
} from 'n8n-workflow';
import { getAirlockClient } from '../../utils/clientFactory';
import { normalizeConsentStatusWithError } from '../../utils/consentNormalizer';
import { mapAirlockError } from '../../utils/errorMapper';
import { deriveSharedKey, generateX25519KeyPair } from '../../utils/crypto';
export class AirlockEcho implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Airlock Echo',
		name: 'airlockEcho',
		icon: 'fa:satellite-dish',
		group: ['transform'],
		version: 1,
		description: 'Verify connectivity to Airlock Gateway and check consent status',
		defaults: {
			name: 'Airlock Echo',
		},
		inputs: ['main'],
		outputs: ['main'],
		credentials: [
			{
				name: 'airlockGatewayApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Echo / Consent Check',
						value: 'echo',
						description: 'Call echo() and optionally checkConsent()',
						action: 'Echo and check consent',
					},
					{
						name: 'Pair Device',
						value: 'pair',
						description: 'Execute the device pairing flow to derive your encryption key',
						action: 'Pair device',
					},
				],
				default: 'echo',
			},
			{
				displayName: 'Fail If Consent Not Approved',
				name: 'failOnConsent',
				type: 'boolean',
				default: false,
				description: 'Whether to throw an error if the user has not approved consent',
				displayOptions: {
					show: {
						operation: ['echo'],
					},
				},
			},
			{
				displayName: 'Include Raw Response',
				name: 'includeRaw',
				type: 'boolean',
				default: false,
				description: 'Whether to include the raw gateway echo response',
				displayOptions: {
					show: {
						operation: ['echo'],
					},
				},
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: any[] = [];
		const operation = this.getNodeParameter('operation', 0) as string;

		let client;
		try {
			client = await getAirlockClient(this);
		} catch (error) {
			throw mapAirlockError(this, error);
		}

		for (let i = 0; i < items.length; i++) {
			try {
				if (operation === 'echo') {
					const failOnConsent = this.getNodeParameter('failOnConsent', i, false) as boolean;
					const includeRaw = this.getNodeParameter('includeRaw', i, false) as boolean;

					const echoResult = await client.echo();
					
					let consentStatus = 'unknown';
					try {
						consentStatus = await client.checkConsent();
					} catch (consentError) {
						consentStatus = normalizeConsentStatusWithError(undefined, consentError);
					}

					if (failOnConsent && consentStatus !== 'approved') {
						throw new NodeOperationError(this.getNode(), `Consent not approved. Current status: ${consentStatus}`, { itemIndex: i });
					}

					const output: any = {
						gatewayReachable: true,
						echoUtc: echoResult.utc,
						echoTimezone: echoResult.timezone,
						consentStatus,
						needsConsent: consentStatus !== 'approved',
					};

					if (includeRaw) {
						output.raw = echoResult;
					}

					returnData.push(output);
				} else if (operation === 'pair') {
					const credentials = await this.getCredentials('airlockGatewayApi');
					const deviceCode = credentials?.deviceCode as string | undefined;
					const enforcerId = credentials?.enforcerId as string;
					const workspaceName = credentials?.workspaceName as string | undefined;

					if (!deviceCode) {
						throw new NodeOperationError(this.getNode(), 'You must provide a "Pre-generated Device Code" in your Airlock Gateway API credentials to perform pairing.', { itemIndex: i });
					}

					const keyPair = generateX25519KeyPair();

					const claimResp = await client.claimPairing({
						pairingCode: deviceCode,
						deviceId: enforcerId,
						enforcerId,
						enforcerLabel: 'n8n Workflow',
						workspaceName: workspaceName || 'default',
						x25519PublicKey: keyPair.publicKey,
					});

					let serverPubKey = '';
					let routingToken = '';
					let attempts = 0;
					
					while (attempts < 30) {
						const status = await client.getPairingStatus(claimResp.pairingNonce);
						const state = (status.state || '').toLowerCase();
						if (state === 'completed') {
							routingToken = (status as any).routingToken || '';
							const respJson = (status as any).responseJson;
							if (respJson) {
								const respObj = JSON.parse(respJson);
								serverPubKey = respObj.x25519PublicKey || '';
							}
							break;
						} else if (state === 'revoked' || state === 'expired') {
							throw new Error(`Pairing failed with state: ${status.state}`);
						}
						
						await new Promise(r => setTimeout(r, 5000));
						attempts++;
					}

					if (!serverPubKey) {
						throw new Error('Pairing timed out waiting for server public key. Check your mobile app.');
					}

					const derivedEncryptionKey = deriveSharedKey(keyPair.privateKey, serverPubKey);

					// Auto-update the credential store via n8n's REST API
					let credentialsSaved = false;
					try {
						const credentialRef = this.getNode().credentials?.airlockGatewayApi;
						const credId = credentialRef?.id;
						const apiKey = process.env.N8N_API_KEY;
						if (credId && apiKey) {
							const baseApiUrl = `http://localhost:${process.env.N8N_PORT || '5678'}/api/v1`;
							// Read existing credential data
							const getResp = await fetch(`${baseApiUrl}/credentials/${credId}`, {
								headers: { 'X-N8N-API-KEY': apiKey },
							});
							if (getResp.ok) {
								const existing = await getResp.json() as any;
								// Merge new values into existing credential data
								const updatedData = {
									...existing.data,
									encryptionKeyBase64Url: derivedEncryptionKey,
									routingToken: routingToken,
									deviceCode: '', // Clear the used device code
								};
								const putResp = await fetch(`${baseApiUrl}/credentials/${credId}`, {
									method: 'PATCH',
									headers: {
										'X-N8N-API-KEY': apiKey,
										'Content-Type': 'application/json',
									},
									body: JSON.stringify({
										name: existing.name,
										type: existing.type,
										data: updatedData,
									}),
								});
								credentialsSaved = putResp.ok;
							}
						}
					} catch {
						// Non-fatal — user can still copy manually
					}

					returnData.push({
					paired: true,
					credentialsSaved,
					encryptionKeyBase64Url: derivedEncryptionKey,
					routingToken: routingToken,
					instructions: credentialsSaved
						? 'Credentials have been automatically updated!'
						: `Auto-save failed${!process.env.N8N_API_KEY ? ' (N8N_API_KEY environment variable is not set)' : ''}.`
							+ ' To enable auto-save, set the N8N_API_KEY environment variable in your n8n container/instance.'
							+ ' Otherwise, please copy the encryptionKeyBase64Url and routingToken values above into your Airlock Gateway API credentials manually.',
				});
				}
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({ json: { error: (error as Error).message } });
					continue;
				}
				throw mapAirlockError(this, error);
			}
		}

		return [this.helpers.returnJsonArray(returnData)];
	}
}
