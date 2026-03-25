import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { getAirlockClient } from '../../utils/clientFactory';
import { buildEncryptedArtifactRequest } from '../../utils/artifactBuilder';
import { mapDecisionOutput } from '../../utils/outputMapper';
import { mapAirlockError } from '../../utils/errorMapper';

/** A single requested action shown to the approver on mobile. */
interface RequestedAction {
	id: string;
	caption: string;
	style: 'primary' | 'secondary' | 'danger';
	decision: 'allow' | 'deny';
}

/** Built-in action presets matching the platform test enforcer. */
const ACTION_PRESETS: Record<string, RequestedAction[]> = {
	allow_only: [
		{ id: 'allow', caption: 'Allow', style: 'primary', decision: 'allow' },
	],
	allow_deny: [
		{ id: 'allow', caption: 'Allow', style: 'primary', decision: 'allow' },
		{ id: 'deny', caption: 'Deny', style: 'danger', decision: 'deny' },
	],
	run_skip_deny: [
		{ id: 'run', caption: 'Run', style: 'primary', decision: 'allow' },
		{ id: 'skip', caption: 'Skip', style: 'secondary', decision: 'deny' },
		{ id: 'deny', caption: 'Deny', style: 'danger', decision: 'deny' },
	],
	full: [
		{ id: 'run_all', caption: 'Run All', style: 'primary', decision: 'allow' },
		{ id: 'run', caption: 'Run', style: 'secondary', decision: 'allow' },
		{ id: 'edit', caption: 'Edit', style: 'secondary', decision: 'deny' },
		{ id: 'skip', caption: 'Skip', style: 'secondary', decision: 'deny' },
		{ id: 'reject', caption: 'Reject', style: 'danger', decision: 'deny' },
	],
};

export class AirlockEnforcer implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Airlock Enforcer',
		name: 'airlockEnforcer',
		icon: 'fa:lock',
		group: ['transform'],
		version: 1,
		description: 'Submit an encrypted approval request to Airlock Gateway',
		defaults: {
			name: 'Airlock Enforcer',
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
				displayName: 'Artifact Type',
				name: 'artifactType',
				type: 'options',
				options: [
					{ name: 'Command Review', value: 'command.review' },
					{ name: 'Plan Review', value: 'plan.review' },
					{ name: 'Task Review', value: 'task.review' },
					{ name: 'Patch Review', value: 'patch.review' },
					{ name: 'Checkpoint Review', value: 'checkpoint.review' },
				],
				default: 'command.review',
				description: 'The semantic type of HarP artifact being submitted',
			},
			{
				displayName: 'Request Label',
				name: 'requestLabel',
				type: 'string',
				default: '',
				required: true,
				description: 'Title shown to the approver on their mobile device (e.g., "Deploy to Production")',
			},
			// ── Requested Actions (org.harp.requestedActions) ──────────
			{
				displayName: 'Action Preset',
				name: 'actionPreset',
				type: 'options',
				options: [
					{ name: 'Allow Only', value: 'allow_only', description: 'Single Allow button' },
					{ name: 'Allow / Deny', value: 'allow_deny', description: 'Allow and Deny buttons' },
					{ name: 'Run / Skip / Deny', value: 'run_skip_deny', description: 'Run, Skip, and Deny buttons' },
					{ name: 'Full (5 buttons)', value: 'full', description: 'Run All, Run, Edit, Skip, Reject' },
					{ name: 'Custom', value: 'custom', description: 'Define your own actions' },
				],
				default: 'allow_deny',
				description: 'Choose which approval buttons the approver sees on their mobile device',
			},
			{
				displayName: 'Custom Actions',
				name: 'customActions',
				type: 'fixedCollection',
				typeOptions: { multipleValues: true },
				displayOptions: {
					show: { actionPreset: ['custom'] },
				},
				default: {},
				options: [
					{
						name: 'actions',
						displayName: 'Actions',
						values: [
							{
								displayName: 'ID',
								name: 'id',
								type: 'string',
								default: '',
								description: 'Stable action identifier (e.g., "approve", "reject")',
							},
							{
								displayName: 'Caption',
								name: 'caption',
								type: 'string',
								default: '',
								description: 'Button label shown on mobile (e.g., "Approve", "Reject")',
							},
							{
								displayName: 'Style',
								name: 'style',
								type: 'options',
								options: [
									{ name: 'Primary', value: 'primary' },
									{ name: 'Secondary', value: 'secondary' },
									{ name: 'Danger', value: 'danger' },
								],
								default: 'primary',
								description: 'Visual style of the button',
							},
							{
								displayName: 'Decision',
								name: 'decision',
								type: 'options',
								options: [
									{ name: 'Allow', value: 'allow' },
									{ name: 'Deny', value: 'deny' },
								],
								default: 'allow',
								description: 'What tapping this button means semantically',
							},
						],
					},
				],
			},
			// ── Payload ──────────────────────────────────────────────
			{
				displayName: 'Payload Mode',
				name: 'payloadMode',
				type: 'options',
				options: [
					{
						name: 'JSON Payload',
						value: 'json',
					},
					{
						name: 'Raw Text Payload',
						value: 'text',
					},
				],
				default: 'json',
			},
			{
				displayName: 'JSON Payload',
				name: 'jsonPayload',
				type: 'json',
				displayOptions: {
					show: { payloadMode: ['json'] },
				},
				default: '{}',
				required: true,
			},
			{
				displayName: 'Text Payload',
				name: 'textPayload',
				type: 'string',
				typeOptions: { alwaysOpenEditWindow: true, rows: 4 },
				displayOptions: {
					show: { payloadMode: ['text'] },
				},
				default: '',
				required: true,
			},
			// Wait configuration is now handled globally via the Airlock Gateway API credentials.
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: any[] = [];

		let client;
		try {
			client = await getAirlockClient(this);
		} catch (error) {
			throw mapAirlockError(this, error);
		}

		const credentials = await this.getCredentials('airlockGatewayApi');
		const enforcerId = credentials?.enforcerId as string;
		const workspaceName = credentials?.workspaceName as string | undefined;
		const repoName = credentials?.repoName as string | undefined;
		const approvalTimeoutSeconds = (credentials?.approvalTimeoutSeconds as number | undefined) ?? 60;
		const failMode = (credentials?.failMode as string | undefined) ?? 'failClosed';

		for (let i = 0; i < items.length; i++) {
			try {
				const requestLabel = this.getNodeParameter('requestLabel', i) as string;
				const artifactType = this.getNodeParameter('artifactType', i) as string;
				const payloadMode = this.getNodeParameter('payloadMode', i) as string;
				const actionPreset = this.getNodeParameter('actionPreset', i) as string;

				// Resolve requested actions
				let requestedActions: RequestedAction[] = [];
				if (actionPreset === 'custom') {
					const customActionsRaw = this.getNodeParameter('customActions', i, {}) as any;
					const actionEntries = customActionsRaw?.actions || [];
					requestedActions = actionEntries.map((a: any) => ({
						id: a.id || '',
						caption: a.caption || '',
						style: a.style || 'primary',
						decision: a.decision || 'allow',
					}));
				} else {
					requestedActions = ACTION_PRESETS[actionPreset] || ACTION_PRESETS['allow_deny'];
				}

				// Build extensions object
				const extensions: Record<string, unknown> = {
					'org.harp.requestedActions': {
						version: 1,
						actions: requestedActions,
					},
				};

				// Build plaintext payload with extensions injected
				let payloadObj: Record<string, unknown> = {};
				if (payloadMode === 'json') {
					const jsonPayload = this.getNodeParameter('jsonPayload', i);
					let parsed: unknown = jsonPayload;
					if (typeof parsed === 'string') {
						try { parsed = JSON.parse(parsed); } catch { /* keep as string */ }
					}
					if (typeof parsed === 'object' && parsed !== null) {
						payloadObj = { ...parsed as Record<string, unknown> };
					} else {
						payloadObj = { data: String(jsonPayload) };
					}
				} else {
					payloadObj = { data: this.getNodeParameter('textPayload', i) as string };
				}

				// Inject extensions into payload
				payloadObj.extensions = extensions;
				const plaintextPayload = JSON.stringify(payloadObj);

				if (!credentials.encryptionKeyBase64Url || !credentials.routingToken) {
					throw new Error('Airlock Gateway Credentials are missing the Encryption Key or Routing Token. Please run an Airlock Echo node in "Pair Device" mode to generate them.');
				}

				const requestInfo = buildEncryptedArtifactRequest({
					enforcerId,
					artifactType,
					plaintextPayload,
					encryptionKeyBase64Url: credentials.encryptionKeyBase64Url as string,
					workspaceName,
					repoName,
					requestLabel,
				});

				// Inject actionId and routingToken into metadata
				if (!requestInfo.metadata) {
					requestInfo.metadata = {};
				}
				requestInfo.metadata['routingToken'] = credentials.routingToken as string;

				const requestId = await client.encryptAndSubmitArtifact(requestInfo);

				let rawDecision = null;
				const enforcerLabel = this.getNode().name;
				
				// Send an initial heartbeat immediately
				client.sendHeartbeat({
					enforcerId,
					workspaceName,
					enforcerLabel,
				}).catch(() => {});

				// Keep sending heartbeats every 60 seconds for long-polling requests
				const heartbeatInterval = setInterval(() => {
					client.sendHeartbeat({
						enforcerId,
						workspaceName,
						enforcerLabel,
					}).catch(() => {});
				}, 60000);

				try {
					rawDecision = await client.waitForDecision(requestId, approvalTimeoutSeconds);
				} catch (error: any) {
					if (failMode === 'failClosed') {
						throw mapAirlockError(this, error);
					} else {
						// Fail Open: Mock an allow decision to ensure the workflow continues
						rawDecision = {
							requestId,
							msgType: 'decision',
							body: {
								decision: 'allow',
								reason: `Fail Open auto-approval on error/timeout: ${error.message || 'Timeout'}`,
								artifactHash: '',
							}
						};
					}
				} finally {
					clearInterval(heartbeatInterval);
				}

				const output = mapDecisionOutput(
					requestLabel,
					enforcerId,
					requestId,
					artifactType,
					workspaceName,
					repoName,
					rawDecision
				);

				returnData.push(output);
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
