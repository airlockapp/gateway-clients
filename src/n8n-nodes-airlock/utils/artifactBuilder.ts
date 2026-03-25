import { EncryptedArtifactRequest } from '@airlockapp/gateway-sdk';

export interface ArtifactBuilderContext {
	enforcerId: string;
	artifactType: string;
	plaintextPayload: string;
	encryptionKeyBase64Url: string;
	workspaceName?: string;
	repoName?: string;
	requestLabel?: string;
}

export function buildEncryptedArtifactRequest(
	context: ArtifactBuilderContext
): EncryptedArtifactRequest {
	const metadata: Record<string, string> = {};

	if (context.workspaceName) metadata['workspaceName'] = context.workspaceName;
	if (context.repoName) metadata['repoName'] = context.repoName;
	if (context.requestLabel) metadata['requestLabel'] = context.requestLabel;

	return {
		enforcerId: context.enforcerId,
		artifactType: context.artifactType || 'command-approval',
		plaintextPayload: context.plaintextPayload,
		encryptionKeyBase64Url: context.encryptionKeyBase64Url,
		metadata: Object.keys(metadata).length > 0 ? metadata : undefined,
	};
}
