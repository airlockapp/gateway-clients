import { DecisionDeliverEnvelope } from '@airlockapp/gateway-sdk';

export interface EnforcerOutput {
	requestLabel: string;
	decision: string | null;
	requestId: string;
	status: string;
	reason?: string;
	artifactType: string;
	workspaceName?: string;
	repoName?: string;
	enforcerId: string;
	rawDecision: DecisionDeliverEnvelope | null;
}

export function mapDecisionOutput(
	requestLabel: string,
	enforcerId: string,
	requestId: string,
	artifactType: string,
	workspaceName?: string,
	repoName?: string,
	rawDecision?: DecisionDeliverEnvelope | null
): EnforcerOutput {
	return {
		requestLabel,
		decision: rawDecision?.body?.decision || null,
		requestId: rawDecision?.requestId || requestId,
		status: rawDecision ? 'completed' : 'pending',
		reason: rawDecision?.body?.reason,
		artifactType,
		workspaceName,
		repoName,
		enforcerId,
		rawDecision: rawDecision || null,
	};
}
