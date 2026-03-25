export function validateRequiredField(value: any, name: string): void {
	if (value === undefined || value === null || (typeof value === 'string' && value.trim() === '')) {
		throw new Error(`The field "${name}" is required.`);
	}
}
