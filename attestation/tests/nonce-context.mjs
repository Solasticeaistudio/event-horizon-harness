export function nonceContext(deviceId, overrides = {}) {
  return {
    deviceId,
    executorId: deviceId,
    sessionId: 'attestation-test-session',
    purpose: 'executor-attestation',
    ...overrides,
  };
}

export async function issueChallenge(verifier, deviceId, overrides = {}) {
  const context = nonceContext(deviceId, overrides);
  return { context, nonce: await verifier.nonceAuthority.issue(context) };
}
