export function nonceContext(deviceId, overrides = {}) {
  return {
    deviceId,
    executorId: deviceId,
    sessionId: 'attestation-test-session',
    purpose: 'executor-attestation',
    ...overrides,
  };
}

export function issueChallenge(verifier, deviceId, overrides = {}) {
  const context = nonceContext(deviceId, overrides);
  return { context, nonce: verifier.nonceAuthority.issue(context) };
}
