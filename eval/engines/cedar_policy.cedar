// One decision per (role, purpose, field). Context carries purpose + flags.
// Normal path: authority valid+current, role entitled to purpose, field in purpose set.
permit (principal, action == Action::"read", resource)
when {
  context.auth && context.cur && !context.emg &&
  principal.entitled == context.purpose &&
  context.purpose.fields.contains(resource.name)
};
// Emergency path: still needs valid+current authority and entitlement; bounded set replaces purpose set.
permit (principal, action == Action::"read", resource)
when {
  context.auth && context.cur && context.emg &&
  principal.entitled == context.purpose &&
  ["identity", "cleft_dx", "operative_note"].contains(resource.name)
};
