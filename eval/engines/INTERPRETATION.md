# Interpretation choices (blind spec)

1. **Granularity**: Cedar decides one field per `is_authorized` call (resource = Field); the granted set is the union of permits. Rego computes the set directly.
2. **Denial precedence**: invalid authority, stale authority, or role not entitled to the stated purpose gives an empty set. This holds for emergency requests too ("A request is denied if..." precedes "otherwise"), so break-glass does not bypass authority or entitlement (limits T09, T08).
3. **Emergency set replaces the purpose set**: if emergency is true and checks pass, grant requested ∩ {identity, cleft_dx, operative_note}. "Receive a bounded set" is read as the bound itself, not an additional intersection with the purpose set. Consequence: a guardian, ai_service, researcher, speech or dentist in an emergency can get operative_note, and a researcher can get identity. Alternative reading (intersect with both) was rejected because it would make emergency a no-op for several roles.
4. **Emergency is not additive**: it never grants more than the 3-field bound, even for surgeon (facial_image is dropped in an emergency).
5. **"Diagnosis" = `cleft_dx`.**
6. **Emergency does not widen entitlement**: the purpose must still be the role's one entitled purpose.
7. **Non-allowed requested fields are silently dropped** (allow-minimised), not a whole-request deny; empty result = deny.
8. **Unknown role, purpose or field**: nothing granted (unknown fields ignored). Strict booleans: only `true` counts.
9. **No default allow**: nothing grants `family_relationship` in any purpose, so it is never released.
