package hiss

import rego.v1

purpose_fields := {
	"treatment_surgery": {"operative_note", "identity", "cleft_dx", "facial_image"},
	"treatment_speech": {"identity", "speech_assessment", "cleft_dx"},
	"treatment_dental": {"identity", "cleft_dx", "dental_data"},
	"guardian_coordination": {"identity", "cleft_dx"},
	"research": {"research_pseudonym", "speech_assessment", "cleft_dx", "dental_data"},
	"ai_admin_summary": {"identity", "cleft_dx"},
}

entitled := {
	"surgeon": "treatment_surgery", "speech": "treatment_speech", "dentist": "treatment_dental",
	"guardian": "guardian_coordination", "researcher": "research", "ai_service": "ai_admin_summary",
}

emergency_set := {"identity", "cleft_dx", "operative_note"}

# Allowed pool for a request; undefined (=> deny) if authority/entitlement fails.
pool(r) := purpose_fields[r.purpose] if {
	r.auth == true
	r.cur == true
	entitled[r.role] == r.purpose
	r.emg == false
}

pool(r) := emergency_set if {
	r.auth == true
	r.cur == true
	entitled[r.role] == r.purpose
	r.emg == true
}

granted(r) := {f | some f in r.fields; f in pool(r)} if pool(r)

granted(r) := set() if not pool(r)

# Batch: input.requests is an array; output array of arrays, same order.
result := [sort([f | some f in granted(r)]) | some r in input.requests]
