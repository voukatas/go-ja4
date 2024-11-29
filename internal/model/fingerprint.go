package model

type FingerprintRecord struct {
	Application          *string `json:"application"`
	Library              *string `json:"library"`
	Device               *string `json:"device"`
	OS                   *string `json:"os"`
	UserAgentString      *string `json:"user_agent_string"`
	CertificateAuthority *string `json:"certificate_authority"`
	ObservationCount     int     `json:"observation_count"`
	Verified             bool    `json:"verified"`
	Notes                *string `json:"notes"`
	Ja4Fingerprint       *string `json:"ja4_fingerprint"`
	Ja4FingerprintString *string `json:"ja4_fingerprint_string"`
	Ja4sFingerprint      *string `json:"ja4s_fingerprint"`
	Ja4hFingerprint      *string `json:"ja4h_fingerprint"`
	Ja4xFingerprint      *string `json:"ja4x_fingerprint"`
	Ja4tFingerprint      *string `json:"ja4t_fingerprint"`
	Ja4tsFingerprint     *string `json:"ja4ts_fingerprint"`
	Ja4tscanFingerprint  *string `json:"ja4tscan_fingerprint"`
}
