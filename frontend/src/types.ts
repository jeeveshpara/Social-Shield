// Shared types used across all pages and components

export interface Finding {
  type?: string;
  code?: string;
  severity?: string;
  description?: string;
  evidence?: string;
  recommendation?: string;
  points?: number;
}

export interface PlatformProbe {
  platform: string;
  status: "found" | "not_found" | "timeout" | "rate_limited" | "unknown" | "error";
  profile_url?: string;
  status_code?: number;
}

export interface HomoglyphMatch {
  char: string;
  position: number;
  mimics: string;
  unicode_name: string;
}

export interface UsernameIntel {
  username: string;
  entropy: number;
  homoglyphs: HomoglyphMatch[];
  impersonation_terms: string[];
  footprint: PlatformProbe[];
}

export interface DnsIntel {
  a_records?: string[];
  aaaa_records?: string[];
  mx_records?: string[];
  ns_records?: string[];
  spf_records?: string[];
  dmarc_records?: string[];
}

export interface RdapIntel {
  status?: string;
  domain?: string;
  registrar?: string;
  registration_date?: string;
  expiration_date?: string;
  last_changed_date?: string;
  age_days?: number;
  message?: string;
}

export interface DomainIntel {
  hostname: string;
  apex_domain: string;
  tld: string;
  dns: DnsIntel;
  rdap: RdapIntel;
}

export interface RedirectHop {
  hop: number;
  url: string;
  status_code: number;
}

export interface UrlTraceIntel {
  initial_url: string;
  final_url: string;
  is_shortener?: boolean;
  redirect_chain?: RedirectHop[];
  reputation?: {
    status?: string;
    provider?: string;
    threat_types?: string[];
    message?: string;
  };
}

export interface WebMetadataIntel {
  title?: string;
  description?: string;
  og_site_name?: string;
  og_type?: string;
  og_image?: string;
  canonical_url?: string;
  author?: string;
}

export interface ScamMatch {
  category: string;
  title: string;
  severity: string;
  points: number;
  matches: string[];
}

export interface ScamAssessment {
  score: number;
  matched_categories: ScamMatch[];
}

export interface PhishingSignal {
  type: string;
  points: number;
  provider?: string;
  threat_types?: string;
  brand?: string;
  label?: string;
  distance?: number;
  tld?: string;
  subdomain?: string;
  keywords?: string[];
  host?: string;
}

export interface PhishingAssessment {
  score: number;
  is_suspect: boolean;
  matched_brand?: string;
  signals: PhishingSignal[];
}

export interface ImpersonationSignal {
  type: string;
  points: number;
  affixes?: string[];
  target?: string;
  distance?: number;
  count?: number;
  description?: string;
}

export interface ImpersonationAssessment {
  score: number;
  is_suspect: boolean;
  matched_target?: string;
  signals: ImpersonationSignal[];
}

export interface RiskBreakdown {
  score: number;
  level: string;
  dimension_scores: {
    osint: number;
    phishing: number;
    scam: number;
    impersonation: number;
  };
  risk_factors: string[];
}

export interface FraudIntel {
  scam_assessment?: ScamAssessment;
  phishing_assessment?: PhishingAssessment;
  impersonation_assessment?: ImpersonationAssessment;
  risk_breakdown?: RiskBreakdown;
}

export interface MitreAttackItem {
  id: string;
  name: string;
  tactic: string;
  description: string;
}

export interface AiAnalystReport {
  executive_summary: string;
  threat_actor_profile: {
    intent: string;
    sophistication: "Low" | "Moderate" | "Advanced" | "Unknown";
    target_demographic: string;
  };
  mitre_attack: MitreAttackItem[];
  evidence_synthesis: string[];
  containment_steps: string[];
  recommendations: string[];
  generated_by: string;
}

export interface OsintEvidence {
  target?: string;
  input_type?: "username" | "url";
  platform?: string;
  analysis_timestamp?: string;
  username_intel?: UsernameIntel;
  domain_intel?: DomainIntel;
  url_trace?: UrlTraceIntel;
  metadata?: WebMetadataIntel;
  fraud_intel?: FraudIntel;
  ai_analyst?: AiAnalystReport;
  [key: string]: unknown;
}

export interface Scan {
  id: number;
  target: string;
  platform: string;
  risk_score: number;
  risk_level: string;
  findings: Finding[];
  evidence?: OsintEvidence;
  created_at: string;
}

export const API_URL = "http://127.0.0.1:8000";
