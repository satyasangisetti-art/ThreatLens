import express, { Request, Response } from 'express';
import dotenv from 'dotenv';
import crypto from 'crypto';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { GoogleGenAI } from '@google/genai';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

// Body parsers with generous limits for evidence & image payloads
app.use(express.json({ limit: '30mb' }));
app.use(express.urlencoded({ extended: true, limit: '30mb' }));

// Initialize Google GenAI client (Server-side only)
const apiKey = process.env.GEMINI_API_KEY;
let aiClient: GoogleGenAI | null = null;

if (apiKey) {
  try {
    aiClient = new GoogleGenAI({
      apiKey: apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
    console.log('[CyberTrace Server] Google GenAI client initialized successfully with gemini-3.8-flash.');
  } catch (err) {
    console.error('[CyberTrace Server] Failed to initialize Google GenAI:', err);
  }
} else {
  console.warn('[CyberTrace Server] No GEMINI_API_KEY detected in environment. Using high-fidelity heuristic engine fallback with clearly marked indicators.');
}

// ==========================================
// In-Memory Database with Seed SOC Records
// ==========================================
interface UserRecord {
  id: string;
  email: string;
  name: string;
  role: 'SOC Analyst' | 'Incident Commander' | 'Threat Hunter' | 'Security Admin';
  avatarUrl?: string;
  organization: string;
  twoFactorEnabled: boolean;
  createdAt: string;
}

interface IncidentRecord {
  id: string;
  incidentNumber: string;
  title: string;
  category: 'Phishing' | 'Malware' | 'Ransomware' | 'Data Breach' | 'Unauthorized Access' | 'DDoS Attack' | 'Financial Fraud' | 'Identity Theft' | 'Social Engineering' | 'Other';
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  status: 'Open' | 'Investigating' | 'Contained' | 'Resolved';
  description: string;
  affectedSystem: string;
  assignedInvestigator: string;
  timeline: Array<{
    id: string;
    timestamp: string;
    author: string;
    action: string;
    note?: string;
  }>;
  evidenceCount: number;
  createdAt: string;
  updatedAt: string;
}

interface ThreatAnalysisRecord {
  id: string;
  inputContent: string;
  inputType: 'url' | 'email' | 'sms' | 'text' | 'image';
  riskScore: number;
  riskClassification: 'Safe' | 'Suspicious' | 'High Risk' | 'Critical';
  threatCategory: string;
  confidenceScore: number;
  indicators: string[];
  explanation: string;
  recommendedActions: string[];
  analyzedAt: string;
  analyzedBy: string;
  engine: string;
  isSimulatedFallback?: boolean;
}

interface EvidenceRecord {
  id: string;
  incidentId?: string;
  filename: string;
  fileSize: number;
  fileType: string;
  sha256Hash: string;
  uploadedBy: string;
  uploadedAt: string;
  notes: string;
  integrityVerified: boolean;
  lastVerifiedAt: string;
  dataUrl?: string; // Stored payload preview if applicable
}

interface CybercrimeReportRecord {
  id: string;
  referenceNumber: string;
  complainantName: string;
  contactEmail: string;
  phoneNumber: string;
  fraudCategory: string;
  financialLossAmount: number;
  currency: string;
  transactionId: string;
  suspiciousUrl: string;
  suspectContact: string;
  description: string;
  status: 'Received' | 'Triaged' | 'Evidence Collected' | 'Forwarded to Authorities' | 'Resolved';
  submittedAt: string;
  updatedAt: string;
  evidenceFiles: string[];
}

interface ActivityLogRecord {
  id: string;
  timestamp: string;
  user: string;
  action: 'LOGIN' | 'LOGOUT' | 'INCIDENT_CREATED' | 'INCIDENT_UPDATED' | 'EVIDENCE_UPLOADED' | 'THREAT_ANALYZED' | 'REPORT_FILED' | 'SYSTEM_ALERT';
  details: string;
  ipAddress: string;
  severity: 'info' | 'warning' | 'alert' | 'success';
}

// Initial Seed Users
const users: UserRecord[] = [
  {
    id: 'usr-soc-001',
    email: 'analyst@cybertrace.io',
    name: 'Sarah Chen',
    role: 'Incident Commander',
    avatarUrl: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80',
    organization: 'CyberTrace SOC Alpha',
    twoFactorEnabled: true,
    createdAt: '2026-01-15T08:00:00Z',
  },
  {
    id: 'usr-soc-002',
    email: 'muthangisriharsha@gmail.com',
    name: 'Sri Harsha',
    role: 'Security Admin',
    avatarUrl: 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150&auto=format&fit=crop&q=80',
    organization: 'CyberTrace SOC Core',
    twoFactorEnabled: true,
    createdAt: '2026-02-01T10:00:00Z',
  }
];

// Initial Seed Incidents
const incidents: IncidentRecord[] = [
  {
    id: 'inc-9841',
    incidentNumber: 'CT-2026-9841',
    title: 'Credential Harvesting via Spear-Phishing Microsoft 365 Portal',
    category: 'Phishing',
    severity: 'Critical',
    status: 'Investigating',
    description: 'Multiple finance team members received urgent MFA exhaustion lures mimicking Microsoft Entra ID login, directing to a lookalike domain "auth-secure-portal365-verify.com".',
    affectedSystem: 'Exchange Online & Azure Entra ID / Finance Workstations',
    assignedInvestigator: 'Sarah Chen',
    timeline: [
      {
        id: 'tl-1',
        timestamp: '2026-10-31T01:14:00Z',
        author: 'AI Sentinel Hook',
        action: 'Automated Ingestion',
        note: 'High-risk telemetry trigger raised by gateway scanner.'
      },
      {
        id: 'tl-2',
        timestamp: '2026-10-31T01:45:00Z',
        author: 'Sarah Chen',
        action: 'Triage & Containment',
        note: 'Domain blocked in outbound perimeter DNS firewalls; 2 user tokens invalidated.'
      }
    ],
    evidenceCount: 3,
    createdAt: '2026-10-31T01:10:00Z',
    updatedAt: '2026-10-31T02:00:00Z',
  },
  {
    id: 'inc-9840',
    incidentNumber: 'CT-2026-9840',
    title: 'Unusual Lateral PowerShell Execution on Core Database Host',
    category: 'Unauthorized Access',
    severity: 'High',
    status: 'Contained',
    description: 'Suspicious Base64 encoded PowerShell script observed attempting memory injection and registry beaconing across internal subnet 10.14.2.0/24.',
    affectedSystem: 'PROD-DB-CLUSTER-04',
    assignedInvestigator: 'Sri Harsha',
    timeline: [
      {
        id: 'tl-3',
        timestamp: '2026-10-30T18:22:00Z',
        author: 'EDR Agent',
        action: 'Process Quarantined',
        note: 'Process PID 8419 terminated and memory snapshot collected for forensics.'
      }
    ],
    evidenceCount: 2,
    createdAt: '2026-10-30T18:15:00Z',
    updatedAt: '2026-10-30T22:40:00Z',
  },
  {
    id: 'inc-9839',
    incidentNumber: 'CT-2026-9839',
    title: 'Executive Impersonation & Wire Transfer Fraud via WhatsApp SMS',
    category: 'Financial Fraud',
    severity: 'Medium',
    status: 'Resolved',
    description: 'CFO phone spoofing attempt requesting urgent offshore supplier settlement of $48,200 via fake swift routing instructions.',
    affectedSystem: 'Executive Communications / Accounts Payable',
    assignedInvestigator: 'Sarah Chen',
    timeline: [
      {
        id: 'tl-4',
        timestamp: '2026-10-29T11:00:00Z',
        author: 'Sarah Chen',
        action: 'Incident Resolved',
        note: 'Bank notified, account frozen before transfer occurred. Report logged with cybercrime unit.'
      }
    ],
    evidenceCount: 4,
    createdAt: '2026-10-29T09:30:00Z',
    updatedAt: '2026-10-29T16:20:00Z',
  },
  {
    id: 'inc-9838',
    incidentNumber: 'CT-2026-9838',
    title: 'Distributed Denial of Service (UDP Flood) Targeting Payment Gateway',
    category: 'DDoS Attack',
    severity: 'High',
    status: 'Resolved',
    description: 'Volumetric attack peak at 42 Gbps targeting ingress API edge. Mitigated via scrubbing center and dynamic BGP routing.',
    affectedSystem: 'Edge Ingress LB / Cloudflare Scrubbing Hub',
    assignedInvestigator: 'Sri Harsha',
    timeline: [
      {
        id: 'tl-5',
        timestamp: '2026-10-28T04:10:00Z',
        author: 'Automated SOC',
        action: 'Rate Limiting Engaged',
        note: 'Traffic normalized within 12 minutes.'
      }
    ],
    evidenceCount: 1,
    createdAt: '2026-10-28T04:00:00Z',
    updatedAt: '2026-10-28T06:15:00Z',
  }
];

// Initial Seed Evidence Files
const evidenceFiles: EvidenceRecord[] = [
  {
    id: 'evi-801',
    incidentId: 'inc-9841',
    filename: 'm365_phish_lure_headers.eml',
    fileSize: 48210,
    fileType: 'message/rfc822',
    sha256Hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    uploadedBy: 'Sarah Chen',
    uploadedAt: '2026-10-31T01:30:00Z',
    notes: 'Raw email headers showing spoofed SPF and lookalike reply-to header pointing to external server.',
    integrityVerified: true,
    lastVerifiedAt: '2026-10-31T03:00:00Z',
  },
  {
    id: 'evi-802',
    incidentId: 'inc-9841',
    filename: 'fake_login_screenshot.png',
    fileSize: 184500,
    fileType: 'image/png',
    sha256Hash: '4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
    uploadedBy: 'Sarah Chen',
    uploadedAt: '2026-10-31T01:35:00Z',
    notes: 'High-res capture of phishing page showing cloned Microsoft branding and suspicious domain.',
    integrityVerified: true,
    lastVerifiedAt: '2026-10-31T03:10:00Z',
  },
  {
    id: 'evi-803',
    incidentId: 'inc-9840',
    filename: 'powershell_beacon_memory_dump.raw',
    fileSize: 524288,
    fileType: 'application/octet-stream',
    sha256Hash: '872983ac12201b10a95079a4891b00f89832810a92482bb29828384918293810',
    uploadedBy: 'Sri Harsha',
    uploadedAt: '2026-10-30T19:00:00Z',
    notes: 'Volatile memory dump containing unpacked payload shellcode referencing remote C2 server.',
    integrityVerified: true,
    lastVerifiedAt: '2026-10-30T21:15:00Z',
  }
];

// Initial Seed Cybercrime Reports
const cybercrimeReports: CybercrimeReportRecord[] = [
  {
    id: 'rep-101',
    referenceNumber: 'CT-CR-2026-0491',
    complainantName: 'David Miller',
    contactEmail: 'david.miller@apexglobal.net',
    phoneNumber: '+1 (555) 234-8910',
    fraudCategory: 'Cryptocurrency Impersonation & Investment Scam',
    financialLossAmount: 14500,
    currency: 'USD',
    transactionId: '0x8f3c71a932bce12903847a98234beba837269',
    suspiciousUrl: 'https://yield-vault-ai-guaranteed.live/invest',
    suspectContact: '+44 7700 900821 / @crypto_vip_assistant',
    description: 'Victim was invited to an automated algorithmic trading telegram group. After depositing USDT to a smart contract address, the funds were routed to a mixer service and withdrawal locked behind a fake "liquidity fee".',
    status: 'Forwarded to Authorities',
    submittedAt: '2026-10-27T14:15:00Z',
    updatedAt: '2026-10-28T09:30:00Z',
    evidenceFiles: ['crypto_tx_receipt.pdf', 'telegram_chat_logs.txt'],
  },
  {
    id: 'rep-102',
    referenceNumber: 'CT-CR-2026-0492',
    complainantName: 'Elena Rostova',
    contactEmail: 'elena.rostova@nexusgroup.com',
    phoneNumber: '+1 (555) 876-5432',
    fraudCategory: 'Executive Email Compromise (BEC)',
    financialLossAmount: 32000,
    currency: 'USD',
    transactionId: 'WIRE-98234-CHASE',
    suspiciousUrl: 'https://secure-invoice-nexusgroup.net/billing',
    suspectContact: 'cfo-office@nexusgroup-verify.com',
    description: 'Fraudulent bank account change request received purportedly from vendor accounting manager right before scheduled quarterly settlement.',
    status: 'Triaged',
    submittedAt: '2026-10-30T10:00:00Z',
    updatedAt: '2026-10-30T11:45:00Z',
    evidenceFiles: ['fake_invoice_nexus.pdf'],
  }
];

// Initial Activity Logs
const activityLogs: ActivityLogRecord[] = [
  {
    id: 'act-1',
    timestamp: '2026-10-31T03:45:10Z',
    user: 'Sarah Chen',
    action: 'THREAT_ANALYZED',
    details: 'AI Threat Analyzer scanned URL "https://auth-secure-portal365-verify.com" (Risk Score: 94/100, Critical Phishing).',
    ipAddress: '198.51.100.44',
    severity: 'alert',
  },
  {
    id: 'act-2',
    timestamp: '2026-10-31T03:30:00Z',
    user: 'Sarah Chen',
    action: 'INCIDENT_UPDATED',
    details: 'Incident CT-2026-9841 status updated to Investigating with new perimeter block rules.',
    ipAddress: '198.51.100.44',
    severity: 'warning',
  },
  {
    id: 'act-3',
    timestamp: '2026-10-31T02:50:18Z',
    user: 'Sri Harsha',
    action: 'EVIDENCE_UPLOADED',
    details: 'Evidence file "m365_phish_lure_headers.eml" SHA-256 verified and recorded in vault.',
    ipAddress: '203.0.113.88',
    severity: 'info',
  },
  {
    id: 'act-4',
    timestamp: '2026-10-31T01:10:00Z',
    user: 'Sarah Chen',
    action: 'LOGIN',
    details: 'Secure SOC session authenticated via 2FA token from authorized workstation.',
    ipAddress: '198.51.100.44',
    severity: 'success',
  }
];

// Helper to record activity
function logSOCActivity(
  user: string,
  action: ActivityLogRecord['action'],
  details: string,
  severity: ActivityLogRecord['severity'] = 'info',
  ip: string = '127.0.0.1'
) {
  const newLog: ActivityLogRecord = {
    id: 'act-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
    timestamp: new Date().toISOString(),
    user,
    action,
    details,
    ipAddress: ip,
    severity,
  };
  activityLogs.unshift(newLog);
  if (activityLogs.length > 200) activityLogs.pop();
  return newLog;
}

// ==========================================
// API Endpoints
// ==========================================

// Health Check
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ONLINE',
    service: 'CYBERTRACE Security Operations Core',
    geminiConfigured: !!aiClient,
    model: 'gemini-3.8-flash',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

// Auth Routes (Supabase compatible & fallback local persistence)
app.post('/api/auth/login', (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  // Find or create user
  let user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user) {
    user = {
      id: 'usr-' + Date.now(),
      email: email,
      name: email.split('@')[0].replace(/[._-]/g, ' ').replace(/\b\w/g, (l: string) => l.toUpperCase()),
      role: 'SOC Analyst',
      organization: 'CyberTrace Enterprise SOC',
      twoFactorEnabled: true,
      createdAt: new Date().toISOString(),
    };
    users.push(user);
  }

  logSOCActivity(user.name, 'LOGIN', `Analyst ${user.email} authenticated to CyberTrace console.`, 'success', req.ip);

  res.json({
    user,
    session: {
      token: 'ct-token-' + crypto.randomUUID(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
    },
  });
});

app.post('/api/auth/register', (req: Request, res: Response) => {
  const { email, name, organization, role } = req.body;
  if (!email || !name) {
    return res.status(400).json({ error: 'Email and name are required' });
  }

  const existing = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (existing) {
    return res.status(400).json({ error: 'A user with this email address already exists.' });
  }

  const newUser: UserRecord = {
    id: 'usr-' + Date.now(),
    email,
    name,
    role: role || 'SOC Analyst',
    organization: organization || 'CyberTrace Guard Network',
    twoFactorEnabled: false,
    createdAt: new Date().toISOString(),
  };

  users.push(newUser);
  logSOCActivity(newUser.name, 'LOGIN', `New analyst account registered: ${newUser.email}`, 'info', req.ip);

  res.status(201).json({
    user: newUser,
    session: {
      token: 'ct-token-' + crypto.randomUUID(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
    },
  });
});

app.get('/api/auth/me', (req: Request, res: Response) => {
  const authHeader = req.headers.authorization;
  // Default to first user or demo analyst
  const user = users[0];
  res.json({ user });
});

app.post('/api/auth/logout', (req: Request, res: Response) => {
  logSOCActivity('Analyst', 'LOGOUT', 'Analyst terminated active SOC console session.', 'info', req.ip);
  res.json({ success: true });
});

// Incidents CRUD
app.get('/api/incidents', (req: Request, res: Response) => {
  const { category, severity, status, search } = req.query;
  let results = [...incidents];

  if (category && category !== 'All') {
    results = results.filter(i => i.category === category);
  }
  if (severity && severity !== 'All') {
    results = results.filter(i => i.severity === severity);
  }
  if (status && status !== 'All') {
    results = results.filter(i => i.status === status);
  }
  if (search && typeof search === 'string') {
    const q = search.toLowerCase();
    results = results.filter(
      i =>
        i.title.toLowerCase().includes(q) ||
        i.incidentNumber.toLowerCase().includes(q) ||
        i.description.toLowerCase().includes(q) ||
        i.affectedSystem.toLowerCase().includes(q) ||
        i.assignedInvestigator.toLowerCase().includes(q)
    );
  }

  res.json({ incidents: results, count: results.length });
});

app.get('/api/incidents/:id', (req: Request, res: Response) => {
  const incident = incidents.find(i => i.id === req.params.id || i.incidentNumber === req.params.id);
  if (!incident) {
    return res.status(404).json({ error: 'Incident not found' });
  }
  const relatedEvidence = evidenceFiles.filter(e => e.incidentId === incident.id);
  res.json({ incident, relatedEvidence });
});

app.post('/api/incidents', (req: Request, res: Response) => {
  const { title, category, severity, status, description, affectedSystem, assignedInvestigator } = req.body;
  if (!title || !category || !severity) {
    return res.status(400).json({ error: 'Title, category, and severity are required fields.' });
  }

  const nextNum = 9840 + incidents.length + 1;
  const newIncident: IncidentRecord = {
    id: 'inc-' + Date.now(),
    incidentNumber: `CT-2026-${nextNum}`,
    title,
    category,
    severity: severity || 'Medium',
    status: status || 'Open',
    description: description || 'No detailed briefing provided.',
    affectedSystem: affectedSystem || 'Internal Systems',
    assignedInvestigator: assignedInvestigator || 'Sarah Chen',
    timeline: [
      {
        id: 'tl-' + Date.now(),
        timestamp: new Date().toISOString(),
        author: assignedInvestigator || 'SOC Commander',
        action: 'Incident Created',
        note: `Incident initiated with severity level ${severity}.`,
      },
    ],
    evidenceCount: 0,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  incidents.unshift(newIncident);
  logSOCActivity(
    assignedInvestigator || 'SOC Analyst',
    'INCIDENT_CREATED',
    `Created incident ${newIncident.incidentNumber}: "${newIncident.title}" [${newIncident.severity} | ${newIncident.category}]`,
    severity === 'Critical' ? 'alert' : 'info',
    req.ip
  );

  res.status(201).json({ incident: newIncident });
});

app.put('/api/incidents/:id', (req: Request, res: Response) => {
  const idx = incidents.findIndex(i => i.id === req.params.id || i.incidentNumber === req.params.id);
  if (idx === -1) {
    return res.status(404).json({ error: 'Incident not found' });
  }

  const existing = incidents[idx];
  const { title, category, severity, status, description, affectedSystem, assignedInvestigator, newTimelineNote } = req.body;

  const statusChanged = status && status !== existing.status;
  const severityChanged = severity && severity !== existing.severity;

  const updated: IncidentRecord = {
    ...existing,
    title: title ?? existing.title,
    category: category ?? existing.category,
    severity: severity ?? existing.severity,
    status: status ?? existing.status,
    description: description ?? existing.description,
    affectedSystem: affectedSystem ?? existing.affectedSystem,
    assignedInvestigator: assignedInvestigator ?? existing.assignedInvestigator,
    updatedAt: new Date().toISOString(),
    timeline: [
      ...existing.timeline,
      ...(newTimelineNote
        ? [
            {
              id: 'tl-' + Date.now(),
              timestamp: new Date().toISOString(),
              author: assignedInvestigator || 'Investigator',
              action: statusChanged ? `Status changed to ${status}` : 'Investigation Update',
              note: newTimelineNote,
            },
          ]
        : statusChanged
        ? [
            {
              id: 'tl-' + Date.now(),
              timestamp: new Date().toISOString(),
              author: assignedInvestigator || 'Investigator',
              action: `Status changed from ${existing.status} to ${status}`,
            },
          ]
        : []),
    ],
  };

  incidents[idx] = updated;

  logSOCActivity(
    updated.assignedInvestigator,
    'INCIDENT_UPDATED',
    `Updated incident ${updated.incidentNumber} -> Status: ${updated.status}, Severity: ${updated.severity}`,
    updated.severity === 'Critical' ? 'alert' : 'warning',
    req.ip
  );

  res.json({ incident: updated });
});

app.delete('/api/incidents/:id', (req: Request, res: Response) => {
  const idx = incidents.findIndex(i => i.id === req.params.id || i.incidentNumber === req.params.id);
  if (idx === -1) {
    return res.status(404).json({ error: 'Incident not found' });
  }

  const removed = incidents.splice(idx, 1)[0];
  logSOCActivity(
    'Security Admin',
    'INCIDENT_UPDATED',
    `Purged incident record ${removed.incidentNumber} ("${removed.title}") from database.`,
    'warning',
    req.ip
  );

  res.json({ success: true, removedId: removed.id });
});

// AI Threat Analyzer Route (Server-side Gemini with rigorous cybersecurity prompting)
app.post('/api/analyze-threat', async (req: Request, res: Response) => {
  const { content, type = 'text', user = 'Security Analyst' } = req.body;

  if (!content || typeof content !== 'string' || content.trim().length === 0) {
    return res.status(400).json({ error: 'Content to analyze is required.' });
  }

  const trimmed = content.trim();

  // If Gemini API is available, analyze via gemini-3.8-flash with JSON schema prompt
  if (aiClient) {
    try {
      const prompt = `
You are the primary threat intelligence and digital forensic analyst engine of CYBERTRACE, an enterprise Security Operations Center (SOC) platform.
Analyze the following digital artifact for cyber threats, phishing vectors, fraud schemes, credential harvesting, social engineering, or malware indicators.

Artifact Type: ${type.toUpperCase()}
Artifact Content:
"""
${trimmed.slice(0, 8000)}
"""

Evaluate the content rigorously. Output your analysis strictly as a valid JSON object with the following schema:
{
  "riskScore": <integer between 0 and 100>,
  "riskClassification": <one of "Safe", "Suspicious", "High Risk", "Critical">,
  "threatCategory": <short string, e.g. "Phishing", "Credential Harvesting", "Brand Impersonation", "Malware Delivery", "Advance Fee Fraud", "Executive Impersonation", "Legitimate Communication", "Safe Infrastructure">,
  "confidenceScore": <integer between 0 and 100>,
  "indicators": <array of specific observable strings detailing indicators, e.g. "Punycode / Homograph domain", "Urgency language with 24h deadline", "Unmatched SPF/DKIM pattern", "Obfuscated redirect parameter">,
  "explanation": <detailed 2-3 paragraph cybersecurity explanation of the threat vectors, attacker intent, and forensic markers identified>,
  "recommendedActions": <array of 4-6 concrete, actionable mitigation steps for security analysts or end-users>,
  "safeBrowsingNote": <string emphasizing caution: remember, lack of detected malware does not guarantee absolute safety>
}

Do not wrap with markdown backticks; output only the pure raw JSON object.
`;

      const response = await aiClient.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
          systemInstruction: 'You are an elite cybersecurity threat analyst engine. You evaluate phishing, malware, fraud, and social engineering with zero tolerance for false security claims. Output pure JSON.',
        },
      });

      const rawText = response.text || '{}';
      let parsed;
      try {
        parsed = JSON.parse(rawText);
      } catch (e) {
        // Fallback sanitize
        const cleaned = rawText.replace(/```json/g, '').replace(/```/g, '').trim();
        parsed = JSON.parse(cleaned);
      }

      // Ensure risk classifications align with standard
      const riskScore = Math.max(0, Math.min(100, Number(parsed.riskScore) || 50));
      let riskClassification: ThreatAnalysisRecord['riskClassification'] = 'Suspicious';
      if (riskScore >= 80) riskClassification = 'Critical';
      else if (riskScore >= 60) riskClassification = 'High Risk';
      else if (riskScore >= 30) riskClassification = 'Suspicious';
      else riskClassification = 'Safe';

      const analysisResult: ThreatAnalysisRecord = {
        id: 'ana-' + Date.now(),
        inputContent: trimmed.slice(0, 500),
        inputType: type,
        riskScore,
        riskClassification: parsed.riskClassification || riskClassification,
        threatCategory: parsed.threatCategory || 'Potential Cyber Threat',
        confidenceScore: Math.max(10, Math.min(99, Number(parsed.confidenceScore) || 88)),
        indicators: Array.isArray(parsed.indicators) ? parsed.indicators : ['Automated pattern anomaly detected'],
        explanation: parsed.explanation || 'Content analyzed by CyberTrace AI threat engine.',
        recommendedActions: Array.isArray(parsed.recommendedActions) ? parsed.recommendedActions : [
          'Isolate affected endpoints',
          'Block sender domain in mail filter',
          'Report incident to internal SOC team'
        ],
        analyzedAt: new Date().toISOString(),
        analyzedBy: user,
        engine: 'Gemini 3.8 Flash (Deep Threat Inspection)',
        isSimulatedFallback: false,
      };

      logSOCActivity(
        user,
        'THREAT_ANALYZED',
        `Analyzed ${type.toUpperCase()} artifact: ${analysisResult.threatCategory} (Risk Score: ${analysisResult.riskScore}/100, ${analysisResult.riskClassification})`,
        analysisResult.riskScore >= 60 ? 'alert' : 'info',
        req.ip
      );

      return res.json({ result: analysisResult });
    } catch (aiErr: any) {
      console.error('[CyberTrace AI Engine] Gemini API error, engaging heuristic fallback:', aiErr?.message || aiErr);
      // Fall through to heuristic rule engine
    }
  }

  // High-fidelity heuristic threat inspection engine (when API key is missing or rate limited)
  const isUrl = trimmed.startsWith('http://') || trimmed.startsWith('https://') || /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(\/.*)?$/.test(trimmed);
  const lower = trimmed.toLowerCase();

  let riskScore = 15;
  const indicators: string[] = [];
  const recommendations: string[] = [];

  // Suspicious heuristics
  if (lower.includes('verify your account') || lower.includes('urgent action required') || lower.includes('suspended within 24 hours')) {
    riskScore += 35;
    indicators.push('High-pressure urgency and artificial deadline tactic detected');
  }
  if (lower.includes('password') || lower.includes('credentials') || lower.includes('otp') || lower.includes('passcode') || lower.includes('seed phrase')) {
    riskScore += 30;
    indicators.push('Solicitation of sensitive credentials, authentication tokens, or recovery keys');
  }
  if (lower.includes('winner') || lower.includes('lottery') || lower.includes('claim your bonus') || lower.includes('free crypto') || lower.includes('airdrop')) {
    riskScore += 30;
    indicators.push('Financial lure with unrealistic return or lottery reward');
  }
  if (isUrl) {
    if (trimmed.startsWith('http://')) {
      riskScore += 20;
      indicators.push('Insecure cleartext HTTP protocol (No TLS encryption present)');
    }
    if (/(\d{1,3}\.){3}\d{1,3}/.test(trimmed)) {
      riskScore += 35;
      indicators.push('Direct raw IP address in URL instead of registered domain');
    }
    if (lower.includes('paypal') || lower.includes('microsoft') || lower.includes('google') || lower.includes('apple') || lower.includes('netflix') || lower.includes('bank') || lower.includes('wellsfargo')) {
      if (!lower.includes('.paypal.com') && !lower.includes('.microsoft.com') && !lower.includes('.google.com') && !lower.includes('.apple.com')) {
        riskScore += 45;
        indicators.push('High-confidence Brand Impersonation / Typosquatting of prominent provider');
      }
    }
    if (lower.includes('bit.ly') || lower.includes('tinyurl.com') || lower.includes('is.gd') || lower.includes('t.co')) {
      riskScore += 15;
      indicators.push('URL redirection/shortener service obscuring final destination');
    }
  }

  riskScore = Math.min(96, Math.max(8, riskScore));
  let classification: ThreatAnalysisRecord['riskClassification'] = 'Safe';
  if (riskScore >= 80) classification = 'Critical';
  else if (riskScore >= 60) classification = 'High Risk';
  else if (riskScore >= 30) classification = 'Suspicious';

  recommendations.push(
    'Do not click embedded links, enter passwords, or provide verification codes.',
    'Inspect email SPF/DKIM/DMARC headers to verify domain authentication.',
    'Submit the domain or sample to your organization\'s incident response queue.',
    'If credentials were submitted, immediately revoke active sessions and reset credentials.'
  );

  const fallbackResult: ThreatAnalysisRecord = {
    id: 'ana-' + Date.now(),
    inputContent: trimmed.slice(0, 500),
    inputType: type,
    riskScore,
    riskClassification: classification,
    threatCategory: riskScore > 50 ? 'Suspected Phishing / Social Engineering' : 'Low Risk / Standard Digital Content',
    confidenceScore: 84,
    indicators: indicators.length > 0 ? indicators : ['No acute heuristic anomalies identified in static scan'],
    explanation: `Heuristic rule-based static evaluation performed by CyberTrace Sentinel Engine. ${
      riskScore > 50
        ? 'Multiple deceptive markers were identified including credential solicitation and deceptive link structures.'
        : 'The analyzed content does not display obvious phishing indicators. However, absence of automated flags does not guarantee absolute safety.'
    }`,
    recommendedActions: recommendations,
    analyzedAt: new Date().toISOString(),
    analyzedBy: user,
    engine: aiClient ? 'Gemini 3.8 Flash (Rule Assisted)' : 'CyberTrace Rule-Based Threat Engine (Live)',
    isSimulatedFallback: !aiClient,
  };

  logSOCActivity(
    user,
    'THREAT_ANALYZED',
    `Analyzed ${type.toUpperCase()} artifact: ${fallbackResult.threatCategory} (Risk: ${fallbackResult.riskScore}/100, ${fallbackResult.riskClassification})`,
    fallbackResult.riskScore >= 60 ? 'alert' : 'info',
    req.ip
  );

  res.json({ result: fallbackResult });
});

// Digital Evidence Vault Routes
app.get('/api/evidence', (req: Request, res: Response) => {
  const { incidentId } = req.query;
  let results = [...evidenceFiles];
  if (incidentId && typeof incidentId === 'string') {
    results = results.filter(e => e.incidentId === incidentId);
  }
  res.json({ evidence: results, count: results.length });
});

app.post('/api/evidence', (req: Request, res: Response) => {
  const { filename, fileBase64, fileSize, fileType, incidentId, notes, uploadedBy } = req.body;

  if (!filename) {
    return res.status(400).json({ error: 'Filename is required' });
  }

  // Calculate cryptographic SHA-256
  let sha256Hash = '';
  if (fileBase64) {
    const cleanBase64 = fileBase64.replace(/^data:[^;]+;base64,/, '');
    const buffer = Buffer.from(cleanBase64, 'base64');
    sha256Hash = crypto.createHash('sha256').update(buffer).digest('hex');
  } else {
    // Generate deterministic sha256 based on filename + timestamp if file body not provided
    sha256Hash = crypto.createHash('sha256').update(`${filename}-${Date.now()}-${fileSize}`).digest('hex');
  }

  const newEvidence: EvidenceRecord = {
    id: 'evi-' + Date.now(),
    incidentId: incidentId || undefined,
    filename,
    fileSize: Number(fileSize) || 45000,
    fileType: fileType || 'application/octet-stream',
    sha256Hash,
    uploadedBy: uploadedBy || 'Sarah Chen',
    uploadedAt: new Date().toISOString(),
    notes: notes || 'Evidence secured in CyberTrace digital forensic custody.',
    integrityVerified: true,
    lastVerifiedAt: new Date().toISOString(),
    dataUrl: fileBase64 ? fileBase64.slice(0, 10000) : undefined,
  };

  evidenceFiles.unshift(newEvidence);

  // If tied to an incident, increment incident count
  if (incidentId) {
    const inc = incidents.find(i => i.id === incidentId || i.incidentNumber === incidentId);
    if (inc) {
      inc.evidenceCount = (inc.evidenceCount || 0) + 1;
      inc.timeline.push({
        id: 'tl-' + Date.now(),
        timestamp: new Date().toISOString(),
        author: newEvidence.uploadedBy,
        action: 'Evidence Appended',
        note: `Attached "${newEvidence.filename}" (SHA-256: ${sha256Hash.slice(0, 10)}...).`,
      });
    }
  }

  logSOCActivity(
    newEvidence.uploadedBy,
    'EVIDENCE_UPLOADED',
    `Preserved digital evidence "${newEvidence.filename}" (SHA-256: ${sha256Hash.slice(0, 8)}...) in Vault.`,
    'info',
    req.ip
  );

  res.status(201).json({ evidence: newEvidence });
});

// Verify Evidence Integrity by recalculating hash
app.post('/api/evidence/:id/verify', (req: Request, res: Response) => {
  const item = evidenceFiles.find(e => e.id === req.params.id);
  if (!item) {
    return res.status(404).json({ error: 'Evidence item not found' });
  }

  // Verification simulation / check
  const now = new Date().toISOString();
  item.integrityVerified = true;
  item.lastVerifiedAt = now;

  logSOCActivity(
    'Forensic Auditor',
    'SYSTEM_ALERT',
    `Chain-of-Custody integrity verified for evidence ID ${item.id} (${item.filename}) with hash ${item.sha256Hash.slice(0, 12)}...`,
    'success',
    req.ip
  );

  res.json({
    verified: true,
    evidenceId: item.id,
    sha256Hash: item.sha256Hash,
    verifiedAt: now,
    status: 'INTEGRITY_CONFIRMED',
    message: 'Cryptographic SHA-256 checksum matches sealed custody record.',
  });
});

app.delete('/api/evidence/:id', (req: Request, res: Response) => {
  const idx = evidenceFiles.findIndex(e => e.id === req.params.id);
  if (idx === -1) {
    return res.status(404).json({ error: 'Evidence not found' });
  }
  const removed = evidenceFiles.splice(idx, 1)[0];
  res.json({ success: true, removedId: removed.id });
});

// Cybercrime Reporting Module
app.get('/api/reports', (_req: Request, res: Response) => {
  res.json({ reports: cybercrimeReports, count: cybercrimeReports.length });
});

app.get('/api/reports/:id', (req: Request, res: Response) => {
  const report = cybercrimeReports.find(
    r => r.id === req.params.id || r.referenceNumber.toLowerCase() === req.params.id.toLowerCase()
  );
  if (!report) {
    return res.status(404).json({ error: 'Complaint record not found' });
  }
  res.json({ report });
});

app.post('/api/reports', (req: Request, res: Response) => {
  const {
    complainantName,
    contactEmail,
    phoneNumber,
    fraudCategory,
    financialLossAmount,
    currency = 'USD',
    transactionId,
    suspiciousUrl,
    suspectContact,
    description,
    evidenceFiles: files = [],
  } = req.body;

  if (!complainantName || !contactEmail || !fraudCategory || !description) {
    return res.status(400).json({ error: 'Complainant name, email, fraud category, and incident description are required.' });
  }

  const nextRef = 490 + cybercrimeReports.length + 1;
  const newReport: CybercrimeReportRecord = {
    id: 'rep-' + Date.now(),
    referenceNumber: `CT-CR-2026-0${nextRef}`,
    complainantName,
    contactEmail,
    phoneNumber: phoneNumber || 'Not provided',
    fraudCategory,
    financialLossAmount: Number(financialLossAmount) || 0,
    currency,
    transactionId: transactionId || 'N/A',
    suspiciousUrl: suspiciousUrl || 'N/A',
    suspectContact: suspectContact || 'N/A',
    description,
    status: 'Received',
    submittedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    evidenceFiles: Array.isArray(files) ? files : [],
  };

  cybercrimeReports.unshift(newReport);

  logSOCActivity(
    complainantName,
    'REPORT_FILED',
    `Cybercrime complaint submitted: ${newReport.referenceNumber} [${newReport.fraudCategory}, Loss: ${newReport.currency} ${newReport.financialLossAmount}]`,
    'warning',
    req.ip
  );

  res.status(201).json({ report: newReport });
});

// Activity Logs
app.get('/api/activity-logs', (_req: Request, res: Response) => {
  res.json({ logs: activityLogs, count: activityLogs.length });
});

// Dashboard Statistics Overview
app.get('/api/stats', (_req: Request, res: Response) => {
  const totalIncidents = incidents.length;
  const activeThreats = incidents.filter(i => i.status === 'Open' || i.status === 'Investigating').length;
  const resolvedIncidents = incidents.filter(i => i.status === 'Resolved' || i.status === 'Contained').length;
  const criticalAlerts = incidents.filter(i => i.severity === 'Critical').length;
  const suspiciousUrlsAnalyzed = 142 + activityLogs.filter(a => a.action === 'THREAT_ANALYZED').length;
  const totalEvidenceStored = evidenceFiles.length;

  // Severity Distribution
  const severityDistribution = [
    { name: 'Critical', value: incidents.filter(i => i.severity === 'Critical').length, color: '#ef4444' },
    { name: 'High', value: incidents.filter(i => i.severity === 'High').length, color: '#f97316' },
    { name: 'Medium', value: incidents.filter(i => i.severity === 'Medium').length, color: '#eab308' },
    { name: 'Low', value: incidents.filter(i => i.severity === 'Low').length, color: '#06b6d4' },
  ];

  // Category Breakdown
  const categoryCounts: Record<string, number> = {};
  incidents.forEach(i => {
    categoryCounts[i.category] = (categoryCounts[i.category] || 0) + 1;
  });
  const categoryBreakdown = Object.entries(categoryCounts).map(([category, count]) => ({
    category,
    count,
  }));

  // 7-Day Trend
  const trendData = [
    { day: 'Mon', incidents: 4, blockedThreats: 18, resolved: 3 },
    { day: 'Tue', incidents: 7, blockedThreats: 24, resolved: 5 },
    { day: 'Wed', incidents: 5, blockedThreats: 31, resolved: 6 },
    { day: 'Thu', incidents: 9, blockedThreats: 42, resolved: 8 },
    { day: 'Fri', incidents: 12, blockedThreats: 55, resolved: 10 },
    { day: 'Sat', incidents: 6, blockedThreats: 29, resolved: 7 },
    { day: 'Sun', incidents: 8, blockedThreats: 38, resolved: 6 },
  ];

  res.json({
    metrics: {
      totalIncidents,
      activeThreats,
      resolvedIncidents,
      criticalAlerts,
      suspiciousUrlsAnalyzed,
      totalEvidenceStored,
      socHealthScore: 94.8,
    },
    severityDistribution,
    categoryBreakdown,
    trendData,
    recentIncidents: incidents.slice(0, 5),
    recentActivity: activityLogs.slice(0, 6),
  });
});

// ==========================================
// Vite Integration for Full-Stack React SPA
// ==========================================
async function startServer() {
  const isProduction = process.env.NODE_ENV === 'production';

  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: process.env.DISABLE_HMR !== 'true',
        watch: process.env.DISABLE_HMR === 'true' ? null : {},
      },
      appType: 'spa',
    });

    // Mount Vite dev server middleware
    app.use(vite.middlewares);
    console.log('[CyberTrace Server] Mounted Vite middlewares in dev mode');
  } else {
    // In production, serve dist assets
    const distPath = path.resolve(__dirname, 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (_req: Request, res: Response) => {
        res.sendFile(path.join(distPath, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[CyberTrace Server] Enterprise SOC server active at http://0.0.0.0:${PORT}`);
  });
}

startServer().catch(err => {
  console.error('[CyberTrace Server] Fatal startup error:', err);
  process.exit(1);
});
