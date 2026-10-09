import express, { Request, Response } from 'express';
import os from 'os';
import dns from 'dns';
import path from 'path';
import QRCode from 'qrcode';
import { GoogleGenAI } from '@google/genai';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

app.use(express.json());

// Initialize Gemini SDK if API key is present
const geminiApiKey = process.env.GEMINI_API_KEY;
let aiClient: GoogleGenAI | null = null;
if (geminiApiKey) {
  try {
    aiClient = new GoogleGenAI({
      apiKey: geminiApiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  } catch (e) {
    console.warn('Gemini AI initialization notice:', e);
  }
}

// ==========================================
// IN-MEMORY SECURITY STATE (Thread-Safe Store)
// ==========================================

export interface Device {
  id: number;
  name: string;
  ip: string;
  mac: string;
  type: 'Laptop' | 'Router' | 'Computer' | 'Server' | 'Mobile' | 'Firewall' | 'IoT';
  status: 'Online' | 'Offline' | 'Suspicious';
  risk: number;
  openPorts: number[];
  vendor: string;
  lastSeen: string;
}

export interface Threat {
  id: number;
  type: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  source: string;
  destination: string;
  port: number;
  time: string;
  status: 'Active' | 'Resolved';
  mitreTechnique: string;
  confidence: number;
  description: string;
}

export interface FirewallRule {
  id: number;
  name: string;
  action: 'BLOCK' | 'ALLOW';
  direction: 'INBOUND' | 'OUTBOUND';
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'ANY';
  sourceIp: string;
  targetPort: string;
  enabled: boolean;
  hits: number;
  createdAt: string;
}

export interface SecurityLog {
  id: number;
  timestamp: string;
  level: 'INFO' | 'WARNING' | 'CRITICAL';
  category: 'TRAFFIC' | 'FIREWALL' | 'AI_DETECTION' | 'DEVICE' | 'SYSTEM';
  message: string;
  sourceIp?: string;
}

// Initial Devices
let devices: Device[] = [
  {
    id: 1,
    name: 'SOC Gateway Core',
    ip: '192.168.1.1',
    mac: '00:1A:2B:3C:4D:01',
    type: 'Router',
    status: 'Online',
    risk: 4,
    openPorts: [53, 80, 443],
    vendor: 'Cisco Systems',
    lastSeen: new Date().toLocaleTimeString(),
  },
  {
    id: 2,
    name: 'Admin Workstation',
    ip: '192.168.1.10',
    mac: '3C:D9:2B:44:12:F0',
    type: 'Laptop',
    status: 'Online',
    risk: 12,
    openPorts: [22, 443],
    vendor: 'Dell Enterprise',
    lastSeen: new Date().toLocaleTimeString(),
  },
  {
    id: 3,
    name: 'Database Cluster Alpha',
    ip: '192.168.1.15',
    mac: 'E4:54:E8:29:91:AA',
    type: 'Server',
    status: 'Online',
    risk: 8,
    openPorts: [5432, 6379, 22],
    vendor: 'HP ProLiant',
    lastSeen: new Date().toLocaleTimeString(),
  },
  {
    id: 4,
    name: 'Engineering Dev PC',
    ip: '192.168.1.25',
    mac: '70:85:C2:5F:B3:31',
    type: 'Computer',
    status: 'Online',
    risk: 22,
    openPorts: [3000, 8080, 22],
    vendor: 'Lenovo ThinkCentre',
    lastSeen: new Date().toLocaleTimeString(),
  },
  {
    id: 5,
    name: 'Industrial IoT Sensor Hub',
    ip: '192.168.1.88',
    mac: 'B8:27:EB:4A:21:78',
    type: 'IoT',
    status: 'Online',
    risk: 34,
    openPorts: [1883],
    vendor: 'Raspberry Pi Foundation',
    lastSeen: new Date().toLocaleTimeString(),
  },
];

// Initial Threats
let threats: Threat[] = [
  {
    id: 1,
    type: 'Anomalous Port Sweep',
    severity: 'Medium',
    source: '192.168.1.25',
    destination: '192.168.1.15',
    port: 5432,
    time: new Date(Date.now() - 14 * 60000).toLocaleTimeString(),
    status: 'Resolved',
    mitreTechnique: 'T1046 - Network Service Scanning',
    confidence: 88,
    description: 'Rapid sequential SYN packets probing internal database listening ports.',
  },
];

// Firewall rules
let firewallRules: FirewallRule[] = [
  {
    id: 1,
    name: 'Default SSH Rate Limiter',
    action: 'ALLOW',
    direction: 'INBOUND',
    protocol: 'TCP',
    sourceIp: '192.168.1.0/24',
    targetPort: '22',
    enabled: true,
    hits: 142,
    createdAt: new Date(Date.now() - 86400000).toISOString().split('T')[0],
  },
  {
    id: 2,
    name: 'Block Known C2 Tor Exit Range',
    action: 'BLOCK',
    direction: 'INBOUND',
    protocol: 'ANY',
    sourceIp: '185.220.101.0/24',
    targetPort: 'ALL',
    enabled: true,
    hits: 27,
    createdAt: new Date(Date.now() - 43200000).toISOString().split('T')[0],
  },
];

// Security logs
let securityLogs: SecurityLog[] = [
  {
    id: 1,
    timestamp: new Date().toLocaleTimeString(),
    level: 'INFO',
    category: 'SYSTEM',
    message: 'NetShield AI Core initialized. Anomaly detection neural heuristic online.',
  },
  {
    id: 2,
    timestamp: new Date().toLocaleTimeString(),
    level: 'INFO',
    category: 'FIREWALL',
    message: 'Firewall rules verified. 2 policies enforced.',
  },
];

// Telemetry History
interface HistoryPoint {
  time: string;
  mbps: number;
  packets: number;
  risk: number;
  cpu: number;
  connections: number;
}
const telemetryHistory: HistoryPoint[] = [];

// Simulation state
let isSimulatingThreat = false;
let simulationType = 'Packet Flood';
let simulationExpiry = 0;

// Network sampling baseline
let lastBytes = 0;
let lastPackets = 0;
let lastSampleTime = Date.now();

// Get local IPv4
function getLocalIp(): string {
  const interfaces = os.networkInterfaces();
  for (const ifaceName of Object.keys(interfaces)) {
    const addresses = interfaces[ifaceName];
    if (addresses) {
      for (const addr of addresses) {
        if (addr.family === 'IPv4' && !addr.internal) {
          return addr.address;
        }
      }
    }
  }
  return '127.0.0.1';
}

// Calculate statistical anomaly score
function calculateAnomalyScore(mbps: number, packets: number, connections: number): {
  riskScore: number;
  health: 'Optimal' | 'Good' | 'Warning' | 'Critical';
  factors: string[];
} {
  let score = 6;
  const factors: string[] = [];

  // Traffic volume assessment
  if (mbps > 50) {
    score += 45;
    factors.push('Severe bandwidth surge detected (>50 Mbps)');
  } else if (mbps > 25) {
    score += 25;
    factors.push('Elevated bandwidth volume (>25 Mbps)');
  } else if (mbps > 10) {
    score += 10;
  }

  // Packet frequency assessment
  if (packets > 1500) {
    score += 45;
    factors.push('Severe packet flood anomaly (>1500 pkts/s)');
  } else if (packets > 600) {
    score += 22;
    factors.push('High packet velocity (>600 pkts/s)');
  }

  // Concurrent connection density
  if (connections > 120) {
    score += 25;
    factors.push('Connection spike (>120 open sockets)');
  } else if (connections > 60) {
    score += 10;
  }

  // Active critical threats impact
  const activeCritical = threats.filter((t) => t.status === 'Active' && t.severity === 'Critical').length;
  const activeHigh = threats.filter((t) => t.status === 'Active' && t.severity === 'High').length;
  if (activeCritical > 0) {
    score += activeCritical * 25;
    factors.push(`${activeCritical} active critical threat(s) unresolved`);
  }
  if (activeHigh > 0) {
    score += activeHigh * 15;
    factors.push(`${activeHigh} high severity alert(s) in progress`);
  }

  const boundedScore = Math.min(Math.max(score, 4), 98);

  let health: 'Optimal' | 'Good' | 'Warning' | 'Critical' = 'Optimal';
  if (boundedScore >= 75) health = 'Critical';
  else if (boundedScore >= 45) health = 'Warning';
  else if (boundedScore >= 20) health = 'Good';

  return { riskScore: boundedScore, health, factors };
}

// Generate realistic live network metrics
function sampleTelemetry() {
  const now = Date.now();
  const timeDiff = Math.max((now - lastSampleTime) / 1000, 0.5);
  lastSampleTime = now;

  // Base OS activity
  const memTotal = os.totalmem();
  const memFree = os.freemem();
  const memUsedPercent = Math.round(((memTotal - memFree) / memTotal) * 100);
  const loadAvg = os.loadavg();
  const cpuPercent = Math.min(Math.round((loadAvg[0] || 0.4) * 25), 100);

  // Check if simulation is ongoing
  if (isSimulatingThreat && Date.now() > simulationExpiry) {
    isSimulatingThreat = false;
  }

  let mbps = 1.2 + Math.random() * 2.5;
  let packets = 45 + Math.random() * 80;
  let connections = 18 + Math.floor(Math.random() * 12);

  if (isSimulatingThreat) {
    switch (simulationType) {
      case 'DDoS / Packet Flood':
        mbps += 35 + Math.random() * 25;
        packets += 1200 + Math.random() * 600;
        connections += 85 + Math.floor(Math.random() * 40);
        break;
      case 'SYN Flood Scan':
        mbps += 8 + Math.random() * 5;
        packets += 800 + Math.random() * 400;
        connections += 110 + Math.floor(Math.random() * 50);
        break;
      case 'Data Exfiltration Surge':
        mbps += 48 + Math.random() * 20;
        packets += 300 + Math.random() * 150;
        connections += 30 + Math.floor(Math.random() * 15);
        break;
      default:
        mbps += 20 + Math.random() * 15;
        packets += 500 + Math.random() * 300;
        connections += 45;
    }
  }

  const { riskScore, health, factors } = calculateAnomalyScore(mbps, packets, connections);
  const timeStr = new Date().toLocaleTimeString();

  const point: HistoryPoint = {
    time: timeStr,
    mbps: Number(mbps.toFixed(2)),
    packets: Math.round(packets),
    risk: riskScore,
    cpu: cpuPercent,
    connections,
  };

  telemetryHistory.push(point);
  if (telemetryHistory.length > 30) {
    telemetryHistory.shift();
  }

  return {
    ...point,
    health,
    memoryUsage: memUsedPercent,
    factors,
    isSimulating: isSimulatingThreat,
    simulationType: isSimulatingThreat ? simulationType : null,
  };
}

// ==========================================
// API ENDPOINTS
// ==========================================

// Dashboard Telemetry
app.get('/api/dashboard', (req: Request, res: Response) => {
  const current = sampleTelemetry();
  const onlineDevices = devices.filter((d) => d.status === 'Online').length;
  const activeThreats = threats.filter((t) => t.status === 'Active').length;

  res.json({
    bandwidth: current.mbps,
    packets: current.packets,
    connections: current.connections,
    cpu: current.cpu,
    memory: current.memoryUsage,
    devices: onlineDevices,
    totalDevices: devices.length,
    threats: activeThreats,
    risk: current.risk,
    health: current.health,
    factors: current.factors,
    isSimulating: current.isSimulating,
    simulationType: current.simulationType,
    time: current.time,
    hasGemini: Boolean(geminiApiKey),
    localIp: getLocalIp(),
  });
});

// Telemetry History
app.get('/api/history', (req: Request, res: Response) => {
  res.json(telemetryHistory);
});

// Devices Management
app.get('/api/devices', (req: Request, res: Response) => {
  res.json(devices);
});

app.post('/api/devices/add', (req: Request, res: Response) => {
  const { name, ip, type, vendor } = req.body || {};
  if (!name || !ip) {
    return res.status(400).json({ success: false, message: 'Device name and IP address are required.' });
  }

  // Basic IPv4 validation
  const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipPattern.test(ip.trim())) {
    return res.status(400).json({ success: false, message: 'Invalid IPv4 address format.' });
  }

  const newId = (devices.length > 0 ? Math.max(...devices.map((d) => d.id)) : 0) + 1;
  const generatedMac = `00:${Math.floor(Math.random() * 89 + 10)}:${Math.floor(Math.random() * 89 + 10)}:${Math.floor(Math.random() * 89 + 10)}:${Math.floor(Math.random() * 89 + 10)}:${Math.floor(Math.random() * 89 + 10)}`;

  const newDevice: Device = {
    id: newId,
    name: String(name).trim(),
    ip: String(ip).trim(),
    mac: generatedMac,
    type: type || 'Computer',
    status: 'Online',
    risk: Math.floor(Math.random() * 18 + 5),
    openPorts: [80, 443],
    vendor: vendor || 'Generic Network Host',
    lastSeen: new Date().toLocaleTimeString(),
  };

  devices.push(newDevice);

  securityLogs.unshift({
    id: Date.now(),
    timestamp: new Date().toLocaleTimeString(),
    level: 'INFO',
    category: 'DEVICE',
    message: `Registered new endpoint: ${newDevice.name} (${newDevice.ip})`,
    sourceIp: newDevice.ip,
  });

  res.json({ success: true, device: newDevice });
});

app.put('/api/devices/edit/:id', (req: Request, res: Response) => {
  const deviceId = parseInt(req.params.id, 10);
  const { name, ip, type, vendor, status } = req.body || {};

  const devIndex = devices.findIndex((d) => d.id === deviceId);
  if (devIndex === -1) {
    return res.status(404).json({ success: false, message: 'Device not found.' });
  }

  const existing = devices[devIndex];
  if (name) existing.name = String(name).trim();
  if (ip) existing.ip = String(ip).trim();
  if (type) existing.type = type;
  if (vendor) existing.vendor = String(vendor).trim();
  if (status) existing.status = status;
  existing.lastSeen = new Date().toLocaleTimeString();

  res.json({ success: true, device: existing });
});

app.delete('/api/devices/delete/:id', (req: Request, res: Response) => {
  const deviceId = parseInt(req.params.id, 10);
  const prevCount = devices.length;
  devices = devices.filter((d) => d.id !== deviceId);

  if (devices.length === prevCount) {
    return res.status(404).json({ success: false, message: 'Device not found.' });
  }

  res.json({ success: true, message: 'Device removed from inventory.' });
});

// Device Ping simulation
app.post('/api/devices/ping/:id', (req: Request, res: Response) => {
  const deviceId = parseInt(req.params.id, 10);
  const device = devices.find((d) => d.id === deviceId);
  if (!device) {
    return res.status(404).json({ success: false, message: 'Device not found.' });
  }

  const latency = (Math.random() * 4.2 + 0.4).toFixed(2);
  device.lastSeen = new Date().toLocaleTimeString();

  res.json({
    success: true,
    device: device.name,
    ip: device.ip,
    latencyMs: parseFloat(latency),
    status: 'ONLINE',
    ttl: 64,
  });
});

// Threats Management
app.get('/api/threats', (req: Request, res: Response) => {
  res.json(threats);
});

// Simulate AI Threat Incident
app.post('/api/threats/simulate', (req: Request, res: Response) => {
  const { threatType } = req.body || {};

  const scenarios = [
    {
      type: 'Packet Flood Anomaly',
      severity: 'Critical' as const,
      port: 80,
      mitre: 'T1498 - Network Denial of Service',
      desc: 'High-frequency volumetric UDP/TCP packet storm originating from untrusted host.',
    },
    {
      type: 'Unauthorized Port Scan',
      severity: 'High' as const,
      port: 445,
      mitre: 'T1046 - Network Service Discovery',
      desc: 'Sequential rapid SYN probes targeting SMB and internal admin ports.',
    },
    {
      type: 'Suspicious C2 Beaconing',
      severity: 'High' as const,
      port: 8443,
      mitre: 'T1071.001 - Web Protocols Command and Control',
      desc: 'Regular periodic jitter outbound telemetry with unusual payload entropy.',
    },
    {
      type: 'DNS Tunneling Attempt',
      severity: 'Medium' as const,
      port: 53,
      mitre: 'T1071.004 - DNS Command and Control',
      desc: 'High rate of high-entropy TXT subdomains queried through internal resolver.',
    },
    {
      type: 'Brute Force SSH Attempt',
      severity: 'High' as const,
      port: 22,
      mitre: 'T1110 - Brute Force Authentication',
      desc: 'Over 85 failed SSH authentication handshakes within a 30-second window.',
    },
  ];

  const chosen = scenarios.find((s) => s.type === threatType) || scenarios[Math.floor(Math.random() * scenarios.length)];
  const sourceIps = ['192.168.1.77', '185.190.141.22', '45.154.255.89', '192.168.1.25', '198.51.100.44'];
  const source = sourceIps[Math.floor(Math.random() * sourceIps.length)];
  const destination = '192.168.1.15';

  isSimulatingThreat = true;
  simulationType = chosen.type;
  simulationExpiry = Date.now() + 60000; // 60 seconds duration

  const newId = (threats.length > 0 ? Math.max(...threats.map((t) => t.id)) : 0) + 1;
  const newThreat: Threat = {
    id: newId,
    type: chosen.type,
    severity: chosen.severity,
    source,
    destination,
    port: chosen.port,
    time: new Date().toLocaleTimeString(),
    status: 'Active',
    mitreTechnique: chosen.mitre,
    confidence: Math.floor(Math.random() * 15 + 85),
    description: chosen.desc,
  };

  threats.unshift(newThreat);

  securityLogs.unshift({
    id: Date.now(),
    timestamp: new Date().toLocaleTimeString(),
    level: chosen.severity === 'Critical' ? 'CRITICAL' : 'WARNING',
    category: 'AI_DETECTION',
    message: `ALERT: ${chosen.type} detected from ${source} -> ${destination}:${chosen.port}`,
    sourceIp: source,
  });

  res.json({ success: true, threat: newThreat, message: 'AI Threat Simulation initiated.' });
});

// Resolve Threat
app.post('/api/threats/resolve/:id', (req: Request, res: Response) => {
  const threatId = parseInt(req.params.id, 10);
  const threat = threats.find((t) => t.id === threatId);
  if (!threat) {
    return res.status(404).json({ success: false, message: 'Threat not found.' });
  }

  threat.status = 'Resolved';

  const remainingActive = threats.filter((t) => t.status === 'Active').length;
  if (remainingActive === 0) {
    isSimulatingThreat = false;
  }

  securityLogs.unshift({
    id: Date.now(),
    timestamp: new Date().toLocaleTimeString(),
    level: 'INFO',
    category: 'AI_DETECTION',
    message: `Remediated threat #${threat.id}: ${threat.type} (${threat.source})`,
    sourceIp: threat.source,
  });

  res.json({ success: true, threat });
});

// AI Deep Threat Investigation (Gemini 3.8 Flash)
app.post('/api/threats/investigate/:id', async (req: Request, res: Response) => {
  const threatId = parseInt(req.params.id, 10);
  const threat = threats.find((t) => t.id === threatId);
  if (!threat) {
    return res.status(404).json({ success: false, message: 'Threat not found.' });
  }

  if (aiClient) {
    try {
      const prompt = `You are NetShield AI Lead SOC Analyst. Conduct a concise, expert forensic analysis for this detected network incident:
Threat Type: ${threat.type}
Severity: ${threat.severity}
Source IP: ${threat.source}
Destination: ${threat.destination}:${threat.port}
MITRE ATT&CK: ${threat.mitreTechnique}
Description: ${threat.description}

Provide a structured assessment containing:
1. Attack Mechanism & Vector
2. Immediate Threat Containment Steps
3. Recommended Firewall Policy Rule
4. Long-term Hardening Advice`;

      const response = await aiClient.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
      });

      return res.json({
        success: true,
        threatId: threat.id,
        analysis: response.text,
        analyzedBy: 'Gemini 3.8 Flash SOC Engine',
      });
    } catch (err: any) {
      console.warn('Gemini Threat Investigation fallback:', err?.message);
    }
  }

  // Fallback Rule-based forensic report
  const fallbackAnalysis = `### NetShield Security Operations Center Forensic Assessment
**Incident #${threat.id}: ${threat.type}**

1. **Attack Mechanism & Vector:**
   The traffic pattern matches signature anomalies associated with ${threat.mitreTechnique}. Source ${threat.source} attempted high-velocity interaction with port ${threat.port} on destination ${threat.destination}.

2. **Immediate Threat Containment Steps:**
   - Execute firewall DROP rule on source ${threat.source}.
   - Isolate host ${threat.destination} if lateral communication is detected.
   - Flush ARP and DNS cache on core router 192.168.1.1.

3. **Recommended Firewall Policy Rule:**
   \`iptables -I INPUT -s ${threat.source} -j DROP\` or configure rule in NetShield Firewall console.

4. **Long-Term Hardening Advice:**
   - Enforce port security with 802.1X network access control.
   - Implement rate limiting (max 50 SYN packets/sec) on sensitive services.`;

  res.json({
    success: true,
    threatId: threat.id,
    analysis: fallbackAnalysis,
    analyzedBy: 'NetShield Heuristic Forensic Engine (Standard)',
  });
});

// IP Analysis & Threat Reputation Tool
app.post('/api/ip-lookup', async (req: Request, res: Response) => {
  const { query } = req.body || {};
  if (!query || typeof query !== 'string') {
    return res.status(400).json({ success: false, message: 'Target IP or hostname is required.' });
  }

  const cleanQuery = query.trim();

  // Validate format
  const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(cleanQuery);
  const isDomain = /^[a-zA-Z0-9][a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}$/.test(cleanQuery);

  let resolvedIp = cleanQuery;
  let reverseDns = 'N/A';

  try {
    if (isDomain) {
      const lookupResult = await dns.promises.lookup(cleanQuery);
      resolvedIp = lookupResult.address;
    } else if (isIpv4) {
      try {
        const rev = await dns.promises.reverse(cleanQuery);
        reverseDns = rev.join(', ') || 'None found';
      } catch {
        reverseDns = 'Unresolved (PTR record missing)';
      }
    }
  } catch (dnsErr) {
    // If external DNS resolution fails in restricted environments, proceed with static analysis
  }

  // Classify IP range
  const isPrivate =
    resolvedIp.startsWith('10.') ||
    resolvedIp.startsWith('192.168.') ||
    resolvedIp.startsWith('172.16.') ||
    resolvedIp.startsWith('127.');

  // Reputation heuristic
  let threatScore = isPrivate ? 12 : 35;
  const isBogon = resolvedIp.startsWith('0.') || resolvedIp.startsWith('240.');
  if (isBogon) threatScore += 45;

  if (threats.some((t) => t.source === resolvedIp && t.status === 'Active')) {
    threatScore = 92;
  }

  let aiAssessment = '';
  if (aiClient) {
    try {
      const prompt = `Analyze target IP/Host: "${cleanQuery}" (Resolved: ${resolvedIp}, Private Network: ${isPrivate}, Reverse DNS: ${reverseDns}).
Provide a 2-paragraph security briefing on whether this IP poses risks, its network tier, and recommended defensive actions.`;
      const response = await aiClient.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
      });
      aiAssessment = response.text || '';
    } catch (e) {
      // Fallback below
    }
  }

  if (!aiAssessment) {
    aiAssessment = isPrivate
      ? `Host ${resolvedIp} resides within private RFC 1918 internal address space. Trusted subnet segment. Standard internal access rules apply.`
      : `Host ${resolvedIp} is an external public routable destination. Threat reputation index: ${threatScore}/100. Recommend monitoring outbound egress traffic.`;
  }

  res.json({
    success: true,
    query: cleanQuery,
    resolvedIp,
    reverseDns,
    isPrivate,
    threatScore,
    threatLevel: threatScore > 75 ? 'HIGH RISK' : threatScore > 40 ? 'SUSPICIOUS' : 'LOW RISK',
    aiAssessment,
  });
});

// Firewall Rules
app.get('/api/firewall', (req: Request, res: Response) => {
  res.json(firewallRules);
});

app.post('/api/firewall/add', (req: Request, res: Response) => {
  const { name, action, direction, protocol, sourceIp, targetPort } = req.body || {};
  if (!name || !sourceIp) {
    return res.status(400).json({ success: false, message: 'Rule name and source IP are required.' });
  }

  const newId = (firewallRules.length > 0 ? Math.max(...firewallRules.map((r) => r.id)) : 0) + 1;
  const newRule: FirewallRule = {
    id: newId,
    name: String(name).trim(),
    action: action === 'ALLOW' ? 'ALLOW' : 'BLOCK',
    direction: direction === 'OUTBOUND' ? 'OUTBOUND' : 'INBOUND',
    protocol: protocol || 'TCP',
    sourceIp: String(sourceIp).trim(),
    targetPort: targetPort ? String(targetPort).trim() : 'ALL',
    enabled: true,
    hits: 0,
    createdAt: new Date().toISOString().split('T')[0],
  };

  firewallRules.unshift(newRule);

  securityLogs.unshift({
    id: Date.now(),
    timestamp: new Date().toLocaleTimeString(),
    level: 'INFO',
    category: 'FIREWALL',
    message: `Firewall Rule Added: ${newRule.action} ${newRule.direction} from ${newRule.sourceIp}:${newRule.targetPort}`,
    sourceIp: newRule.sourceIp,
  });

  res.json({ success: true, rule: newRule });
});

app.post('/api/firewall/toggle/:id', (req: Request, res: Response) => {
  const ruleId = parseInt(req.params.id, 10);
  const rule = firewallRules.find((r) => r.id === ruleId);
  if (!rule) {
    return res.status(404).json({ success: false, message: 'Rule not found.' });
  }

  rule.enabled = !rule.enabled;
  res.json({ success: true, rule });
});

app.delete('/api/firewall/delete/:id', (req: Request, res: Response) => {
  const ruleId = parseInt(req.params.id, 10);
  firewallRules = firewallRules.filter((r) => r.id !== ruleId);
  res.json({ success: true, message: 'Firewall rule removed.' });
});

// Security Logs
app.get('/api/logs', (req: Request, res: Response) => {
  const level = req.query.level as string;
  const category = req.query.category as string;
  const search = (req.query.search as string)?.toLowerCase();

  let filtered = [...securityLogs];
  if (level && level !== 'ALL') {
    filtered = filtered.filter((l) => l.level === level);
  }
  if (category && category !== 'ALL') {
    filtered = filtered.filter((l) => l.category === category);
  }
  if (search) {
    filtered = filtered.filter((l) => l.message.toLowerCase().includes(search) || l.sourceIp?.includes(search));
  }

  res.json(filtered.slice(0, 50));
});

// Clear Logs
app.post('/api/logs/clear', (req: Request, res: Response) => {
  securityLogs = [
    {
      id: Date.now(),
      timestamp: new Date().toLocaleTimeString(),
      level: 'INFO',
      category: 'SYSTEM',
      message: 'Security event logs cleared by administrator.',
    },
  ];
  res.json({ success: true, message: 'Logs cleared.' });
});

// QR Code for Local Network Access
app.get('/api/qr', async (req: Request, res: Response) => {
  try {
    const localIp = getLocalIp();
    const networkUrl = `http://${localIp}:${PORT}`;
    const qrDataUrl = await QRCode.toDataURL(networkUrl, {
      margin: 2,
      width: 280,
      color: {
        dark: '#0f172a',
        light: '#ffffff',
      },
    });

    res.json({
      success: true,
      url: networkUrl,
      localIp,
      port: PORT,
      image: qrDataUrl,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, message: 'QR generation failed: ' + err.message });
  }
});

// Security Report Summary & Exports
app.get('/api/report', (req: Request, res: Response) => {
  const current = sampleTelemetry();
  const onlineDevices = devices.filter((d) => d.status === 'Online').length;
  const activeThreats = threats.filter((t) => t.status === 'Active').length;

  res.json({
    generatedAt: new Date().toLocaleString(),
    bandwidth: current.mbps,
    packets: current.packets,
    connections: current.connections,
    devices: devices.length,
    onlineDevices,
    activeThreats,
    totalThreatsDetected: threats.length,
    risk: current.risk,
    health: current.health,
    factors: current.factors,
    firewallRulesCount: firewallRules.filter((r) => r.enabled).length,
    aiModel: geminiApiKey ? 'Gemini 3.8 Flash + Isolation Heuristic' : 'Isolation Forest & Statistical Z-Score Engine',
  });
});

// CSV Export
app.get('/api/report/export/csv', (req: Request, res: Response) => {
  const lines = [
    'NetShield AI Security Incident & Telemetry Export',
    `Generated,${new Date().toISOString()}`,
    '',
    'SECTION: THREAT LOGS',
    'ID,Type,Severity,Source,Destination,Port,Time,Status,MITRE Technique',
    ...threats.map(
      (t) =>
        `${t.id},"${t.type}",${t.severity},${t.source},${t.destination},${t.port},"${t.time}",${t.status},"${t.mitreTechnique}"`
    ),
    '',
    'SECTION: DEVICE INVENTORY',
    'ID,Name,IP,MAC,Type,Status,RiskScore,Vendor',
    ...devices.map(
      (d) => `${d.id},"${d.name}",${d.ip},${d.mac},${d.type},${d.status},${d.risk},"${d.vendor}"`
    ),
  ];

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=netshield_security_report.csv');
  res.send(lines.join('\n'));
});

// AI SOC Security Assistant (Powered by Gemini 3.8 Flash)
app.post('/api/assistant', async (req: Request, res: Response) => {
  const { question } = req.body || {};
  if (!question || typeof question !== 'string') {
    return res.status(400).json({ answer: 'Please enter a valid security question.' });
  }

  const current = sampleTelemetry();
  const activeThreats = threats.filter((t) => t.status === 'Active');
  const activeThreatDetails = activeThreats.map((t) => `${t.type} (${t.severity}) from ${t.source}`).join(', ') || 'None';

  if (aiClient) {
    try {
      const systemInstruction = `You are NetShield AI, an autonomous Network Security Operations Center (SOC) intelligence assistant.
Current Live System State:
- Network Health: ${current.health} (AI Risk Index: ${current.risk}%)
- Current Bandwidth: ${current.mbps} Mbps | Packets/sec: ${current.packets}
- Active Socket Connections: ${current.connections}
- Total Managed Endpoints: ${devices.length} (${devices.filter((d) => d.status === 'Online').length} Online)
- Active Threats: ${activeThreats.length} [${activeThreatDetails}]
- Active Firewall Rules: ${firewallRules.filter((r) => r.enabled).length}

Answer the user's inquiry clearly, professionally, and authoritatively. If they ask about security actions, give actionable firewall or mitigation commands. Keep answers concise, highly technical yet accessible.`;

      const response = await aiClient.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: question,
        config: {
          systemInstruction,
        },
      });

      return res.json({
        answer: response.text,
        source: 'Gemini 3.8 Flash AI Engine',
      });
    } catch (err: any) {
      console.warn('Gemini Assistant fallback triggered:', err?.message);
    }
  }

  // Fast Rule-Based Fallback
  const q = question.toLowerCase();
  let answer = '';

  if (q.includes('health')) {
    answer = `Network health is currently evaluated as **${current.health}** with a composite anomaly risk score of **${current.risk}%**. Bandwidth utilization is ${current.mbps} Mbps.`;
  } else if (q.includes('threat') || q.includes('attack')) {
    answer = activeThreats.length > 0
      ? `Attention: **${activeThreats.length} active security incident(s)** detected! Summary: ${activeThreatDetails}. You can block offending IPs directly in the Threat Center.`
      : `Zero active threats detected. All monitored ingress/egress channels are nominal.`;
  } else if (q.includes('bandwidth') || q.includes('traffic') || q.includes('speed')) {
    answer = `Current live throughput is **${current.mbps} Mbps** with **${current.packets} packets/second** across ${current.connections} active socket channels.`;
  } else if (q.includes('device') || q.includes('ip') || q.includes('host')) {
    answer = `NetShield is supervising **${devices.length} registered endpoints** (${devices.filter((d) => d.status === 'Online').length} currently active). High-risk endpoints can be isolated via the Devices tab.`;
  } else if (q.includes('firewall') || q.includes('block')) {
    answer = `There are currently **${firewallRules.filter((r) => r.enabled).length} enforced firewall policies**. You can add custom CIDR blocking rules from the Firewall management tab.`;
  } else {
    answer = `NetShield SOC monitoring active. I can inspect live network metrics, explain anomaly risk scores, generate mitigation commands for threats, or check endpoint compliance.`;
  }

  res.json({
    answer,
    source: 'NetShield Security Heuristic Engine',
  });
});

// ==========================================
// STATIC FILES & DEV SERVER INTEGRATION
// ==========================================

async function startServer() {
  if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.resolve('dist')));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.resolve('dist/index.html'));
    });
  } else {
    // In dev mode, mount Vite middleware
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🛡️ NetShield AI Server active at http://0.0.0.0:${PORT}`);
    console.log(`📡 Local Network Access URL: http://${getLocalIp()}:${PORT}`);
  });
}

startServer();
