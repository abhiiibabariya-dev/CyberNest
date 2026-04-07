import { BarChart3, FileDown, Calendar, Clock } from 'lucide-react'

const REPORT_TEMPLATES = [
  { name: 'Executive Summary', desc: 'High-level security posture overview for leadership', icon: '📊', frequency: 'Weekly' },
  { name: 'Alert Trend Report', desc: 'Detailed breakdown of alerts by severity, source, and rule', icon: '📈', frequency: 'Daily' },
  { name: 'Incident Report', desc: 'Full incident timeline, IOCs, and response actions taken', icon: '📋', frequency: 'Per Incident' },
  { name: 'PCI-DSS Compliance', desc: 'PCI-DSS requirement mapping with evidence from SIEM logs', icon: '🔒', frequency: 'Monthly' },
  { name: 'HIPAA Compliance', desc: 'HIPAA security rule compliance evidence report', icon: '🏥', frequency: 'Monthly' },
  { name: 'SOC2 Audit Report', desc: 'SOC2 Type II controls evidence with detection coverage', icon: '✅', frequency: 'Quarterly' },
  { name: 'MITRE ATT&CK Coverage', desc: 'Detection coverage mapped to MITRE ATT&CK framework', icon: '🎯', frequency: 'Monthly' },
  { name: 'Agent Health Report', desc: 'Agent uptime, resource usage, and connectivity summary', icon: '💻', frequency: 'Weekly' },
]

export default function Reports() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <BarChart3 className="w-6 h-6 text-cyber-accent" /> Reports
        </h1>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {REPORT_TEMPLATES.map((report, i) => (
          <div key={i} className="bg-cyber-card border border-cyber-border rounded-xl p-5 hover:border-cyber-accent/30 transition-colors">
            <div className="flex items-start justify-between mb-3">
              <span className="text-2xl">{report.icon}</span>
              <span className="flex items-center gap-1 text-xs text-cyber-muted">
                <Calendar className="w-3 h-3" /> {report.frequency}
              </span>
            </div>
            <h3 className="font-semibold mb-1">{report.name}</h3>
            <p className="text-xs text-cyber-muted mb-4">{report.desc}</p>
            <div className="flex gap-2">
              <button className="flex items-center gap-1 px-3 py-1.5 bg-cyber-accent/15 text-cyber-accent text-xs rounded hover:bg-cyber-accent/25">
                <FileDown className="w-3 h-3" /> Generate PDF
              </button>
              <button className="flex items-center gap-1 px-3 py-1.5 bg-cyber-card border border-cyber-border text-cyber-muted text-xs rounded hover:text-white">
                <Clock className="w-3 h-3" /> Schedule
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
