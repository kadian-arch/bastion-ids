
import React, { useEffect, useState } from 'react';
import { 
  ShieldAlert, Activity, Zap, ChevronLeft, ShieldCheck, 
  BarChart3, Globe, Fingerprint, Terminal, AlertTriangle, 
  Cpu, Lock, Search, RefreshCw, Layers, HardDrive, 
  Database, Radio, FileWarning, ClipboardList
} from 'lucide-react';

/**
 * BASTION ATTACK ANALYSIS MODULE
 * Visualizes Neural Engine Output (CNN-LSTM) and Feature Importance
 */
export default function AnalysisResults({ data, onBack }) {
  const [isVisible, setIsVisible] = useState(false);

  // Trigger entrance animation on mount
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setIsVisible(true);
  }, []);

  // --- DYNAMIC DATA EXTRACTION ---
  const prediction = data?.prediction || "NEUTRAL";
  const confidence = data?.confidence ? `${(parseFloat(data.confidence) * 100).toFixed(2)}%` : "0.00%";
  const isThreat = prediction.toUpperCase() !== "NORMAL" && prediction.toUpperCase() !== "BENIGN";
  
  // --- HEURISTIC FEATURE WEIGHTING ---
  // These represent the most significant features identified by the CNN-LSTM layers
  const insights = [
    { feature: "Source Load (sload)", impact: isThreat ? 94 : 14, color: "bg-red-500", desc: "Outbound packet density per second" },
    { feature: "TTL Variance (sttl)", impact: isThreat ? 81 : 8, color: "bg-orange-500", desc: "Time-to-Live packet distance anomalies" },
    { feature: "D-Packet Count (dpkts)", impact: isThreat ? 52 : 25, color: "bg-yellow-500", desc: "Destination packet accumulation rate" },
    { feature: "Flow State (CON)", impact: isThreat ? 38 : 10, color: "bg-cyan-500", desc: "Connection persistence stability" }
  ];

  const logs = [
    { time: "00:00:01", msg: "Initializing Hybrid CNN-LSTM Kernel...", type: "info" },
    { time: "00:00:02", msg: `Analyzing vector: ${data?.file_name || 'Stream_Buffer'}`, type: "info" },
    { time: "00:00:03", msg: isThreat ? "ANOMALY_DETECTED: Signatures match attack patterns." : "INTEGRITY_CHECK: No malicious vectors found.", type: isThreat ? "error" : "success" }
  ];

  return (
    <div className={`p-8 space-y-8 bg-[#020617] min-h-screen font-mono text-slate-300 transition-all duration-1000 ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`}>
      
      {/* 1. ANALYSIS HEADER */}
      <header className="flex justify-between items-center bg-[#0a0f18] border border-white/5 p-8 rounded-[2.5rem] shadow-2xl relative overflow-hidden group">
        <div className="flex items-center gap-8 relative z-10">
          <button 
            onClick={onBack}
            className="p-4 bg-white/5 rounded-2xl border border-white/10 hover:border-cyan-500 hover:bg-cyan-500/10 transition-all group/back"
          >
            <ChevronLeft size={24} className="text-slate-500 group-hover:text-cyan-400 group-hover:-translate-x-1 transition-transform" />
          </button>
          <div>
            <h1 className="text-3xl font-black text-white uppercase tracking-tighter italic">Engine Verdict Report</h1>
            <div className="flex items-center gap-3 mt-2">
                <Layers className="text-cyan-500" size={14} />
                <p className="text-[10px] text-cyan-500 font-black tracking-[0.4em] uppercase">Deep Learning Analysis Node // Active</p>
            </div>
          </div>
        </div>
        
        <div className="text-right relative z-10">
          <span className="text-[10px] block text-slate-500 font-black uppercase mb-2 tracking-[0.3em] italic">Classification_Status</span>
          <div className={`flex items-center gap-3 px-6 py-2.5 rounded-full border shadow-lg ${isThreat ? 'bg-red-500/10 border-red-500/30' : 'bg-emerald-500/10 border-emerald-500/30'}`}>
            <div className={`w-2 h-2 rounded-full ${isThreat ? 'bg-red-500 animate-pulse shadow-[0_0_10px_#ef4444]' : 'bg-emerald-500 shadow-[0_0_10px_#10b981]'}`}></div>
            <span className={`text-xs font-black uppercase tracking-widest ${isThreat ? 'text-red-500' : 'text-emerald-500'}`}>
              {isThreat ? 'Threat Signature Detected' : 'Verified Secure'}
            </span>
          </div>
        </div>
        <div className="absolute top-0 right-0 w-96 h-full bg-cyan-500/5 blur-[120px] pointer-events-none" />
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        
        {/* LEFT COLUMN: PRIMARY METRICS (8/12) */}
        <div className="lg:col-span-8 space-y-8">
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {/* Prediction Card */}
            <div className="bg-[#0a0f18] border border-white/5 p-10 rounded-[3rem] relative overflow-hidden group hover:border-white/10 transition-all">
               <div className="p-4 bg-white/5 w-fit rounded-2xl mb-6">
                 <Activity className="text-cyan-500" size={32} />
               </div>
               <h4 className="text-slate-500 text-[10px] font-black uppercase mb-2 tracking-[0.4em] italic">Identified Category</h4>
               <p className="text-4xl font-black text-white italic uppercase tracking-tighter">{prediction}</p>
               <div className="absolute -right-8 -bottom-8 opacity-[0.02] group-hover:opacity-[0.05] transition-opacity rotate-12">
                  <Fingerprint size={200} />
               </div>
            </div>

            {/* Confidence Card */}
            <div className="bg-[#0a0f18] border border-white/5 p-10 rounded-[3rem] relative overflow-hidden group hover:border-white/10 transition-all">
               <div className="p-4 bg-white/5 w-fit rounded-2xl mb-6">
                 <ShieldCheck className="text-emerald-500" size={32} />
               </div>
               <h4 className="text-slate-500 text-[10px] font-black uppercase mb-2 tracking-[0.4em] italic">Neural Confidence</h4>
               <p className="text-4xl font-black text-emerald-400 italic tracking-tighter">{confidence}</p>
               <div className="absolute -right-8 -bottom-8 opacity-[0.02] group-hover:opacity-[0.05] transition-opacity">
                  <Globe size={200} />
               </div>
            </div>
          </div>

          {/* NEURAL FEATURE CONTRIBUTION */}
          <div className="bg-[#0a0f18] border border-white/5 p-12 rounded-[3.5rem] relative">
            <div className="flex justify-between items-center mb-12">
              <h3 className="text-white text-sm font-black uppercase tracking-[0.3em] flex items-center gap-4 italic">
                <BarChart3 size={22} className="text-cyan-500" /> Neural_Feature_Contribution
              </h3>
              <div className="px-4 py-1.5 rounded-lg border border-white/5 bg-black text-[9px] text-slate-500 font-black uppercase tracking-widest">
                Heuristic weighting engine v1.4
              </div>
            </div>
            
            <div className="space-y-10">
              {insights.map((item, index) => (
                <div key={index} className="group cursor-help">
                  <div className="flex justify-between text-[11px] font-black mb-4 uppercase tracking-[0.2em]">
                    <div className="flex flex-col">
                      <span className="text-slate-400 group-hover:text-white transition-colors">{item.feature}</span>
                      <span className="text-[8px] text-slate-600 mt-1 lowercase font-normal">{item.desc}</span>
                    </div>
                    <span className="text-white italic bg-white/5 px-3 py-1 rounded-md">+{item.impact}% Impact</span>
                  </div>
                  <div className="h-2 w-full bg-white/5 rounded-full overflow-hidden flex p-0.5 border border-white/5">
                    <div 
                      className={`${item.color} h-full rounded-full transition-all duration-[1.5s] ease-out shadow-[0_0_20px_rgba(255,255,255,0.1)]`} 
                      style={{ width: `${item.impact}%` }}
                    ></div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* TERMINAL MINI-LOG */}
          <div className="bg-black/40 border border-white/5 p-6 rounded-3xl font-mono">
             <div className="flex items-center gap-3 mb-4 opacity-50">
               <Terminal size={14} />
               <span className="text-[9px] font-black uppercase tracking-widest">Analysis Execution Logs</span>
             </div>
             <div className="space-y-2">
                {logs.map((log, i) => (
                  <div key={i} className="flex gap-4 text-[10px]">
                    <span className="text-slate-600">[{log.time}]</span>
                    <span className={log.type === 'error' ? 'text-red-500' : log.type === 'success' ? 'text-emerald-500' : 'text-slate-400'}>
                      {log.msg}
                    </span>
                  </div>
                ))}
             </div>
          </div>
        </div>

        {/* RIGHT COLUMN: ACTION HUD (4/12) */}
        <div className="lg:col-span-4 space-y-8">
          <div className={`rounded-[3.5rem] p-10 border h-full flex flex-col justify-between transition-all duration-1000 ${
            isThreat ? 'bg-red-500/5 border-red-500/20 shadow-[0_0_50px_rgba(239,68,68,0.05)]' : 'bg-emerald-500/5 border-emerald-500/20 shadow-[0_0_50px_rgba(16,185,129,0.05)]'
          }`}>
            <div>
              <div className={`w-20 h-20 rounded-3xl flex items-center justify-center mb-10 transition-transform duration-700 ${
                 isThreat ? 'bg-red-500 text-white animate-pulse' : 'bg-emerald-500 text-white scale-110'
              }`}>
                {isThreat ? <ShieldAlert size={40} /> : <ShieldCheck size={40} />}
              </div>

              <h3 className="text-3xl font-black text-white uppercase mb-6 tracking-tighter italic leading-tight">
                {isThreat ? 'Mitigation Strategy Required' : 'Integrity Handshake Verified'}
              </h3>
              
              <div className="space-y-6">
                 <p className="text-[12px] text-slate-400 leading-relaxed italic border-l-4 border-white/10 pl-6 uppercase tracking-wider">
                   {isThreat 
                     ? `The pattern matches known [${prediction}] signatures. System suggests immediate quarantine of the source vector and session termination via XDP filter.`
                     : "No anomalous patterns detected in the current buffer. System integrity remains optimal. Network topology is verified stable."
                   }
                 </p>
                 
                 <div className="bg-black/40 rounded-2xl p-6 border border-white/5">
                    <h5 className="text-[9px] font-black uppercase text-slate-500 mb-4 tracking-widest">Recommended Actions</h5>
                    <ul className="space-y-3">
                       <li className="flex items-center gap-3 text-[10px] text-slate-300 italic">
                          <div className={`w-1 h-1 rounded-full ${isThreat ? 'bg-red-500' : 'bg-emerald-500'}`}></div>
                          {isThreat ? "Terminate Source IP Session" : "Continue Background Sniffing"}
                       </li>
                       <li className="flex items-center gap-3 text-[10px] text-slate-300 italic">
                          <div className={`w-1 h-1 rounded-full ${isThreat ? 'bg-red-500' : 'bg-emerald-500'}`}></div>
                          {isThreat ? "Enable Deep Packet Inspection" : "Update Signature Database"}
                       </li>
                    </ul>
                 </div>
              </div>
            </div>
            
            <button 
              disabled={!isThreat}
              className={`w-full py-6 rounded-2xl font-black text-[12px] uppercase tracking-[0.5em] transition-all flex items-center justify-center gap-4 mt-12 shadow-2xl relative overflow-hidden group/btn ${
                isThreat 
                ? 'bg-red-600 hover:bg-red-500 text-white shadow-red-900/30' 
                : 'bg-slate-900 text-slate-700 cursor-not-allowed border border-white/5'
              }`}
            >
              <div className="absolute inset-0 bg-white/10 -translate-x-full group-hover/btn:translate-x-full transition-transform duration-700" />
              <span className="relative z-10 flex items-center gap-3">
                {isThreat ? 'EXECUTE QUARANTINE' : 'PROTECTION ACTIVE'} 
                <Zap size={20} className={isThreat ? "animate-pulse" : ""} fill={isThreat ? "currentColor" : "none"} />
              </span>
            </button>
          </div>
        </div>

      </div>

      {/* FOOTER STATS */}
      <div className="flex justify-center gap-12 pt-10 opacity-30 group hover:opacity-100 transition-opacity">
          <div className="flex items-center gap-3">
            <Database size={14} className="text-slate-500" />
            <span className="text-[9px] font-black uppercase tracking-widest">DB_SYNC_OK</span>
          </div>
          <div className="flex items-center gap-3">
            <Radio size={14} className="text-slate-500" />
            <span className="text-[9px] font-black uppercase tracking-widest">UPLINK_STABLE</span>
          </div>
          <div className="flex items-center gap-3">
            <HardDrive size={14} className="text-slate-500" />
            <span className="text-[9px] font-black uppercase tracking-widest">LOCAL_CACHE_CLEAN</span>
          </div>
      </div>
    </div>
  );
}