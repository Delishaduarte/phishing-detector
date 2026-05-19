import { useState } from "react";
import axios from "axios";
import { Chart as ChartJS, ArcElement, Tooltip, CategoryScale, LinearScale, BarElement } from "chart.js";
import { Doughnut, Bar } from "react-chartjs-2";
import "./App.css";

ChartJS.register(ArcElement, Tooltip, CategoryScale, LinearScale, BarElement);

const PHISHING_KEYWORDS = ["click", "verify", "prize", "winner", "account", "urgent", "password", "suspend", "confirm", "free", "claim", "login", "update", "secure", "bank"];

export default function App() {
  const [isLogin, setIsLogin] = useState(true);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [page, setPage] = useState("analyze");
  const [form, setForm] = useState({ name: "", email: "", password: "", phone: "" });
  const [msg, setMsg] = useState("");
  const [emailText, setEmailText] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);
  const [userId, setUserId] = useState(null);
  const [dashboardData, setDashboardData] = useState(null);
  const [profileData, setProfileData] = useState(null);
  const [userName, setUserName] = useState("");
  const [insightsData, setInsightsData] = useState(null);

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const getKeywords = (text) => {
    const lower = text.toLowerCase();
    return PHISHING_KEYWORDS.filter(kw => lower.includes(kw));
  };

  //changes

  const getTimestamp = () => {
    const now = new Date();
    const time = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    return `Today, ${time}`;
  };

  const getThreatLevel = (label, confidence) => {
    if (label === "SAFE") return "Safe";
    if (confidence >= 85) return "High";
    if (confidence >= 60) return "Medium";
    return "Low";
  };

  const loadDashboard = async (uid) => {
    try {
      const res = await axios.get(`http://localhost:3000/dashboard/${uid}`);
      if (res.data.success) setDashboardData(res.data);
    } catch {
      console.log("Dashboard load error");
    }
  };

  const loadProfile = async (uid) => {
  try {
    const res = await axios.get(`http://localhost:3000/profile/${uid}`);
    if (res.data.success) {
      setProfileData(res.data);
    } else {
      // This stops the "Loading..." screen if the database is empty
      setProfileData({ 
        user: { name: "New User", email: "No scans yet" }, 
        stats: { phishing: 0 } 
      });
    }
  } catch (err) {
    console.error("Profile load error", err);
    setProfileData({ 
      user: { name: "Error", email: "Server Down" }, 
      stats: { phishing: 0 } 
    });
  }
};

const loadInsights = async (uid) => {
  try {
    const res = await axios.get(`http://localhost:3000/insights/${uid}`);
    if (res.data.success) setInsightsData(res.data);
  } catch {
    console.log("Insights load error");
  }
};

  const submit = async () => {
    try {
      if (isLogin) {
        const res = await axios.post("http://localhost:3000/login", { email: form.email, password: form.password });
        setMsg(res.data.message);
        if (res.data.message === "Login Successful") {
          setIsLoggedIn(true);
          setUserId(res.data.userId);
          setUserName(res.data.name);
        }
      } else {
        const res = await axios.post("http://localhost:3000/register", { name: form.name, email: form.email, password: form.password, phone: form.phone });
        setMsg(res.data.message);
        setIsLogin(true);
      }
    } catch {
      setMsg("Server Error");
    }
  };

  const handlePredict = async () => {
    if (!emailText.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      const res = await axios.post("http://localhost:3000/predict", { email: emailText });
      const raw = res.data.result;
      const [label, confidence] = raw.split("|");
      const conf = parseInt(confidence);
      const timestamp = getTimestamp();
      const threat = getThreatLevel(label, conf);
      const parsed = { label, confidence: conf, timestamp, threat };
      setResult(parsed);
      setHistory(prev => [
        { text: emailText.slice(0, 40) + "...", label, confidence: conf, timestamp, threat },
        ...prev.slice(0, 19)
      ]);

      await axios.post("http://localhost:3000/save-scan", {
        userId,
        emailText,
        result: label,
        confidence: conf,
        threatLevel: threat,
        keywords: getKeywords(emailText)
      });

    } catch {
      setResult({ label: "ERROR", confidence: 0, timestamp: "", threat: "" });
    }
    setLoading(false);
  };

  const handleClear = () => { setEmailText(""); setResult(null); };
  const isPhishing = result?.label === "PHISHING";

  const totalScanned = dashboardData ? Number(dashboardData.stats.total) : history.length;
  const totalPhishing = dashboardData ? Number(dashboardData.stats.phishing) : history.filter(h => h.label === "PHISHING").length;
  const totalSafe = dashboardData ? Number(dashboardData.stats.safe) : history.filter(h => h.label === "SAFE").length;
  const avgConf = dashboardData ? Number(dashboardData.stats.avgConf) : (history.length > 0 ? Math.round(history.reduce((a, b) => a + b.confidence, 0) / history.length) : 0);

  const displayHistory = dashboardData ? dashboardData.history.map(item => ({
    text: item.email_text.slice(0, 40) + "...",
    label: item.result,
    confidence: item.confidence,
    threat: item.threat_level,
    timestamp: new Date(item.scanned_at).toLocaleString()
  })) : history;

  const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

  const weekPhishing = days.map(day => {
    if (!dashboardData) return 0;
    const match = dashboardData.week.find(w => w.day.startsWith(day) && w.result === "PHISHING");
    return match ? match.count : 0;
  });

  const weekSafe = days.map(day => {
    if (!dashboardData) return 0;
    const match = dashboardData.week.find(w => w.day.startsWith(day) && w.result === "SAFE");
    return match ? match.count : 0;
  });

  const barData = {
    labels: days,
    datasets: [
      { label: "Phishing", data: dashboardData ? weekPhishing : [3, 5, 2, 4, 3, 2, totalPhishing], backgroundColor: "#e53e3e", borderRadius: 4 },
      { label: "Safe", data: dashboardData ? weekSafe : [4, 6, 3, 5, 4, 3, totalSafe], backgroundColor: "#2f855a", borderRadius: 4 }
    ]
  };

  const donutData = {
    labels: ["Phishing", "Safe"],
    datasets: [{ data: [totalPhishing || 1, totalSafe || 1], backgroundColor: ["#e53e3e", "#2f855a"], borderWidth: 0 }]
  };

  const barOptions = {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { display: false }, ticks: { font: { size: 10 } } },
      y: { grid: { color: "#f0f0f0" }, ticks: { font: { size: 10 }, stepSize: 2 } }
    }
  };

  const donutOptions = {
    responsive: true, maintainAspectRatio: false,
    cutout: "70%",
    plugins: { legend: { display: false } }
  };

  return (
    <div className="container">
      {!isLoggedIn ? (
        <div className="card">
          <h1>{isLogin ? "Login" : "Register"}</h1>
          {!isLogin && (
            <>
              <input name="name" placeholder="Full Name" onChange={handleChange} />
              <input name="phone" placeholder="Phone Number" onChange={handleChange} />
            </>
          )}
          <input name="email" placeholder="Email" onChange={handleChange} />
          <input name="password" type="password" placeholder="Password" onChange={handleChange} />
          <button onClick={submit}>{isLogin ? "Login" : "Register"}</button>
          <p className="toggle" onClick={() => setIsLogin(!isLogin)}>
            {isLogin ? "Create Account" : "Already have account?"}
          </p>
          <p className="msg">{msg}</p>
        </div>

      ) : page === "analyze" ? (

        <div className="predict-card">
          <div className="app-title">
            <svg className="shield-icon" viewBox="0 0 24 24" fill="none" stroke="#2a5298" strokeWidth="2">
              <path d="M12 2L3 7v5c0 5 4 9.3 9 10.3C17 21.3 21 17 21 12V7L12 2z" />
            </svg>
            <h1>Email Phishing Detector</h1>
          </div>
          <p className="subtitle">Paste your email content below to check if it is safe or suspicious.</p>

          <div className="nav-tabs">
            <button className="nav-btn active-nav">Analyze</button>
            <button className="nav-btn" onClick={() => { setPage("dashboard"); loadDashboard(userId); }}>Dashboard</button>
            <button className="nav-btn" onClick={() => { setPage("profile"); loadProfile(userId); loadInsights(userId);}}>Profile</button>
            <button className="nav-btn logout-nav" onClick={() => { setIsLoggedIn(false); setUserId(null); setDashboardData(null); setHistory([]); }}>Logout</button>
          </div>

          <textarea
            className="predict-textarea"
            placeholder="Paste full email content here..."
            value={emailText}
            onChange={(e) => setEmailText(e.target.value)}
          />
          <div className="meta-row">
            <span className="char-count">{emailText.length} characters · {emailText.trim() ? emailText.trim().split(/\s+/).length : 0} words</span>
            {emailText && <button className="clear-btn" onClick={handleClear}>Clear</button>}
          </div>

          <button className="predict-btn" onClick={handlePredict} disabled={loading}>
            {loading ? "Analyzing..." : "Analyze Email"}
          </button>

          {loading && (
            <div className="spinner-row">
              <span className="dot"></span><span className="dot"></span><span className="dot"></span>
              <span className="analyzing-text">Analyzing your email...</span>
            </div>
          )}

          {result && !loading && result.label !== "ERROR" && (
            <div className={`result-box ${isPhishing ? "result-danger" : "result-safe"}`}>
              <div className="result-header">
                <span className={`result-badge ${isPhishing ? "badge-danger" : "badge-safe"}`}>
                  {isPhishing ? "Suspicious Email Detected" : "Email Looks Safe"}
                </span>
                <span className="timestamp">{result.timestamp}</span>
              </div>
              <div className="threat-row">
                <span className={`threat-pill pill-${result.threat.toLowerCase()}`}>{result.threat.toUpperCase()} RISK</span>
                <span className={`conf-pct ${isPhishing ? "conf-danger" : "conf-safe"}`}>{result.confidence}% {isPhishing ? "phishing" : "safe"}</span>
              </div>
              <div className="bar-bg">
                <div className={`bar-fill ${isPhishing ? "bar-danger" : "bar-safe"}`} style={{ width: `${result.confidence}%` }}></div>
              </div>
              <div className="result-text">
                {isPhishing ? "This email appears to be a phishing attempt. Do not click on any links or share personal information." : "No phishing indicators were detected in this email."}
              </div>
              {isPhishing && getKeywords(emailText).length > 0 && (
                <div className="keywords-row">
                  Flagged: {getKeywords(emailText).map(kw => <span key={kw} className="kw-tag">{kw}</span>)}
                </div>
              )}
            </div>
          )}

          {result?.label === "ERROR" && (
            <div className="result-box result-error">Error connecting to server</div>
          )}
        </div>
      )  : page === "profile" ? (
        <div className="dashboard">

          <div className="dash-topbar">
            <div className="dash-title-row">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2">
                <path d="M12 2L3 7v5c0 5 4 9.3 9 10.3C17 21.3 21 17 21 12V7L12 2z" />
              </svg>
              <span className="dash-title">Email Phishing Detector</span>
            </div>
            <div className="dash-nav">
              <button className="dash-nav-btn" onClick={() => setPage("analyze")}>Analyze</button>
              <button className="dash-nav-btn" onClick={() => { setPage("dashboard"); loadDashboard(userId); }}>Dashboard</button>
              <button className="dash-nav-btn dash-nav-active">Profile</button>
              <button className="dash-nav-btn" onClick={() => { setIsLoggedIn(false); setUserId(null); setDashboardData(null); setHistory([]); setProfileData(null); }}>Logout</button>
            </div>
          </div>

          {!profileData ? (
            <div style={{ textAlign: "center", color: "white", padding: "60px", fontSize: "15px" }}>Loading profile...</div>
          ) : (
            <>
              {/* PROFILE HEADER */}
              <div style={{ background: "white", borderRadius: "12px", padding: "24px", marginBottom: "12px", border: "0.5px solid #e5e7eb", display: "flex", alignItems: "center", gap: "20px" }}>
                <div style={{ width: "68px", height: "68px", borderRadius: "50%", background: "linear-gradient(135deg, #1e3c72, #2a5298)", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                  <span style={{ color: "white", fontSize: "26px", fontWeight: "500" }}>
                    {profileData.user?.name?.charAt(0).toUpperCase() || "?"}
                  </span>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: "20px", fontWeight: "500", color: "#1a1a2e" }}>{profileData.user?.name || "—"}</div>
                  <div style={{ fontSize: "13px", color: "#888", marginTop: "3px" }}>{profileData.user?.email || "—"}</div>
                  <div style={{ fontSize: "12px", color: "#aaa", marginTop: "3px" }}>📞 {profileData.user?.phone || "Not provided"}</div>
                </div>
                <div style={{ textAlign: "right" }}>
                  <div style={{ fontSize: "11px", color: "#aaa", marginBottom: "4px" }}>Member since</div>
                  <div style={{ fontSize: "13px", color: "#555", fontWeight: "500" }}>
                    {profileData.user?.created_at
                      ? new Date(profileData.user.created_at).toLocaleDateString("en-IN", { day: "numeric", month: "long", year: "numeric" })
                      : "N/A"}
                  </div>
                </div>
              </div>

              {/* STATS GRID */}
              <div className="metrics-grid" style={{ marginBottom: "12px" }}>
                <div className="metric-card">
                  <div className="metric-label">Total scanned</div>
                  <div className="metric-val">{Number(profileData.stats?.total) || 0}</div>
                  <div className="metric-sub gray">all time</div>
                </div>
                <div className="metric-card">
                  <div className="metric-label">Phishing caught</div>
                  <div className="metric-val red">{Number(profileData.stats?.phishing) || 0}</div>
                  <div className="metric-sub red">emails flagged</div>
                </div>
                <div className="metric-card">
                  <div className="metric-label">Safe emails</div>
                  <div className="metric-val green">{Number(profileData.stats?.safe) || 0}</div>
                  <div className="metric-sub green">confirmed safe</div>
                </div>
                <div className="metric-card">
                  <div className="metric-label">Avg confidence</div>
                  <div className="metric-val">{Number(profileData.stats?.avgConf) || 0}%</div>
                  <div className="metric-sub gray">model score</div>
                </div>
              </div>

              {/* MIDDLE ROW — RISK METER + ACCOUNT DETAILS */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "12px" }}>

                {/* SECURITY STATUS WITH SPEEDOMETER */}
                <div style={{ background: "white", borderRadius: "12px", padding: "20px", border: "0.5px solid #e5e7eb" }}>
                  <div style={{ fontSize: "14px", fontWeight: "500", color: "#333", marginBottom: "14px", display: "flex", alignItems: "center", gap: "7px" }}>
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#2a5298" strokeWidth="2"><path d="M12 2L3 7v5c0 5 4 9.3 9 10.3C17 21.3 21 17 21 12V7L12 2z"/></svg>
                    Security status
                  </div>

                  {(() => {
                    const total = Number(profileData.stats?.total) || 0;
                    const phishing = Number(profileData.stats?.phishing) || 0;
                    const score = total > 0 ? Math.round((phishing / total) * 100) : 0;
                    const color = score < 30 ? "#2f855a" : score < 70 ? "#d97706" : "#e53e3e";
                    const label = score < 30 ? "Safe" : score < 70 ? "Moderate risk" : "High risk";

                    return (
                      <div style={{ textAlign: "center" }}>
                        <canvas
                          ref={el => {
                            if (!el) return;
                            const ctx = el.getContext("2d");
                            const cx = 110, cy = 115, r = 85;
                            ctx.clearRect(0, 0, 220, 130);
                            [
                              { from: 0, to: 0.3, color: "#2f855a" },
                              { from: 0.3, to: 0.7, color: "#d97706" },
                              { from: 0.7, to: 1.0, color: "#e53e3e" }
                            ].forEach(seg => {
                              ctx.beginPath();
                              ctx.arc(cx, cy, r, Math.PI + seg.from * Math.PI, Math.PI + seg.to * Math.PI);
                              ctx.lineWidth = 18;
                              ctx.strokeStyle = seg.color;
                              ctx.lineCap = "butt";
                              ctx.stroke();
                            });
                            const angle = Math.PI + (score / 100) * Math.PI;
                            ctx.beginPath();
                            ctx.moveTo(cx, cy);
                            ctx.lineTo(cx + (r - 10) * Math.cos(angle), cy + (r - 10) * Math.sin(angle));
                            ctx.lineWidth = 2.5;
                            ctx.strokeStyle = "#333";
                            ctx.lineCap = "round";
                            ctx.stroke();
                            ctx.beginPath();
                            ctx.arc(cx, cy, 6, 0, 2 * Math.PI);
                            ctx.fillStyle = "#333";
                            ctx.fill();
                            ctx.font = "11px Arial";
                            ctx.fillStyle = "#888";
                            ctx.textAlign = "center";
                            ctx.fillText("0", cx - r - 6, cy + 4);
                            ctx.fillText("100", cx + r + 10, cy + 4);
                            ctx.fillText("50", cx, cy - r - 6);
                          }}
                          width={220} height={130}
                        />
                        <div style={{ fontSize: "22px", fontWeight: "500", color, marginTop: "4px" }}>{score}%</div>
                        <div style={{ fontSize: "13px", color, fontWeight: "500" }}>{label}</div>
                        <div style={{ fontSize: "11px", color: "#aaa", marginTop: "4px" }}>based on your scan history</div>

                        <div style={{ display: "flex", justifyContent: "center", gap: "14px", margin: "10px 0 14px", fontSize: "11px", color: "#666" }}>
                          {[["#2f855a", "Safe 0–30%"], ["#d97706", "Moderate 30–70%"], ["#e53e3e", "High 70%+"]].map(([c, t]) => (
                            <span key={t} style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                              <span style={{ width: "9px", height: "9px", borderRadius: "50%", background: c, display: "inline-block" }}></span>{t}
                            </span>
                          ))}
                        </div>

                        <div style={{ borderTop: "0.5px solid #f0f0f0", paddingTop: "12px", textAlign: "left" }}>
                          {[
                            [ `${phishing} phishing emails caught`],
                            [ `${total - phishing} safe emails verified`],
                            [ `${Number(profileData.stats?.avgConf) || 0}% average model confidence`]
                          ].map(([icon, text]) => (
                            <div key={text} style={{ display: "flex", alignItems: "center", gap: "10px", padding: "5px 0", fontSize: "13px", color: "#555" }}>
                              <span style={{ fontSize: "14px" }}>{icon}</span>{text}
                            </div>
                          ))}
                        </div>
                      </div>
                    );
                  })()}
                </div>

                {/* ACCOUNT DETAILS */}
                <div style={{ background: "white", borderRadius: "12px", padding: "20px", border: "0.5px solid #e5e7eb" }}>
                  <div style={{ fontSize: "14px", fontWeight: "500", color: "#333", marginBottom: "14px", display: "flex", alignItems: "center", gap: "7px" }}>
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#2a5298" strokeWidth="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/></svg>
                    Account details
                  </div>
                  {[
                    { label: "Full name", value: profileData.user?.name || "—" },
                    { label: "Email", value: profileData.user?.email || "—" },
                    { label: "Phone", value: profileData.user?.phone || "Not provided" },
                    { label: "First scan", value: profileData.firstScan ? new Date(profileData.firstScan).toLocaleDateString("en-IN", { day: "numeric", month: "long", year: "numeric" }) : "No scans yet" },
                    { label: "Detection rate", value: Number(profileData.stats?.total) > 0 ? `${Math.round((Number(profileData.stats.phishing) / Number(profileData.stats.total)) * 100)}% phishing` : "No data yet" }
                  ].map((row, i, arr) => (
                    <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "9px 0", borderBottom: i < arr.length - 1 ? "0.5px solid #f5f5f5" : "none" }}>
                      <span style={{ fontSize: "12px", color: "#999" }}>{row.label}</span>
                      <span style={{ fontSize: "13px", color: "#333" }}>{row.value}</span>
                    </div>
                  ))}
                </div>

              </div>

              {/* EMAIL BEHAVIOR INSIGHTS */}
              <div style={{ background: "white", borderRadius: "12px", padding: "20px", border: "0.5px solid #e5e7eb" }}>
                <div style={{ fontSize: "14px", fontWeight: "500", color: "#333", marginBottom: "14px", display: "flex", alignItems: "center", gap: "7px" }}>
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#2a5298" strokeWidth="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
                  Email behavior insights
                </div>

                {(() => {
                  const total = Number(profileData.stats?.total) || 0;
                  const phishing = Number(profileData.stats?.phishing) || 0;
                  const phishPct = total > 0 ? Math.round((phishing / total) * 100) : 0;

                  const keywords = insightsData?.keywords || [];
                  const topThreat = insightsData?.topThreat || "Medium";
                  const busiestDay = insightsData?.busiestDay || null;
                  const thisWeek = insightsData?.thisWeek || 0;
                  const lastWeek = insightsData?.lastWeek || 0;
                  const rawTrend = lastWeek > 0 ? Math.round(((thisWeek - lastWeek) / lastWeek) * 100) : null;
const trendPct = rawTrend !== null ? Math.min(rawTrend, 100) : null;
const trendDisplay = trendPct !== null && Math.abs(trendPct) > 500 ? null : trendPct;
                  const threatColor = topThreat === "High" ? { bg: "#fee2e2", color: "#7f1d1d" } : topThreat === "Medium" ? { bg: "#fed7aa", color: "#7c2d12" } : { bg: "#d1fae5", color: "#065f46" };

                  const insights = [
                    // INSIGHT 1 — top keywords (fully dynamic)
                    keywords.length > 0 ? {
                      bg: "#fef3c7",
                      title: "Your most flagged keywords",
                      sub: "These words appeared most frequently in phishing emails detected in your inbox.",
                      tags: keywords,
                      tagColor: { bg: "#fef3c7", color: "#78350f" }
                    } : null,

                    // INSIGHT 2 — phishing percentage (dynamic)
                    {
                      bg: "#fee2e2",
                      title: `${phishPct}% of your emails were phishing attempts`,
                      sub: phishPct > 50
                        ? "More than half your scanned emails were phishing. Your inbox is being heavily targeted."
                        : phishPct > 0
                        ? "Less than half your scanned emails were phishing. Keep scanning to stay protected."
                        : "No phishing emails detected yet. Scan more emails to see insights.",
                      tags: [],
                    },

                    // INSIGHT 3 — most common threat level (dynamic)
                    {
                      bg: threatColor.bg,
                      title: `Most threats are ${topThreat} risk level`,
                      sub: topThreat === "High"
                        ? "Most phishing emails targeting you are highly sophisticated. Be very careful with any unexpected email."
                        : topThreat === "Medium"
                        ? "Most phishing emails you receive are moderately dangerous. Always verify sender addresses."
                        : "Most phishing attempts on you are low risk but still worth staying alert.",
                      tags: [],
                      tagColor: threatColor
                    },

                    // INSIGHT 4 — busiest phishing day (dynamic)
                    busiestDay ? {
                      bg: "#e6f1fb",
                      title: `${busiestDay} is your most targeted day`,
                      sub: `You receive more phishing emails on ${busiestDay} than any other day. Be extra cautious on this day.`,
                      tags: [],
                    } : null,

                    // INSIGHT 5 — week trend (dynamic)
                    trendPct !== null ? {
                      bg: trendPct > 0 ? "#fee2e2" : "#d1fae5",
                      title: trendPct > 0
  ? `Phishing increased significantly this week`
  : `Phishing down ${Math.abs(trendPct)}% this week`,
sub: trendPct > 0
  ? `You received ${thisWeek} phishing emails this week vs ${lastWeek} last week. Attackers are more active — stay alert.`
  : `You received ${thisWeek} phishing emails this week vs ${lastWeek} last week. Things are improving.`,
                      tags: [],
                    } : null,

                    // INSIGHT 6 — static security tip (always shown)
                    {
                      bg: "#fef3c7", 
                      title: "Security tip: Always verify sender domains",
                      sub: "Phishing emails often use domains that look legitimate but have small differences — like 'paypa1.com' instead of 'paypal.com'.",
                      tags: [],
                    }
                  ].filter(Boolean);

                  return insights.map((item, i) => (
                    <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: "12px", padding: "11px 0", borderBottom: i < insights.length - 1 ? "0.5px solid #f5f5f5" : "none" }}>
                      <div style={{ width: "34px", height: "34px", borderRadius: "8px", background: item.bg, display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, fontSize: "15px" }}>
                        {item.icon}
                      </div>
                      <div>
                        <div style={{ fontSize: "13px", fontWeight: "500", color: "#222", marginBottom: "2px" }}>{item.title}</div>
                        <div style={{ fontSize: "12px", color: "#888", marginBottom: item.tags?.length ? "6px" : "0" }}>{item.sub}</div>
                        {item.tags?.map(tag => (
                          <span key={tag} style={{ display: "inline-block", background: item.tagColor?.bg || "#e6f1fb", color: item.tagColor?.color || "#0c447c", borderRadius: "4px", padding: "2px 8px", fontSize: "11px", margin: "2px 2px 0 0" }}>{tag}</span>
                        ))}
                      </div>
                    </div>
                  ));
                })()}
              </div>
            </>
          )}
        </div>
) : (

        <div className="dashboard">
          <div className="dash-topbar">
            <div className="dash-title-row">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2">
                <path d="M12 2L3 7v5c0 5 4 9.3 9 10.3C17 21.3 21 17 21 12V7L12 2z" />
              </svg>
              <span className="dash-title">Email Phishing Detector</span>
            </div>
            <div className="dash-nav">
              <button className="dash-nav-btn" onClick={() => setPage("analyze")}>Analyze</button>
              <button className="dash-nav-btn dash-nav-active">Dashboard</button>
              <button className="nav-btn" onClick={() => { setPage("profile"); loadProfile(userId); loadInsights(userId);}}>Profile</button>
              <button className="dash-nav-btn" onClick={() => { setIsLoggedIn(false); setUserId(null); setDashboardData(null); setHistory([]); }}>Logout</button>
            </div>
          </div>

        {/* ===== PHISHING ALERT BANNER ===== */}
{totalPhishing > totalSafe && (
  <div className="alert-banner">
    <div>
      <p className="alert-title">High Phishing Activity Detected!</p>
      <p className="alert-msg">
        You have received <strong>{totalPhishing} phishing</strong> emails vs <strong>{totalSafe} safe</strong> emails.
        Stay alert ! do not click any suspicious links or share personal information.
      </p>
    </div>
  </div>
)}


          <div className="metrics-grid">
            <div className="metric-card">
              <div className="metric-label">Total scanned</div>
              <div className="metric-val">{totalScanned}</div>
              <div className="metric-sub gray">all time</div>
            </div>
            <div className="metric-card">
              <div className="metric-label">Phishing detected</div>
              <div className="metric-val red">{totalPhishing}</div>
              <div className="metric-sub red">{totalScanned > 0 ? Math.round((totalPhishing / totalScanned) * 100) : 0}% of total</div>
            </div>
            <div className="metric-card">
              <div className="metric-label">Safe emails</div>
              <div className="metric-val green">{totalSafe}</div>
              <div className="metric-sub green">{totalScanned > 0 ? Math.round((totalSafe / totalScanned) * 100) : 0}% of total</div>
            </div>
            <div className="metric-card">
              <div className="metric-label">Avg confidence</div>
              <div className="metric-val">{avgConf}%</div>
              <div className="metric-sub gray">across all scans</div>
            </div>
          </div>

          <div className="charts-row">
            <div className="chart-card">
              <div className="chart-title">Scans this week</div>
              <div className="legend-row">
                <span className="legend-item"><span className="legend-dot" style={{ background: "#e53e3e" }}></span>Phishing</span>
                <span className="legend-item"><span className="legend-dot" style={{ background: "#2f855a" }}></span>Safe</span>
              </div>
              <div style={{ position: "relative", height: "160px" }}>
                <Bar data={barData} options={barOptions} />
              </div>
            </div>
            <div className="chart-card">
              <div className="chart-title">Overall breakdown</div>
              <div className="legend-row">
                <span className="legend-item"><span className="legend-dot" style={{ background: "#e53e3e" }}></span>Phishing {totalScanned > 0 ? Math.round((totalPhishing / totalScanned) * 100) : 0}%</span>
                <span className="legend-item"><span className="legend-dot" style={{ background: "#2f855a" }}></span>Safe {totalScanned > 0 ? Math.round((totalSafe / totalScanned) * 100) : 0}%</span>
              </div>
              <div style={{ position: "relative", height: "160px" }}>
                <Doughnut data={donutData} options={donutOptions} />
              </div>
            </div>
          </div>

          <div className="history-card">
            <div className="chart-title">Recent scan history</div>
            {displayHistory.length === 0 ? (
              <p className="no-history">No emails analyzed yet. Go to Analyze to get started!</p>
            ) : (
              <table className="hist-table">
                <thead>
                  <tr>
                    <th>Email preview</th>
                    <th>Result</th>
                    <th>Confidence</th>
                    <th>Risk</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {displayHistory.map((item, i) => (
                    <tr key={i}>
                      <td className="preview-text">{item.text}</td>
                      <td><span className={`pill ${item.label === "PHISHING" ? "pill-phish" : "pill-safe"}`}>{item.label === "PHISHING" ? "Phishing" : "Safe"}</span></td>
                      <td className={item.label === "PHISHING" ? "red" : "green"}>{item.confidence}%</td>
                      <td><span className={`pill pill-${item.threat.toLowerCase()}`}>{item.threat}</span></td>
                      <td className="gray">{item.timestamp}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </div>
  );
}