const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const { exec } = require("child_process");

const app = express();

app.use(cors());
app.use(express.json());

// ================= DB CONNECTION =================
const db = mysql.createConnection({
  host: "127.0.0.1",
  user: "root",
  password: "delisha123*",
  database: "login_db"
});

db.connect((err) => {
  if (err) console.log("MySQL error:", err);
  else console.log("MySQL Connected");
});

// ================= REGISTER =================
app.post("/register", (req, res) => {
  const { name, email, password, phone } = req.body;
  const sql = "INSERT INTO users (name, email, password, phone) VALUES (?, ?, ?, ?)";
  db.query(sql, [name, email, password, phone], (err) => {
    if (err) return res.json({ message: "Error / Email exists" });
    res.json({ message: "User Registered Successfully" });
  });
});

// ================= LOGIN =================
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const sql = "SELECT * FROM users WHERE email=? AND password=?";
  db.query(sql, [email, password], (err, result) => {
    if (result && result.length > 0) {
      res.json({ message: "Login Successful", userId: result[0].user_id, name: result[0].name });
    } else {
      res.json({ message: "Invalid Credentials" });
    }
  });
});

// ================= ML PREDICTION =================
app.post("/predict", (req, res) => {
  const email = req.body.email;

 const safeEmail = email
  .replace(/\n/g, " ")      // remove newlines
  .replace(/\r/g, " ")
  .replace(/"/g, '\\"')    // escape quotes
  .trim();

  exec(`py ${__dirname}/predict.py "${safeEmail}"`, (err, stdout, stderr) => {
    console.log("RAW OUTPUT FROM PYTHON:", stdout);

    if (err) {
      console.log("ERROR:", err);
      console.log("STDERR:", stderr);
      return res.status(500).json({
        result: "Error running model. Check backend terminal."
      });
    }

    res.json({ result: stdout.trim() });
  });
});
// ================= SAVE SCAN =================
app.post("/save-scan", (req, res) => {
  const { userId, emailText, result, confidence, threatLevel, keywords } = req.body;

  const scanSql = "INSERT INTO scans (user_id, email_text, result, confidence, threat_level) VALUES (?, ?, ?, ?, ?)";

  db.query(scanSql, [userId, emailText, result, confidence, threatLevel], (err, scanResult) => {
    if (err) return res.json({ success: false });

    const scanId = scanResult.insertId;

    if (keywords && keywords.length > 0) {
      const kwValues = keywords.map(kw => [scanId, kw]);
      const kwSql = "INSERT INTO flagged_keywords (scan_id, keyword) VALUES ?";
      db.query(kwSql, [kwValues], (kwErr) => {
        if (kwErr) console.log("Keyword save error:", kwErr);
      });
    }

    res.json({ success: true, scanId });
  });
});

// ================= GET DASHBOARD DATA =================
app.get("/dashboard/:userId", (req, res) => {
  const userId = req.params.userId;

  const statsSql = `
  SELECT 
    COUNT(*) as total,
    IFNULL(SUM(result = 'PHISHING'), 0) as phishing,
    IFNULL(SUM(result = 'SAFE'), 0) as safe,
    IFNULL(ROUND(AVG(confidence)), 0) as avgConf
  FROM scans WHERE user_id = ?
`;

  const historySql = `
    SELECT scan_id, email_text, result, confidence, threat_level, scanned_at
    FROM scans WHERE user_id = ?
    ORDER BY scanned_at DESC LIMIT 20
  `;

  const weekSql = `
    SELECT 
      DAYNAME(scanned_at) as day,
      result,
      COUNT(*) as count
    FROM scans
    WHERE user_id = ? AND scanned_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    GROUP BY DAYNAME(scanned_at), result
  `;

  db.query(statsSql, [userId], (err, stats) => {
    if (err) return res.json({ success: false });

    db.query(historySql, [userId], (err2, history) => {
      if (err2) return res.json({ success: false });

      db.query(weekSql, [userId], (err3, week) => {
        if (err3) return res.json({ success: false });

        res.json({ success: true, stats: stats[0], history, week });
      });
    });
  });
});

// ================= GET PROFILE =================
app.get("/profile/:userId", (req, res) => {
  const userId = req.params.userId;

  const userSql = "SELECT name, email, phone, created_at FROM users WHERE user_id = ?";
  
  const statsSql = `
  SELECT 
    COUNT(*) as total,
    IFNULL(SUM(result = 'PHISHING'), 0) as phishing,
    IFNULL(SUM(result = 'SAFE'), 0) as safe,
    IFNULL(ROUND(AVG(confidence)), 0) as avgConf
  FROM scans WHERE user_id = ?
`;

  const firstScanSql = `
    SELECT scanned_at FROM scans 
    WHERE user_id = ? 
    ORDER BY scanned_at ASC LIMIT 1
  `;

  db.query(userSql, [userId], (err, userResult) => {
    if (err || userResult.length === 0) return res.json({ success: false });

    db.query(statsSql, [userId], (err2, statsResult) => {
      if (err2) return res.json({ success: false });

      db.query(firstScanSql, [userId], (err3, firstScan) => {
        if (err3) return res.json({ success: false });

        res.json({
          success: true,
          user: userResult[0],
          stats: statsResult[0],
          firstScan: firstScan.length > 0 ? firstScan[0].scanned_at : null
        });
      });
    });
  });
});
// ================= GET INSIGHTS =================
app.get("/insights/:userId", (req, res) => {
  const userId = req.params.userId;

  // top keywords from flagged_keywords table
  const keywordSql = `
    SELECT fk.keyword, COUNT(*) as count
    FROM flagged_keywords fk
    JOIN scans s ON fk.scan_id = s.scan_id
    WHERE s.user_id = ?
    GROUP BY fk.keyword
    ORDER BY count DESC
    LIMIT 6
  `;

  // most common threat level
  const threatSql = `
    SELECT threat_level, COUNT(*) as count
    FROM scans
    WHERE user_id = ? AND result = 'PHISHING'
    GROUP BY threat_level
    ORDER BY count DESC
    LIMIT 1
  `;

  // busiest phishing day
  const daySql = `
    SELECT DAYNAME(scanned_at) as day, COUNT(*) as count
    FROM scans
    WHERE user_id = ? AND result = 'PHISHING'
    GROUP BY DAYNAME(scanned_at)
    ORDER BY count DESC
    LIMIT 1
  `;

  // this week vs last week
  const trendSql = `
    SELECT
      SUM(CASE WHEN scanned_at >= DATE_SUB(NOW(), INTERVAL 7 DAY) AND result = 'PHISHING' THEN 1 ELSE 0 END) as thisWeek,
      SUM(CASE WHEN scanned_at >= DATE_SUB(NOW(), INTERVAL 14 DAY) AND scanned_at < DATE_SUB(NOW(), INTERVAL 7 DAY) AND result = 'PHISHING' THEN 1 ELSE 0 END) as lastWeek
    FROM scans WHERE user_id = ?
  `;

  db.query(keywordSql, [userId], (err, keywords) => {
    if (err) return res.json({ success: false });

    db.query(threatSql, [userId], (err2, threat) => {
      if (err2) return res.json({ success: false });

      db.query(daySql, [userId], (err3, day) => {
        if (err3) return res.json({ success: false });

        db.query(trendSql, [userId], (err4, trend) => {
          if (err4) return res.json({ success: false });

          res.json({
            success: true,
            keywords: keywords.map(k => k.keyword),
            topThreat: threat[0]?.threat_level || "Medium",
            busiestDay: day[0]?.day || null,
            thisWeek: Number(trend[0]?.thisWeek) || 0,
            lastWeek: Number(trend[0]?.lastWeek) || 0
          });
        });
      });
    });
  });
});
// ================= SERVER =================
app.listen(3000, () => {
  console.log("Server running on port 3000");
});